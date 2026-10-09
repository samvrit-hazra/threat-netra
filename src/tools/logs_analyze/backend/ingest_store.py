import os
import json
import time
import hashlib
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

from src.tools.logs_analyze.backend.parser import LogParser
from src.tools.logs_analyze.backend.detector import ThreatDetector

DATA_FILE = os.path.join(os.path.dirname(__file__), "agent_tokens.json")
MAX_BUFFER_EVENTS = 500
SALT = "threatnetra_agent_telemetry_v1"

class IngestStore:
    _lock = threading.Lock()
    _tokens_map: Dict[str, Dict[str, Any]] = {}       # token -> user metadata
    _user_to_token: Dict[str, str] = {}               # user_id -> token
    _live_buffers: Dict[str, Dict[str, Any]] = {}      # token -> live buffer state

    @classmethod
    def initialize(cls):
        with cls._lock:
            if os.path.exists(DATA_FILE):
                try:
                    with open(DATA_FILE, "r") as f:
                        data = json.load(f)
                        cls._tokens_map = data.get("tokens", {})
                        cls._user_to_token = data.get("user_to_token", {})
                except Exception:
                    cls._tokens_map = {}
                    cls._user_to_token = {}

    @classmethod
    def _save_persistent(cls):
        try:
            with open(DATA_FILE, "w") as f:
                json.dump({
                    "tokens": cls._tokens_map,
                    "user_to_token": cls._user_to_token
                }, f, indent=2)
        except Exception:
            pass

    @classmethod
    def get_or_create_token_for_user(cls, user_id: str, email: str = "") -> str:
        """
        Retrieves existing token for user, or generates a deterministic secret token.
        """
        cls.initialize()
        with cls._lock:
            if user_id in cls._user_to_token:
                token = cls._user_to_token[user_id]
                if token in cls._tokens_map:
                    return token

            # Generate fresh token
            raw_hash = hashlib.sha256(f"{user_id}:{SALT}".encode()).hexdigest()[:24]
            token = f"tn_sec_{raw_hash}"

            cls._tokens_map[token] = {
                "user_id": user_id,
                "email": email,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            cls._user_to_token[user_id] = token
            cls._save_persistent()
            return token

    @classmethod
    def regenerate_token_for_user(cls, user_id: str, email: str = "") -> str:
        cls.initialize()
        with cls._lock:
            # Generate random salt addition with timestamp
            ts = int(time.time())
            raw_hash = hashlib.sha256(f"{user_id}:{SALT}:{ts}".encode()).hexdigest()[:24]
            new_token = f"tn_sec_{raw_hash}"

            # Remove old token if present
            old_token = cls._user_to_token.get(user_id)
            if old_token and old_token in cls._tokens_map:
                del cls._tokens_map[old_token]
                if old_token in cls._live_buffers:
                    del cls._live_buffers[old_token]

            cls._tokens_map[new_token] = {
                "user_id": user_id,
                "email": email,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            cls._user_to_token[user_id] = new_token
            cls._save_persistent()
            return new_token

    @classmethod
    def validate_token(cls, token: str) -> Optional[Dict[str, Any]]:
        cls.initialize()
        with cls._lock:
            return cls._tokens_map.get(token)

    @classmethod
    def get_user_token(cls, user_id: str) -> Optional[str]:
        cls.initialize()
        with cls._lock:
            return cls._user_to_token.get(user_id)

    @classmethod
    def record_ingest(cls, token: str, raw_text: str, client_ip: str = "") -> Dict[str, Any]:
        """
        Parses incoming batch from script, correlates threats, updates live rolling buffer.
        """
        cls.initialize()
        parse_result = LogParser.parse_text(raw_text)
        new_events = parse_result.get("parsed_events", [])
        total_lines = parse_result.get("total_lines", 0)

        with cls._lock:
            if token not in cls._live_buffers:
                cls._live_buffers[token] = {
                    "total_lines_streamed": 0,
                    "total_batches": 0,
                    "recent_events": [],
                    "latest_forensics": {},
                    "last_ingested_at": None,
                    "last_client_ip": client_ip,
                    "latest_raw_snippet": ""
                }

            buf = cls._live_buffers[token]
            buf["total_lines_streamed"] += total_lines
            buf["total_batches"] += 1
            buf["last_ingested_at"] = datetime.now(timezone.utc).isoformat()
            buf["last_client_ip"] = client_ip
            buf["latest_raw_snippet"] = raw_text[-3000:]

            # Prepend newest events to rolling buffer (up to MAX_BUFFER_EVENTS)
            combined_events = new_events + buf["recent_events"]
            buf["recent_events"] = combined_events[:MAX_BUFFER_EVENTS]

            # Re-evaluate threats across the aggregated event stream
            forensics = ThreatDetector.analyze_events(buf["recent_events"])
            buf["latest_forensics"] = forensics

            return {
                "format": parse_result.get("detected_format", "unknown"),
                "lines_received": total_lines,
                "events_parsed": len(new_events),
                "total_streamed_lines": buf["total_lines_streamed"],
                "threat_level": forensics.get("threat_level", "NOMINAL"),
                "threat_score": forensics.get("threat_score", 0),
                "total_findings": forensics.get("total_findings", 0),
                "critical_count": forensics.get("critical_count", 0),
                "high_count": forensics.get("high_count", 0),
                "hostile_ips": len(forensics.get("suspicious_ips", [])),
                "timestamp": buf["last_ingested_at"]
            }

    @classmethod
    def get_live_buffer(cls, token: str) -> Optional[Dict[str, Any]]:
        with cls._lock:
            buf = cls._live_buffers.get(token)
            if not buf:
                return None
            return {
                "total_lines_streamed": buf["total_lines_streamed"],
                "total_batches": buf["total_batches"],
                "last_ingested_at": buf["last_ingested_at"],
                "last_client_ip": buf["last_client_ip"],
                "events": buf["recent_events"],
                "forensics": buf["latest_forensics"],
                "latest_raw_snippet": buf["latest_raw_snippet"]
            }

    @classmethod
    def clear_buffer(cls, token: str):
        with cls._lock:
            if token in cls._live_buffers:
                del cls._live_buffers[token]

# Auto-initialize store on import
IngestStore.initialize()
