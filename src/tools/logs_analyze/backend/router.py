import os
from fastapi import APIRouter, Request, Depends, HTTPException, UploadFile, File, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from src.auth.backend.dependencies import require_approved_user
from src.tools.logs_analyze.backend.parser import LogParser
from src.tools.logs_analyze.backend.detector import ThreatDetector
from src.tools.logs_analyze.backend.ai_service import AIForensicService
from src.tools.logs_analyze.backend.ingest_store import IngestStore

router = APIRouter(prefix="/tools/logs_analyze", tags=["logs_analyze"])
templates = Jinja2Templates(directory="src")

SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "..", "scripts")

# Predefined realistic attack samples for instant evaluation
SAMPLES = {
    "ssh_brute_force": """Oct 09 03:14:20 gateway sshd[28412]: Failed password for invalid user admin from 198.51.100.42 port 48291 ssh2
Oct 09 03:14:22 gateway sshd[28415]: Failed password for invalid user root from 198.51.100.42 port 48293 ssh2
Oct 09 03:14:25 gateway sshd[28419]: Failed password for invalid user test from 198.51.100.42 port 48295 ssh2
Oct 09 03:14:28 gateway sshd[28423]: Failed password for invalid user oracle from 198.51.100.42 port 48297 ssh2
Oct 09 03:14:31 gateway sshd[28426]: Failed password for invalid user postgres from 198.51.100.42 port 48299 ssh2
Oct 09 03:14:34 gateway sshd[28430]: Failed password for invalid user support from 198.51.100.42 port 48301 ssh2
Oct 09 03:14:38 gateway sshd[28433]: Failed password for invalid user backup from 198.51.100.42 port 48303 ssh2
Oct 09 03:14:41 gateway sshd[28438]: Failed password for invalid user deploy from 198.51.100.42 port 48305 ssh2
Oct 09 03:15:02 gateway sshd[28450]: Accepted publickey for secops from 10.0.4.15 port 52310 ssh2: RSA SHA256:v8z+e...""",

    "web_app_attack": """192.0.2.14 - - [09/Oct/2026:08:12:01 +0000] "GET /products.php?id=1' UNION SELECT null,username,password FROM users-- HTTP/1.1" 200 4821 "-" "sqlmap/1.7.2#stable"
192.0.2.14 - - [09/Oct/2026:08:12:04 +0000] "GET /static/../../../../etc/passwd HTTP/1.1" 404 230 "-" "Mozilla/5.0"
192.0.2.14 - - [09/Oct/2026:08:12:06 +0000] "GET /api/v1/ping?host=127.0.0.1;cat /etc/shadow HTTP/1.1" 500 148 "-" "curl/7.88.1"
192.0.2.14 - - [09/Oct/2026:08:12:09 +0000] "GET /.env HTTP/1.1" 403 162 "-" "gobuster/3.5"
192.0.2.14 - - [09/Oct/2026:08:12:11 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "gobuster/3.5"
192.0.2.14 - - [09/Oct/2026:08:12:14 +0000] "GET /phpmyadmin/index.php HTTP/1.1" 404 162 "-" "gobuster/3.5"
192.0.2.99 - - [09/Oct/2026:08:13:00 +0000] "POST /comment?text=<script>alert('xss')</script> HTTP/1.1" 200 812 "-" "Mozilla/5.0"
10.0.0.5 - - [09/Oct/2026:08:14:22 +0000] "GET /dashboard HTTP/1.1" 200 15200 "https://threatnetra.com" "Mozilla/5.0" """,

    "firewall_sweep": """[UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:12:34:56 SRC=203.0.113.88 DST=10.0.1.5 PROTO=TCP SPT=54120 DPT=22
[UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:12:34:56 SRC=203.0.113.88 DST=10.0.1.5 PROTO=TCP SPT=54121 DPT=23
[UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:12:34:56 SRC=203.0.113.88 DST=10.0.1.5 PROTO=TCP SPT=54122 DPT=80
[UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:12:34:56 SRC=203.0.113.88 DST=10.0.1.5 PROTO=TCP SPT=54123 DPT=445
[UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:12:34:56 SRC=203.0.113.88 DST=10.0.1.5 PROTO=TCP SPT=54124 DPT=3389
[UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:12:34:56 SRC=203.0.113.88 DST=10.0.1.5 PROTO=TCP SPT=54125 DPT=8080
[UFW ACCEPT] IN=eth0 OUT= MAC=52:54:00:12:34:56 SRC=192.168.1.50 DST=10.0.1.5 PROTO=TCP SPT=49210 DPT=443""",

    "windows_persistence": """2026-10-09 09:15:00 WIN-SRV01 Security EventID: 4625 Account Name: Administrator Failure Reason: Unknown user name or bad password Source Network Address: 198.51.100.77
2026-10-09 09:15:03 WIN-SRV01 Security EventID: 4625 Account Name: Administrator Failure Reason: Unknown user name or bad password Source Network Address: 198.51.100.77
2026-10-09 09:15:07 WIN-SRV01 Security EventID: 4625 Account Name: Administrator Failure Reason: Unknown user name or bad password Source Network Address: 198.51.100.77
2026-10-09 09:16:42 WIN-SRV01 Security EventID: 4720 A user account was created. Target Account Name: svc_backdoor Subject User Name: SYSTEM
2026-10-09 09:17:15 WIN-SRV01 System EventID: 7045 A service was installed in the system. Service Name: ReverseShell Binary Path: C:\\Windows\\Temp\\nc.exe -Ldp 4444 -e cmd.exe
2026-10-09 09:18:22 WIN-SRV01 Security EventID: 1102 The audit log was cleared. Subject User Name: svc_backdoor"""
}

class AnalyzeTextRequest(BaseModel):
    raw_logs: str

class AIDiagnoseRequest(BaseModel):
    summary: Dict[str, Any]
    sample_snippet: str

# -------------------------------------------------------------------------
# UI & SAMPLES
# -------------------------------------------------------------------------

@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def read_logs_analyze_ui(
    request: Request,
    current_user: dict = Depends(require_approved_user)
):
    """
    Renders the AI Log & Network Forensic Analyzer interface.
    """
    user_id = str(current_user.get("id", ""))
    email = current_user.get("email", "")
    token = IngestStore.get_or_create_token_for_user(user_id, email)
    base_url = str(request.base_url).rstrip("/")
    secret_url = f"{base_url}/tools/logs_analyze/api/stream/{token}"

    return templates.TemplateResponse(
        request=request,
        name="tools/logs_analyze/frontend/index.html",
        context={
            "user": current_user,
            "role": current_user.get("role", "normal_user"),
            "secret_token": token,
            "secret_ingest_url": secret_url
        }
    )

@router.get("/api/samples/{sample_id}")
async def get_sample_logs(
    sample_id: str,
    current_user: dict = Depends(require_approved_user)
):
    if sample_id not in SAMPLES:
        raise HTTPException(status_code=404, detail="Requested sample not found.")
    return JSONResponse({
        "status": "success",
        "sample_id": sample_id,
        "logs": SAMPLES[sample_id]
    })

# -------------------------------------------------------------------------
# MANUAL LOG INGESTION (PASTE & UPLOAD)
# -------------------------------------------------------------------------

@router.post("/api/analyze")
async def analyze_raw_logs(
    payload: AnalyzeTextRequest,
    current_user: dict = Depends(require_approved_user)
):
    """
    Parses and evaluates logs submitted via JSON payload.
    """
    raw_text = payload.raw_logs.strip()
    if not raw_text:
        raise HTTPException(status_code=400, detail="Log content cannot be empty.")

    parse_result = LogParser.parse_text(raw_text)
    detected_threats = ThreatDetector.analyze_events(parse_result["parsed_events"])

    return JSONResponse({
        "status": "success",
        "format": parse_result["detected_format"],
        "total_lines": parse_result["total_lines"],
        "unparsed_count": parse_result["unparsed_count"],
        "events": parse_result["parsed_events"][:300],
        "forensics": detected_threats
    })

@router.post("/api/upload")
async def upload_log_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(require_approved_user)
):
    """
    Accepts log file uploads (.log, .txt, .json, .csv).
    """
    content_bytes = await file.read()
    try:
        raw_text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raw_text = content_bytes.decode("latin-1", errors="ignore")

    if not raw_text.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    parse_result = LogParser.parse_text(raw_text)
    detected_threats = ThreatDetector.analyze_events(parse_result["parsed_events"])

    return JSONResponse({
        "status": "success",
        "filename": file.filename,
        "format": parse_result["detected_format"],
        "total_lines": parse_result["total_lines"],
        "unparsed_count": parse_result["unparsed_count"],
        "events": parse_result["parsed_events"][:300],
        "forensics": detected_threats
    })

# -------------------------------------------------------------------------
# CONTINUOUS AGENT TELEMETRY (STREAM / SECRET API INGESTION)
# -------------------------------------------------------------------------

@router.get("/api/agent/config")
async def get_agent_config(
    request: Request,
    current_user: dict = Depends(require_approved_user)
):
    """
    Returns the secret ingestion URL and live buffer stats for the user.
    """
    user_id = str(current_user.get("id", ""))
    email = current_user.get("email", "")
    token = IngestStore.get_or_create_token_for_user(user_id, email)
    base_url = str(request.base_url).rstrip("/")
    secret_url = f"{base_url}/tools/logs_analyze/api/stream/{token}"

    buf = IngestStore.get_live_buffer(token) or {}

    return JSONResponse({
        "status": "success",
        "token": token,
        "secret_url": secret_url,
        "total_lines_streamed": buf.get("total_lines_streamed", 0),
        "total_batches": buf.get("total_batches", 0),
        "last_ingested_at": buf.get("last_ingested_at"),
        "last_client_ip": buf.get("last_client_ip")
    })

@router.post("/api/agent/regenerate-token")
async def regenerate_agent_token(
    request: Request,
    current_user: dict = Depends(require_approved_user)
):
    """
    Revokes previous secret token and generates a fresh one.
    """
    user_id = str(current_user.get("id", ""))
    email = current_user.get("email", "")
    new_token = IngestStore.regenerate_token_for_user(user_id, email)
    base_url = str(request.base_url).rstrip("/")
    secret_url = f"{base_url}/tools/logs_analyze/api/stream/{new_token}"

    return JSONResponse({
        "status": "success",
        "token": new_token,
        "secret_url": secret_url
    })

async def _process_stream_request(request: Request, secret_token: str) -> JSONResponse:
    """Helper to process incoming log stream with secret token."""
    token_meta = IngestStore.validate_token(secret_token)
    if not token_meta:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Invalid secret ingestion API key or URL."
        )

    # Read payload - supports raw text, JSON, or form
    body_bytes = await request.body()
    try:
        raw_text = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raw_text = body_bytes.decode("latin-1", errors="ignore")

    raw_text = raw_text.strip()
    if not raw_text:
        raise HTTPException(status_code=400, detail="Empty log stream payload received.")

    # Check if JSON payload was sent
    if raw_text.startswith("{") and raw_text.endswith("}"):
        try:
            import json
            parsed_json = json.loads(raw_text)
            if "raw_logs" in parsed_json and isinstance(parsed_json["raw_logs"], str):
                raw_text = parsed_json["raw_logs"].strip()
            elif "logs" in parsed_json and isinstance(parsed_json["logs"], str):
                raw_text = parsed_json["logs"].strip()
        except Exception:
            pass

    client_ip = request.client.host if request.client else "unknown"
    result = IngestStore.record_ingest(secret_token, raw_text, client_ip)

    return JSONResponse({
        "status": "success",
        "message": f"Successfully ingested {result['lines_received']} log lines.",
        **result
    })

@router.post("/api/stream/{secret_token}")
async def receive_stream_by_path(
    secret_token: str,
    request: Request
):
    """
    Endpoint targeted by shell scripts:
    POST /tools/logs_analyze/api/stream/{secret_token}
    """
    return await _process_stream_request(request, secret_token)

@router.post("/api/ingest")
async def receive_stream_by_query(
    request: Request,
    token: Optional[str] = Query(None)
):
    """
    Alternative endpoint accepting token query parameter or Authorization header:
    POST /tools/logs_analyze/api/ingest?token={secret_token}
    """
    secret_token = token
    if not secret_token:
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            secret_token = auth_hdr[7:].strip()
        elif "X-Ingest-Key" in request.headers:
            secret_token = request.headers.get("X-Ingest-Key")

    if not secret_token:
        raise HTTPException(status_code=401, detail="Missing secret token parameter.")

    return await _process_stream_request(request, secret_token)

@router.get("/api/agent/live-stream")
async def get_live_stream_data(
    current_user: dict = Depends(require_approved_user)
):
    """
    Polled by the web UI to display live logs forwarded by the shell agent script.
    """
    user_id = str(current_user.get("id", ""))
    token = IngestStore.get_user_token(user_id)
    if not token:
        return JSONResponse({"status": "idle", "has_data": False})

    buf = IngestStore.get_live_buffer(token)
    if not buf or buf.get("total_lines_streamed", 0) == 0:
        return JSONResponse({
            "status": "idle",
            "has_data": False,
            "total_lines_streamed": 0,
            "total_batches": 0
        })

    return JSONResponse({
        "status": "active",
        "has_data": True,
        "total_lines_streamed": buf["total_lines_streamed"],
        "total_batches": buf["total_batches"],
        "last_ingested_at": buf["last_ingested_at"],
        "last_client_ip": buf["last_client_ip"],
        "events": buf["events"][:300],
        "forensics": buf["forensics"]
    })

@router.post("/api/agent/clear-stream")
async def clear_live_stream_buffer(
    current_user: dict = Depends(require_approved_user)
):
    """
    Resets the live buffer for the user.
    """
    user_id = str(current_user.get("id", ""))
    token = IngestStore.get_user_token(user_id)
    if token:
        IngestStore.clear_buffer(token)
    return JSONResponse({"status": "success", "message": "Buffer cleared."})

# -------------------------------------------------------------------------
# SCRIPT DOWNLOAD ENDPOINTS
# -------------------------------------------------------------------------

@router.get("/scripts/threatnetra-agent.sh")
async def download_linux_agent():
    path = os.path.join(SCRIPTS_DIR, "threatnetra-agent.sh")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Script not found.")
    return FileResponse(
        path=path,
        media_type="text/x-shellscript",
        filename="threatnetra-agent.sh"
    )

@router.get("/scripts/threatnetra-agent.ps1")
async def download_windows_agent():
    path = os.path.join(SCRIPTS_DIR, "threatnetra-agent.ps1")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Script not found.")
    return FileResponse(
        path=path,
        media_type="text/plain",
        filename="threatnetra-agent.ps1"
    )

@router.get("/scripts/threatnetra-agent.bat")
async def download_windows_batch():
    path = os.path.join(SCRIPTS_DIR, "threatnetra-agent.bat")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Script not found.")
    return FileResponse(
        path=path,
        media_type="application/x-bat",
        filename="threatnetra-agent.bat"
    )

# -------------------------------------------------------------------------
# AI DIAGNOSIS
# -------------------------------------------------------------------------

@router.post("/api/ai-diagnose")
async def run_ai_forensics(
    payload: AIDiagnoseRequest,
    current_user: dict = Depends(require_approved_user)
):
    """
    Submits structured analysis to configured AI model (Gemma / Groq).
    """
    report = AIForensicService.generate_incident_report(
        analysis_summary=payload.summary,
        sample_logs=payload.sample_snippet
    )
    return JSONResponse({
        "status": "success",
        "ai_report": report
    })
