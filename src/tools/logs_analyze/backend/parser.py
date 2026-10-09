import re
import json
from typing import List, Dict, Any, Optional

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
TIMESTAMP_REGEX = re.compile(
    r'(?:\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|'
    r'[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|'
    r'\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})'
)
HTTP_METHOD_REGEX = re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\b')
LEVEL_REGEX = re.compile(r'\b(CRITICAL|ALERT|EMERGENCY|FATAL|ERROR|WARN(?:ING)?|INFO|DEBUG|NOTICE)\b', re.IGNORECASE)

# Common Log Format / Combined Log Format regex
APACHE_COMBINED_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<protocol>[^"]+))?"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# Standard Syslog regex: Oct 09 11:42:10 hostname app[123]: message
SYSLOG_REGEX = re.compile(
    r'^(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<service>[A-Za-z0-9_\-\.\/]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
)

# Firewall / IPTables pattern
IPTABLES_REGEX = re.compile(
    r'(?P<action>DROP|REJECT|BLOCK|ACCEPT|INSPECT).*?SRC=(?P<src_ip>\S+).*?DST=(?P<dst_ip>\S+).*?PROTO=(?P<proto>\S+)',
    re.IGNORECASE
)

# Windows Event Log pattern
WIN_EVENT_REGEX = re.compile(
    r'(?:EventID|Event ID|Event\s*Code)[:=]\s*(?P<event_id>\d+)',
    re.IGNORECASE
)

class LogParser:
    @staticmethod
    def identify_format(sample_lines: List[str]) -> str:
        apache_matches = 0
        syslog_matches = 0
        json_matches = 0
        iptables_matches = 0
        win_matches = 0

        for line in sample_lines[:20]:
            trimmed = line.strip()
            if not trimmed:
                continue
            if trimmed.startswith("{") and trimmed.endswith("}"):
                try:
                    json.loads(trimmed)
                    json_matches += 1
                    continue
                except Exception:
                    pass
            if APACHE_COMBINED_REGEX.match(trimmed):
                apache_matches += 1
            elif IPTABLES_REGEX.search(trimmed):
                iptables_matches += 1
            elif WIN_EVENT_REGEX.search(trimmed):
                win_matches += 1
            elif SYSLOG_REGEX.match(trimmed):
                syslog_matches += 1

        if json_matches >= 2:
            return "json"
        if apache_matches >= 2:
            return "web_access"
        if iptables_matches >= 1:
            return "firewall"
        if win_matches >= 1:
            return "windows_event"
        if syslog_matches >= 2:
            return "syslog"
        return "unstructured"

    @classmethod
    def parse_text(cls, raw_content: str) -> Dict[str, Any]:
        lines = [l for l in raw_content.splitlines() if l.strip()]
        if not lines:
            return {
                "detected_format": "empty",
                "total_lines": 0,
                "parsed_events": [],
                "unparsed_count": 0
            }

        detected_format = cls.identify_format(lines)
        events = []
        unparsed = 0

        for idx, line in enumerate(lines, start=1):
            parsed = cls.parse_single_line(line, idx, detected_format)
            if parsed:
                events.append(parsed)
            else:
                unparsed += 1

        return {
            "detected_format": detected_format,
            "total_lines": len(lines),
            "parsed_events": events,
            "unparsed_count": unparsed
        }

    @classmethod
    def parse_single_line(cls, line: str, line_no: int, preferred_format: str) -> Optional[Dict[str, Any]]:
        line_clean = line.strip()
        if not line_clean:
            return None

        # 1. JSON Log Parsing
        if line_clean.startswith("{") and line_clean.endswith("}"):
            try:
                data = json.loads(line_clean)
                timestamp = (
                    data.get("timestamp") or
                    data.get("time") or
                    data.get("@timestamp") or
                    data.get("datetime") or
                    "N/A"
                )
                level = (
                    data.get("level") or
                    data.get("severity") or
                    data.get("log_level") or
                    "INFO"
                ).upper()
                msg = (
                    data.get("message") or
                    data.get("msg") or
                    data.get("event") or
                    json.dumps(data)
                )
                ip = (
                    data.get("ip") or
                    data.get("src_ip") or
                    data.get("client_ip") or
                    data.get("source_ip")
                )
                if not ip:
                    ip_match = IP_REGEX.search(str(msg))
                    if ip_match:
                        ip = ip_match.group(0)

                return {
                    "id": f"evt-{line_no}",
                    "line_number": line_no,
                    "format": "json",
                    "timestamp": str(timestamp),
                    "level": str(level),
                    "source_ip": ip or "N/A",
                    "destination_ip": data.get("dst_ip") or data.get("dest_ip") or "N/A",
                    "service": data.get("service") or data.get("app") or data.get("component") or "system",
                    "event_type": data.get("event_type") or data.get("action") or "generic_event",
                    "message": str(msg),
                    "raw": line_clean
                }
            except Exception:
                pass

        # 2. Apache/Nginx Combined Web Access Log
        web_match = APACHE_COMBINED_REGEX.match(line_clean)
        if web_match:
            d = web_match.groupdict()
            status = int(d.get("status", 200))
            level = "ERROR" if status >= 500 else ("WARN" if status >= 400 else "INFO")
            return {
                "id": f"evt-{line_no}",
                "line_number": line_no,
                "format": "web_access",
                "timestamp": d.get("timestamp") or "N/A",
                "level": level,
                "source_ip": d.get("ip") or "N/A",
                "destination_ip": "Local Server",
                "service": "web_server",
                "method": d.get("method") or "GET",
                "path": d.get("path") or "/",
                "status_code": status,
                "user_agent": d.get("user_agent") or "N/A",
                "message": f"{d.get('method')} {d.get('path')} HTTP/1.1 -> {status}",
                "raw": line_clean
            }

        # 3. Firewall / IPTables / UFW
        fw_match = IPTABLES_REGEX.search(line_clean)
        if fw_match:
            d = fw_match.groupdict()
            action = d.get("action", "PACKET").upper()
            level = "WARN" if action in ("DROP", "BLOCK", "REJECT") else "INFO"
            
            dpt_match = re.search(r'\bDPT=(\d+)\b', line_clean)
            dst_port = dpt_match.group(1) if dpt_match else "N/A"

            return {
                "id": f"evt-{line_no}",
                "line_number": line_no,
                "format": "firewall",
                "timestamp": cls._extract_timestamp(line_clean) or "N/A",
                "level": level,
                "source_ip": d.get("src_ip") or "N/A",
                "destination_ip": d.get("dst_ip") or "N/A",
                "protocol": (d.get("proto") or "TCP").upper(),
                "destination_port": dst_port,
                "service": "firewall",
                "event_type": f"firewall_{action.lower()}",
                "message": f"Firewall {action} packet from {d.get('src_ip')} to {d.get('dst_ip')}:{dst_port} ({(d.get('proto') or 'TCP').upper()})",
                "raw": line_clean
            }

        # 4. Syslog (RFC 3164)
        syslog_match = SYSLOG_REGEX.match(line_clean)
        if syslog_match:
            d = syslog_match.groupdict()
            msg = d.get("message", "")
            service = d.get("service", "syslog")
            
            # Detect log level from text or keywords
            lvl_match = LEVEL_REGEX.search(msg)
            if lvl_match:
                level = lvl_match.group(1).upper()
            elif any(k in msg.lower() for k in ["failed", "failure", "invalid", "error", "denied", "unauthorized"]):
                level = "WARN"
            else:
                level = "INFO"

            ip_match = IP_REGEX.search(msg)
            source_ip = ip_match.group(0) if ip_match else "N/A"

            return {
                "id": f"evt-{line_no}",
                "line_number": line_no,
                "format": "syslog",
                "timestamp": d.get("timestamp") or "N/A",
                "level": level,
                "hostname": d.get("hostname") or "localhost",
                "service": service,
                "source_ip": source_ip,
                "destination_ip": "Local Host",
                "message": msg,
                "raw": line_clean
            }

        # 5. Windows Event Log Text
        win_match = WIN_EVENT_REGEX.search(line_clean)
        if win_match:
            event_id = win_match.group("event_id")
            ip_match = IP_REGEX.search(line_clean)
            ts = cls._extract_timestamp(line_clean) or "N/A"
            level = "WARN" if event_id in ("4625", "4720", "7045", "1102", "4698") else "INFO"

            return {
                "id": f"evt-{line_no}",
                "line_number": line_no,
                "format": "windows_event",
                "timestamp": ts,
                "level": level,
                "event_id": event_id,
                "service": f"Security/EventLog ({event_id})",
                "source_ip": ip_match.group(0) if ip_match else "N/A",
                "destination_ip": "Local Workstation",
                "message": line_clean,
                "raw": line_clean
            }

        # 6. Unstructured Fallback with Smart Entity Extraction
        ts = cls._extract_timestamp(line_clean) or "N/A"
        lvl_match = LEVEL_REGEX.search(line_clean)
        level = lvl_match.group(1).upper() if lvl_match else "INFO"
        ip_matches = IP_REGEX.findall(line_clean)
        source_ip = ip_matches[0] if ip_matches else "N/A"
        dest_ip = ip_matches[1] if len(ip_matches) > 1 else "N/A"
        method_match = HTTP_METHOD_REGEX.search(line_clean)
        method = method_match.group(1) if method_match else None

        return {
            "id": f"evt-{line_no}",
            "line_number": line_no,
            "format": "unstructured",
            "timestamp": ts,
            "level": level,
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "method": method,
            "service": "telemetry",
            "message": line_clean,
            "raw": line_clean
        }

    @staticmethod
    def _extract_timestamp(text: str) -> Optional[str]:
        match = TIMESTAMP_REGEX.search(text)
        return match.group(0) if match else None
