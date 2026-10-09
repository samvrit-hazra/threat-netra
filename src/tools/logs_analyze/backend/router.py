from fastapi import APIRouter, Request, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from src.auth.backend.dependencies import require_approved_user
from src.tools.logs_analyze.backend.parser import LogParser
from src.tools.logs_analyze.backend.detector import ThreatDetector
from src.tools.logs_analyze.backend.ai_service import AIForensicService

router = APIRouter(prefix="/tools/logs_analyze", tags=["logs_analyze"])
templates = Jinja2Templates(directory="src")

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

@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def read_logs_analyze_ui(
    request: Request,
    current_user: dict = Depends(require_approved_user)
):
    """
    Renders the AI Log & Network Forensic Analyzer interface.
    Available to all approved authenticated users.
    """
    return templates.TemplateResponse(
        request=request,
        name="tools/logs_analyze/frontend/index.html",
        context={
            "user": current_user,
            "role": current_user.get("role", "normal_user")
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
        "events": parse_result["parsed_events"][:300],  # Return up to 300 events for client rendering
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
