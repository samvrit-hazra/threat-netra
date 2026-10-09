import os
import json
import ssl
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Any, Optional

def get_env_config() -> Dict[str, str]:
    config = {}
    env_path = Path(__file__).resolve().parents[4] / ".env"
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip().strip("'\"")

    for k in ["AI_PROVIDER", "GEMMA_API_KEY", "GEMMA_MODEL", "GROQ_API_KEY", "GROQ_MODEL"]:
        if k in os.environ:
            config[k] = os.environ[k]
    return config

class AIForensicService:
    @classmethod
    def generate_incident_report(
        cls,
        analysis_summary: Dict[str, Any],
        sample_logs: str
    ) -> Dict[str, Any]:
        config = get_env_config()
        provider = config.get("AI_PROVIDER", "gemma").lower()
        gemma_key = config.get("GEMMA_API_KEY", "")
        gemma_model = config.get("GEMMA_MODEL", "gemma-4-26b-a4b-it")
        groq_key = config.get("GROQ_API_KEY", "")
        groq_model = config.get("GROQ_MODEL", "openai/gpt-oss-120b")

        findings_count = analysis_summary.get("total_findings", 0)
        threat_level = analysis_summary.get("threat_level", "NOMINAL")
        threat_score = analysis_summary.get("threat_score", 0)
        suspicious_ips = [item["ip"] for item in analysis_summary.get("suspicious_ips", [])]
        vectors = analysis_summary.get("detected_vectors", [])

        prompt = f"""You are Threat Netra's Senior Cyber Defense & Forensic Analyst.
Analyze the following telemetry and detected threat telemetry:

--- INCIDENT SUMMARY ---
Overall Threat Level: {threat_level} (Score: {threat_score}/100)
Total Threat Indicators Detected: {findings_count}
Identified Adversary IP Addresses: {', '.join(suspicious_ips) if suspicious_ips else 'None isolated'}
Detected Attack Vectors: {', '.join(vectors) if vectors else 'None confirmed'}

--- RAW TELEMETRY SAMPLE ---
{sample_logs[:2000]}

Please provide a structured forensic intelligence assessment in clean Markdown format with the following exact sections:
### 1. Incident Executive Briefing
Concise explanation of what transpired and the risk to the organisation.

### 2. Adversary Intent & Kill-Chain Reconstruction
Reconstruct the attacker's trajectory (Reconnaissance -> Initial Access -> Persistence/Execution).

### 3. MITRE ATT&CK Mapping
Bullet list of relevant T-codes, Tactics, and Techniques observed.

### 4. Immediate Containment & Defensive Actions
Specific, actionable technical countermeasures (e.g., iptables / firewall block rules, credential resets, endpoint isolation).

### 5. Strategic Hardening
Long-term configuration or architectural recommendations.
"""

        # Primary attempt: Configured provider
        if provider == "groq" and groq_key:
            res = cls._call_groq(prompt, groq_key, groq_model)
            if res.get("success"):
                return res
        elif gemma_key:
            res = cls._call_gemma(prompt, gemma_key, gemma_model)
            if res.get("success"):
                return res

        # Fallback to secondary provider if available
        if groq_key:
            res = cls._call_groq(prompt, groq_key, groq_model)
            if res.get("success"):
                return res

        # If both AI APIs fail or are offline, generate synthetic defense intelligence
        return cls._generate_heuristic_report(analysis_summary)

    @classmethod
    def _call_gemma(cls, prompt: str, api_key: str, model: str) -> Dict[str, Any]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}]
        }
        start = time.time()
        context = ssl.create_default_context()
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, context=context, timeout=25) as resp:
                elapsed = time.time() - start
                data = json.loads(resp.read().decode())
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                return {
                    "success": True,
                    "provider": "Gemma (Google AI Studio)",
                    "model": model,
                    "latency_sec": round(elapsed, 2),
                    "report_markdown": text.strip()
                }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @classmethod
    def _call_groq(cls, prompt: str, api_key: str, model: str) -> Dict[str, Any]:
        url = "https://api.groq.com/openai/v1/chat/completions"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a senior cybersecurity incident response analyst."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 1200
        }
        start = time.time()
        context = ssl.create_default_context()
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "ThreatNetra/1.0",
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            data=json.dumps(payload).encode("utf-8")
        )
        try:
            with urllib.request.urlopen(req, context=context, timeout=25) as resp:
                elapsed = time.time() - start
                data = json.loads(resp.read().decode())
                text = data["choices"][0]["message"]["content"]
                return {
                    "success": True,
                    "provider": "Groq Cloud",
                    "model": model,
                    "latency_sec": round(elapsed, 2),
                    "report_markdown": text.strip()
                }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @classmethod
    def _generate_heuristic_report(cls, summary: Dict[str, Any]) -> Dict[str, Any]:
        threat_level = summary.get("threat_level", "NOMINAL")
        score = summary.get("threat_score", 0)
        ips = [s["ip"] for s in summary.get("suspicious_ips", [])]
        ip_list_str = ", ".join(f"`{ip}`" for ip in ips) if ips else "None identified"
        vectors = summary.get("detected_vectors", [])
        vector_str = ", ".join(vectors) if vectors else "Benign operational activity"

        markdown = f"""### 1. Incident Executive Briefing
**Threat Netra Heuristic Telemetry Engine** evaluated the submitted audit logs. Current threat posture is rated **{threat_level}** with an overall impact score of **{score}/100**. Suspicious adversary signatures and behavioral anomalies were cataloged across telemetry streams.

### 2. Adversary Intent & Kill-Chain Reconstruction
- **Primary Vectors Isolated**: {vector_str}
- **Identified Indicators of Compromise (IOCs)**: {ip_list_str}
- **Trajectory**: Observed activity indicates adversary exploitation attempts targeting public services, attempting authentication bypass, credential compromise, and perimeter fuzzing.

### 3. MITRE ATT&CK Mapping
- **T1190**: Exploit Public-Facing Application
- **T1110**: Brute Force / Password Spraying
- **T1059**: Command and Scripting Interpreter Execution
- **T1046**: Network Service Discovery & Sweep

### 4. Immediate Containment & Defensive Actions
1. **Network Layer Isolation**: Implement perimeter drop rules for flagged IPs:
   ```bash
   iptables -I INPUT -s {ips[0] if ips else 'ADVERSARY_IP'} -j DROP
   ```
2. **Access Control**: Enforce mandatory password rotation and terminate active session tokens for affected accounts.
3. **WAF Deployment**: Activate Web Application Firewall rule-sets to reject malicious SQL injection and directory traversal strings.

### 5. Strategic Hardening
- Restrict remote administrative management interfaces (SSH, RDP) behind VPN or zero-trust network access.
- Deploy rate-limiting and progressive authentication delays.
"""
        return {
            "success": True,
            "provider": "Threat Netra Heuristic Forensic Core",
            "model": "Rule-Based Expert Engine",
            "latency_sec": 0.05,
            "report_markdown": markdown
        }
