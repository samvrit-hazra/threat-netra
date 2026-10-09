import re
from collections import defaultdict
from typing import List, Dict, Any

# Signatures for Web Application Exploits
SQLI_PATTERN = re.compile(
    r"(?:union\s+(?:all\s+)?select|'\s*or\s*'?[0-9a-z]+'?\s*=\s*'?[0-9a-z]+|sleep\(\s*\d+\s*\)|waitfor\s+delay|information_schema|benchmark\(\s*\d+|load_file\()",
    re.IGNORECASE
)

PATH_TRAVERSAL_PATTERN = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|/etc/passwd|/etc/shadow|/windows/win\.ini|boot\.ini)",
    re.IGNORECASE
)

XSS_PATTERN = re.compile(
    r"(?:<script\b|javascript:|onerror\s*=|onload\s*=|alert\(|<img\s+src=.*?onerror)",
    re.IGNORECASE
)

RCE_PATTERN = re.compile(
    r"(?:;\s*(?:cat|ls|whoami|id|uname|curl|wget|nc|bash|powershell|cmd\.exe)|\bpowershell(?:\.exe)?\s+-[eE]|\bcurl\s+.*?\bsh\b|\bwget\s+.*?\bsh\b)",
    re.IGNORECASE
)

MALICIOUS_AGENTS = [
    "sqlmap", "nikto", "gobuster", "dirbuster", "wpscan", "masscan",
    "zgrab", "nuclei", "acunetix", "nessus", "nmap"
]

SENSITIVE_PATHS = [
    "/.env", "/.git", "/wp-login.php", "/phpmyadmin", "/admin/config",
    "/actuator/env", "/actuator/heapdump", "/.aws/credentials", "/api/v1/dump"
]

class ThreatDetector:
    @classmethod
    def analyze_events(cls, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        ip_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "request_count": 0,
            "failed_logins": 0,
            "attack_hits": 0,
            "ports_targeted": set(),
            "detected_vectors": set()
        })

        for event in events:
            raw_text = event.get("raw", "")
            src_ip = event.get("source_ip", "N/A")
            msg = event.get("message", "")
            path = event.get("path", "")
            user_agent = event.get("user_agent", "").lower()
            dst_port = event.get("destination_port", "")

            if src_ip and src_ip != "N/A":
                ip_stats[src_ip]["request_count"] += 1
                if dst_port and dst_port != "N/A":
                    ip_stats[src_ip]["ports_targeted"].add(dst_port)

            # 1. SQL Injection Detection
            sqli_match = SQLI_PATTERN.search(path) or SQLI_PATTERN.search(raw_text)
            if sqli_match:
                finding = cls._create_finding(
                    title="SQL Injection Exploit Attempt",
                    severity="CRITICAL",
                    event=event,
                    technique="T1190 - Exploit Public-Facing Application",
                    tactic="Initial Access",
                    detail=f"Detected SQL syntax pattern: '{sqli_match.group(0)}'",
                    confidence="High"
                )
                findings.append(finding)
                if src_ip != "N/A":
                    ip_stats[src_ip]["attack_hits"] += 1
                    ip_stats[src_ip]["detected_vectors"].add("SQL Injection")

            # 2. Path Traversal / LFI
            traversal_match = PATH_TRAVERSAL_PATTERN.search(path) or PATH_TRAVERSAL_PATTERN.search(raw_text)
            if traversal_match:
                finding = cls._create_finding(
                    title="Directory Path Traversal / LFI",
                    severity="HIGH",
                    event=event,
                    technique="T1006 - Direct Volume Access / T1083 - File Discovery",
                    tactic="Discovery",
                    detail=f"Detected directory traversal pattern: '{traversal_match.group(0)}'",
                    confidence="High"
                )
                findings.append(finding)
                if src_ip != "N/A":
                    ip_stats[src_ip]["attack_hits"] += 1
                    ip_stats[src_ip]["detected_vectors"].add("Path Traversal")

            # 3. Cross-Site Scripting (XSS)
            xss_match = XSS_PATTERN.search(path) or XSS_PATTERN.search(raw_text)
            if xss_match:
                finding = cls._create_finding(
                    title="Cross-Site Scripting (XSS) Vector",
                    severity="MEDIUM",
                    event=event,
                    technique="T1059.007 - JavaScript Execution",
                    tactic="Execution",
                    detail=f"Detected script injection pattern: '{xss_match.group(0)}'",
                    confidence="High"
                )
                findings.append(finding)
                if src_ip != "N/A":
                    ip_stats[src_ip]["attack_hits"] += 1
                    ip_stats[src_ip]["detected_vectors"].add("XSS")

            # 4. Command Injection / RCE
            rce_match = RCE_PATTERN.search(path) or RCE_PATTERN.search(raw_text)
            if rce_match:
                finding = cls._create_finding(
                    title="Command Injection / Remote Code Execution Probe",
                    severity="CRITICAL",
                    event=event,
                    technique="T1059 - Command and Scripting Interpreter",
                    tactic="Execution",
                    detail=f"Detected OS command execution payload: '{rce_match.group(0)}'",
                    confidence="High"
                )
                findings.append(finding)
                if src_ip != "N/A":
                    ip_stats[src_ip]["attack_hits"] += 1
                    ip_stats[src_ip]["detected_vectors"].add("Command Injection")

            # 5. Malicious Automated Security Scanner
            for scanner in MALICIOUS_AGENTS:
                if scanner in user_agent or scanner in raw_text.lower():
                    finding = cls._create_finding(
                        title=f"Automated Reconnaissance Tool: {scanner.upper()}",
                        severity="MEDIUM",
                        event=event,
                        technique="T1595.002 - Vulnerability Scanning",
                        tactic="Reconnaissance",
                        detail=f"Tool signature matched in User-Agent / log context: {scanner}",
                        confidence="High"
                    )
                    findings.append(finding)
                    if src_ip != "N/A":
                        ip_stats[src_ip]["attack_hits"] += 1
                        ip_stats[src_ip]["detected_vectors"].add("Automated Scanner")
                    break

            # 6. Sensitive Endpoint Probe
            for sens in SENSITIVE_PATHS:
                if sens in path.lower() or sens in raw_text.lower():
                    finding = cls._create_finding(
                        title=f"Sensitive Resource & Credential Probe ({sens})",
                        severity="HIGH",
                        event=event,
                        technique="T1552 - Unsecured Credentials",
                        tactic="Credential Access",
                        detail=f"Attempted access to sensitive configuration path: {sens}",
                        confidence="Medium"
                    )
                    findings.append(finding)
                    if src_ip != "N/A":
                        ip_stats[src_ip]["attack_hits"] += 1
                        ip_stats[src_ip]["detected_vectors"].add("Configuration Probe")
                    break

            # 7. Authentication Failures (SSH, PAM, Windows 4625)
            is_auth_failure = False
            msg_lower = msg.lower()
            if any(term in msg_lower for term in [
                "failed password", "authentication failure", "failed logon",
                "invalid user", "pam_authenticate: failure", "error: pam: 7"
            ]) or event.get("event_id") == "4625":
                is_auth_failure = True
                if src_ip != "N/A":
                    ip_stats[src_ip]["failed_logins"] += 1

            if is_auth_failure:
                finding = cls._create_finding(
                    title="Authentication Failure / Invalid Credential Attempt",
                    severity="LOW",
                    event=event,
                    technique="T1110 - Brute Force",
                    tactic="Credential Access",
                    detail=f"Authentication failure recorded: {msg[:100]}",
                    confidence="High"
                )
                findings.append(finding)

            # 8. Windows Security Auditing Events
            if event.get("event_id") == "4720":
                findings.append(cls._create_finding(
                    title="User Account Created (Event 4720)",
                    severity="HIGH",
                    event=event,
                    technique="T1136.001 - Local Account Creation",
                    tactic="Persistence",
                    detail="A new user account was provisioned on the host.",
                    confidence="High"
                ))
            elif event.get("event_id") == "7045":
                findings.append(cls._create_finding(
                    title="New Service Installed (Event 7045)",
                    severity="HIGH",
                    event=event,
                    technique="T1543.003 - Windows Service",
                    tactic="Persistence",
                    detail="A new system service was installed, potential persistence vector.",
                    confidence="High"
                ))
            elif event.get("event_id") == "1102":
                findings.append(cls._create_finding(
                    title="Audit Log Cleared (Event 1102)",
                    severity="CRITICAL",
                    event=event,
                    technique="T1070.001 - Clear Windows Event Logs",
                    tactic="Defense Evasion",
                    detail="The security audit log was explicitly cleared to evade detection.",
                    confidence="High"
                ))

        # 9. Aggregate Brute Force Correlation
        for ip, stats in ip_stats.items():
            if stats["failed_logins"] >= 3:
                findings.append({
                    "id": f"corr-brute-{ip}",
                    "title": f"Brute Force Password Attack from {ip}",
                    "severity": "CRITICAL" if stats["failed_logins"] >= 6 else "HIGH",
                    "source_ip": ip,
                    "technique": "T1110.001 - Password Guessing",
                    "tactic": "Credential Access",
                    "detail": f"{stats['failed_logins']} consecutive failed authentication attempts originating from IP {ip}.",
                    "confidence": "High",
                    "event_line": "Multiple correlated events"
                })
                stats["detected_vectors"].add("Brute Force Attack")

            # Port Scanning Correlation
            if len(stats["ports_targeted"]) >= 3:
                findings.append({
                    "id": f"corr-scan-{ip}",
                    "title": f"Port Sweep & Reconnaissance from {ip}",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "technique": "T1046 - Network Service Discovery",
                    "tactic": "Discovery",
                    "detail": f"Source scanned {len(stats['ports_targeted'])} distinct target ports: {list(stats['ports_targeted'])[:6]}.",
                    "confidence": "High",
                    "event_line": "Multiple firewall events"
                })
                stats["detected_vectors"].add("Port Sweep Scan")

        # Compile Suspicious IP Dossier
        suspicious_ips = []
        for ip, stats in ip_stats.items():
            if stats["failed_logins"] >= 2 or stats["attack_hits"] >= 1 or len(stats["ports_targeted"]) >= 2:
                suspicious_ips.append({
                    "ip": ip,
                    "total_requests": stats["request_count"],
                    "failed_logins": stats["failed_logins"],
                    "exploit_hits": stats["attack_hits"],
                    "vectors": list(stats["detected_vectors"]),
                    "risk_level": "CRITICAL" if (stats["attack_hits"] >= 2 or stats["failed_logins"] >= 5) else "HIGH"
                })

        suspicious_ips.sort(key=lambda x: (x["failed_logins"] + x["exploit_hits"] * 2), reverse=True)

        # Calculate Overall Threat Score (0 to 100)
        critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in findings if f["severity"] == "HIGH")
        medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
        low_count = sum(1 for f in findings if f["severity"] == "LOW")

        base_score = min(100, (critical_count * 35) + (high_count * 20) + (medium_count * 8) + (low_count * 3))
        if critical_count > 0:
            base_score = max(base_score, 60)

        if base_score >= 75:
            threat_level = "CRITICAL"
        elif base_score >= 45:
            threat_level = "HIGH"
        elif base_score >= 20:
            threat_level = "ELEVATED"
        else:
            threat_level = "NOMINAL"

        return {
            "threat_score": base_score,
            "threat_level": threat_level,
            "total_findings": len(findings),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "findings": findings,
            "suspicious_ips": suspicious_ips,
            "detected_vectors": list({v for s in ip_stats.values() for v in s["detected_vectors"]})
        }

    @staticmethod
    def _create_finding(
        title: str,
        severity: str,
        event: Dict[str, Any],
        technique: str,
        tactic: str,
        detail: str,
        confidence: str
    ) -> Dict[str, Any]:
        return {
            "id": f"find-{event.get('id', 'unk')}",
            "title": title,
            "severity": severity,
            "event_id": event.get("id"),
            "event_line": event.get("line_number"),
            "timestamp": event.get("timestamp", "N/A"),
            "source_ip": event.get("source_ip", "N/A"),
            "technique": technique,
            "tactic": tactic,
            "detail": detail,
            "confidence": confidence,
            "raw_snippet": event.get("raw", "")[:140]
        }
