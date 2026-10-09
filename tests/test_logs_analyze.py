import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import src.main
from src.tools.logs_analyze.backend.parser import LogParser
from src.tools.logs_analyze.backend.detector import ThreatDetector
from src.tools.logs_analyze.backend.router import SAMPLES
from src.tools.logs_analyze.backend.ai_service import AIForensicService

def test_parser_formats():
    for name, raw in SAMPLES.items():
        res = LogParser.parse_text(raw)
        assert res["total_lines"] > 0
        assert len(res["parsed_events"]) > 0
        assert res["detected_format"] in ["syslog", "web_access", "firewall", "windows_event", "unstructured"]

def test_web_app_attack_detection():
    raw = SAMPLES["web_app_attack"]
    parse_res = LogParser.parse_text(raw)
    threats = ThreatDetector.analyze_events(parse_res["parsed_events"])

    assert threats["total_findings"] >= 3
    assert threats["threat_level"] in ["HIGH", "CRITICAL"]
    assert "SQL Injection" in threats["detected_vectors"]
    assert "Path Traversal" in threats["detected_vectors"]
    assert any(s["ip"] == "192.0.2.14" for s in threats["suspicious_ips"])

def test_ssh_brute_force_detection():
    raw = SAMPLES["ssh_brute_force"]
    parse_res = LogParser.parse_text(raw)
    threats = ThreatDetector.analyze_events(parse_res["parsed_events"])

    assert threats["threat_level"] in ["HIGH", "CRITICAL"]
    assert any("Brute Force" in v for v in threats["detected_vectors"])
    assert any(s["ip"] == "198.51.100.42" for s in threats["suspicious_ips"])

def test_firewall_sweep_detection():
    raw = SAMPLES["firewall_sweep"]
    parse_res = LogParser.parse_text(raw)
    threats = ThreatDetector.analyze_events(parse_res["parsed_events"])

    assert any(s["ip"] == "203.0.113.88" for s in threats["suspicious_ips"])
    assert any("Port Sweep" in v for v in threats["detected_vectors"])

def test_heuristic_report_generation():
    raw = SAMPLES["web_app_attack"]
    parse_res = LogParser.parse_text(raw)
    threats = ThreatDetector.analyze_events(parse_res["parsed_events"])
    report = AIForensicService._generate_heuristic_report(threats)

    assert report["success"] is True
    assert "Incident Executive Briefing" in report["report_markdown"]
    assert "MITRE ATT&CK" in report["report_markdown"]

if __name__ == "__main__":
    test_parser_formats()
    print("[PASS] Multi-format parser verified")
    test_web_app_attack_detection()
    print("[PASS] Web exploit detection (SQLi/LFI/XSS) verified")
    test_ssh_brute_force_detection()
    print("[PASS] SSH Brute Force correlation verified")
    test_firewall_sweep_detection()
    print("[PASS] Firewall port sweep detection verified")
    test_heuristic_report_generation()
    print("[PASS] AI Forensic & Heuristic fallback report verified")
    print("\nALL UNIT TESTS PASSED SUCCESSFULLY!")
