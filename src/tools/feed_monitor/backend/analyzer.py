import os
import re
import json
import time
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
import httpx

logger = logging.getLogger("feed_monitor.analyzer")

def _load_env_config() -> Dict[str, str]:
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

    for k in ["GROQ_API_KEY", "GROQ_MODEL", "GEMMA_API_KEY", "GEMMA_MODEL", "OPEN_ROUTER_GEMMA"]:
        if k in os.environ:
            config[k] = os.environ[k]
    return config

def _build_prompt(feeds: List[Dict[str, Any]], scenarios: List[str]) -> str:
    feed_summaries = []
    for f in feeds:
        feed_summaries.append({
            "title": f.get("title", ""),
            "description": f.get("description", "")[:600]
        })

    return f"""You are an autonomous Cyber Threat Intelligence (CTI) triage analyst engine.
Evaluate whether the following feed items describe real cyber/kinetic threats and whether they EXPLICITLY state that any user alert scenario has occurred.

User Custom Scenarios to Alert On:
{json.dumps(scenarios)}

RULES FOR SCENARIO MATCHING:
1. Examine each article title and description carefully.
2. Does it EXPLICITLY match one of the user scenarios?
3. If it only talks about general news or loosely related themes without the specific event occurring, set "is_scenario_match" to false.
4. "is_threat" must be true if the event involves malware, ransomware, APT, data breaches, vulnerability exploitation, cyber attacks, or kinetic conflict.

Raw Feed Items:
{json.dumps(feed_summaries)}

Respond ONLY with a valid JSON object with a single key "analysis" containing an array of objects.
Do NOT enclose your response in markdown text other than valid JSON.
JSON format:
{{
  "analysis": [
    {{
      "item_title": "Exact original title of the item",
      "reasoning": "Step-by-step intelligence rationale explaining the threat assessment and scenario match.",
      "is_threat": true,
      "is_scenario_match": false,
      "matched_scenario_name": "Exact matching scenario string from the list, or 'None'",
      "summary": "Concise 1-2 sentence threat intelligence summary."
    }}
  ]
}}
"""

def _extract_json_analysis(raw_text: str) -> List[Dict[str, Any]]:
    if not raw_text:
        return []
    cleaned = raw_text.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned.split("```json", 1)[1].split("```", 1)[0].strip()
    elif cleaned.startswith("```"):
        cleaned = cleaned.split("```", 1)[1].split("```", 1)[0].strip()

    # Search for first { and last }
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1:
        cleaned = cleaned[first_brace:last_brace + 1]

    try:
        data = json.loads(cleaned)
        items = data.get("analysis", [])
        
        normalized = []
        invalid_tokens = {"none", "null", "false", "", "n/a", "no", "undefined"}
        for item in items:
            is_match = bool(item.get("is_scenario_match", False))
            matched_name = str(item.get("matched_scenario_name", "")).strip()
            
            if not is_match or matched_name.lower() in invalid_tokens:
                scenario_matched = None
                is_match = False
            else:
                scenario_matched = matched_name

            normalized.append({
                "item_title": item.get("item_title", "Untitled Item"),
                "reasoning": item.get("reasoning", "Autonomous CTI heuristic correlation."),
                "is_threat": bool(item.get("is_threat", False)),
                "is_scenario_match": is_match,
                "scenario_matched": scenario_matched,
                "matched_scenario_name": scenario_matched,
                "summary": item.get("summary", "Analysis completed.")
            })
        return normalized
    except Exception as e:
        logger.warning(f"Failed to parse LLM JSON: {e} | Text: {raw_text[:200]}")
        return []

def _heuristic_analysis(feeds: List[Dict[str, Any]], scenarios: List[str]) -> List[Dict[str, Any]]:
    results = []
    threat_keywords = [
        "ransomware", "malware", "apt", "breach", "zero-day", "0-day", "exploit",
        "cve", "ddos", "backdoor", "phishing", "leak", "hacked", "cyber", "attack",
        "espionage", "trojan", "vulnerability", "infostealer", "rce", "compromise"
    ]

    for f in feeds:
        title = f.get("title", "")
        desc = f.get("description", "")
        text = f"{title} {desc}".lower()
        
        is_threat = any(kw in text for kw in threat_keywords)
        
        matched_scenario = None
        for scen in scenarios:
            s_clean = scen.strip().lower()
            if not s_clean:
                continue
            words = [w for w in re.split(r'\W+', s_clean) if len(w) > 3]
            if words and any(w in text for w in words):
                matched_scenario = scen.strip()
                break

        is_match = matched_scenario is not None
        if is_match:
            reasoning = f"Heuristic match triggered for scenario '{matched_scenario}'. Key threat indicators identified in telemetry."
        elif is_threat:
            reasoning = "Cyber adversary indicators identified based on signature patterns and threat taxonomy."
        else:
            reasoning = "Informational telemetry item. No critical adversary markers or scenario thresholds exceeded."

        results.append({
            "item_title": title,
            "reasoning": reasoning,
            "is_threat": is_threat or is_match,
            "is_scenario_match": is_match,
            "scenario_matched": matched_scenario,
            "matched_scenario_name": matched_scenario,
            "summary": desc[:180] + ("..." if len(desc) > 180 else "") if desc else "Automated telemetry assessment completed."
        })
    return results

def _analyze_with_groq(feeds: List[Dict[str, Any]], scenarios: List[str], config: Dict[str, str]) -> Optional[List[Dict[str, Any]]]:
    api_key = config.get("GROQ_API_KEY")
    if not api_key:
        return None
    model = config.get("GROQ_MODEL", "openai/gpt-oss-120b")
    
    prompt = _build_prompt(feeds[:5], scenarios)
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a cyber threat intelligence engine. Respond only with structured JSON."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 1200,
        "response_format": {"type": "json_object"}
    }
    
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json=payload
            )
            if resp.status_code == 200:
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                parsed = _extract_json_analysis(content)
                if parsed:
                    return parsed
    except Exception as e:
        logger.error(f"Groq analysis error: {e}")
    return None

def _analyze_with_gemma(feeds: List[Dict[str, Any]], scenarios: List[str], config: Dict[str, str]) -> Optional[List[Dict[str, Any]]]:
    api_key = config.get("GEMMA_API_KEY")
    if not api_key:
        return None
    model = config.get("GEMMA_MODEL", "gemma-4-26b-a4b-it")
    
    prompt = _build_prompt(feeds[:5], scenarios)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }
    
    try:
        with httpx.Client(timeout=25.0) as client:
            resp = client.post(url, headers={"Content-Type": "application/json"}, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                parsed = _extract_json_analysis(text)
                if parsed:
                    return parsed
    except Exception as e:
        logger.error(f"Gemma analysis error: {e}")
    return None

def analyze_feeds(feeds: List[Dict[str, Any]], scenarios: List[str], provider: str = "auto") -> List[Dict[str, Any]]:
    """Analyzes ingested feeds against threat taxonomy and user alert scenarios."""
    if not feeds:
        return []

    config = _load_env_config()
    results: Optional[List[Dict[str, Any]]] = None

    prov = provider.lower()
    if prov == "groq":
        results = _analyze_with_groq(feeds, scenarios, config)
    elif prov == "gemma":
        results = _analyze_with_gemma(feeds, scenarios, config)
    else: # auto
        results = _analyze_with_groq(feeds, scenarios, config)
        if not results:
            results = _analyze_with_gemma(feeds, scenarios, config)

    # Heuristic fallback if LLMs fail or are offline
    if not results:
        logger.info("Using heuristic intelligence engine fallback.")
        results = _heuristic_analysis(feeds, scenarios)

    # Attach extracted URLs back to each result item
    feed_url_map = {f.get("title", "").strip().lower(): f.get("extracted_urls", []) for f in feeds}
    for item in results:
        title_key = item.get("item_title", "").strip().lower()
        if title_key in feed_url_map:
            item["extracted_urls"] = feed_url_map[title_key]
        else:
            # Substring match if title was slightly altered by LLM
            matched_urls = []
            for ft, urls in feed_url_map.items():
                if ft in title_key or title_key in ft:
                    matched_urls.extend(urls)
            item["extracted_urls"] = list(dict.fromkeys(matched_urls))

    return results
