import os
import re
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
import httpx

logger = logging.getLogger("profile_auth.ai_analyzer")

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

    for k in ["AI_PROVIDER", "GROQ_API_KEY", "GROQ_MODEL", "GEMMA_API_KEY", "GEMMA_MODEL"]:
        if k in os.environ:
            config[k] = os.environ[k]
    return config

def _extract_json_block(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned.split("```json", 1)[1].split("```", 1)[0].strip()
    elif cleaned.startswith("```"):
        cleaned = cleaned.split("```", 1)[1].split("```", 1)[0].strip()

    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1:
        cleaned = cleaned[first_brace:last_brace+1]

    try:
        return json.loads(cleaned)
    except Exception as e:
        logger.warning(f"Error decoding JSON block from LLM: {e}")
        return None

def _call_groq_analysis(prompt: str, config: Dict[str, str]) -> Optional[Dict[str, Any]]:
    api_key = config.get("GROQ_API_KEY")
    if not api_key or "your_" in api_key:
        return None
    model = config.get("GROQ_MODEL", "openai/gpt-oss-120b")

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are Threat Netra's Senior OSINT & Counter-Intelligence Forensic Analyst. "
                    "Analyze social media scraping telemetry and detect synthetic bots, disinformation sock-puppets, "
                    "and fake accounts. Respond with strictly valid JSON only."
                )
            },
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 1600,
        "response_format": {"type": "json_object"}
    }

    try:
        with httpx.Client(timeout=14.0) as client:
            resp = client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json=payload
            )
            if resp.status_code == 200:
                content = resp.json()["choices"][0]["message"]["content"]
                parsed = _extract_json_block(content)
                if parsed:
                    parsed["ai_engine_used"] = f"Groq LPU ({model})"
                    return parsed
    except Exception as e:
        logger.warning(f"Groq profile analysis error: {e}")
    return None

def _call_gemma_analysis(prompt: str, config: Dict[str, str]) -> Optional[Dict[str, Any]]:
    api_key = config.get("GEMMA_API_KEY")
    if not api_key or "your_" in api_key:
        return None
    model = config.get("GEMMA_MODEL", "gemma-4-26b-a4b-it")

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    payload = {
        "contents": [
            {"parts": [{"text": f"{prompt}\n\nIMPORTANT: Output strictly valid RFC8259 JSON format only."}]}
        ]
    }

    try:
        with httpx.Client(timeout=12.0) as client:
            resp = client.post(url, headers={"Content-Type": "application/json"}, json=payload)
            if resp.status_code == 200:
                parts = resp.json()["candidates"][0]["content"]["parts"]
                text = parts[0]["text"]
                parsed = _extract_json_block(text)
                if parsed:
                    parsed["ai_engine_used"] = f"Google Gemma ({model})"
                    return parsed
    except Exception as e:
        logger.warning(f"Gemma profile analysis error: {e}")
    return None

def _heuristic_analysis(telemetry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic defense forensic heuristic engine used when LLM APIs are unreachable.
    Evaluates follower/following ratios, post velocity, bio patterns, digit density,
    and Wayback Machine archival presence.
    """
    target = telemetry.get("target", "unknown_target")
    platform = telemetry.get("platform", "generic")
    extracted = telemetry.get("extracted_data", {})
    twitter_archive = telemetry.get("twitter_archive") or {}

    followers_str = str(extracted.get("follower_count", "0")).upper().replace(",", "")
    following_str = str(extracted.get("following_count", "0")).upper().replace(",", "")
    posts_str = str(extracted.get("posts_count", "0")).upper().replace(",", "")
    bio = extracted.get("bio", "")

    # Parse numeric approximations
    def parse_num(val_str: str) -> float:
        val_str = val_str.strip()
        mult = 1.0
        if val_str.endswith("K"):
            mult = 1000.0
            val_str = val_str[:-1]
        elif val_str.endswith("M"):
            mult = 1000000.0
            val_str = val_str[:-1]
        elif val_str.endswith("B"):
            mult = 1000000000.0
            val_str = val_str[:-1]
        try:
            return float(val_str) * mult
        except Exception:
            return 0.0

    followers = parse_num(followers_str)
    following = parse_num(following_str)
    posts = parse_num(posts_str)

    score = 25  # baseline fake score
    anomalies = []

    # 1. Digits in username
    digit_count = sum(c.isdigit() for c in target)
    if digit_count >= 5:
        score += 20
        anomalies.append({
            "indicator": f"High Numeric Suffix Density ({digit_count} digits)",
            "severity": "HIGH",
            "detail": "Automated bot generators typically append pseudo-random numeric strings to handles."
        })
    elif digit_count >= 3:
        score += 8
        anomalies.append({
            "indicator": f"Moderate Numeric Handle Patterns ({digit_count} digits)",
            "severity": "MEDIUM",
            "detail": "Standard username generation pattern observed."
        })

    # 2. Follower to Following ratio
    if following > 500 and followers < 50:
        score += 25
        anomalies.append({
            "indicator": "Extreme Asymmetric Following Ratio",
            "severity": "HIGH",
            "detail": f"Account follows {int(following)} users but only has {int(followers)} followers, typical of automated scraping or spam vectors."
        })
    elif following > 1000 and (followers / (following + 1)) < 0.2:
        score += 15
        anomalies.append({
            "indicator": "Unbalanced Follower/Following Curve",
            "severity": "MEDIUM",
            "detail": "Ratio exhibits inorganic acquisition profile."
        })
    elif followers > 10000 and following < 2000:
        score -= 15

    # 3. Bio characteristics
    if not bio or bio.strip() in ("No description snippet available.", f"Metadata indexed for {target}"):
        score += 12
        anomalies.append({
            "indicator": "Sparse / Missing Public Bio Metadata",
            "severity": "MEDIUM",
            "detail": "No indexed profile biography or description was isolated in search telemetry."
        })
    elif len(bio) < 25:
        score += 5
    elif any(kw in bio.lower() for kw in ["crypto", "airdrop", "giveaway", "dm for promo", "telegram"]):
        score += 18
        anomalies.append({
            "indicator": "High-Risk Spam / Monetization Keywords in Bio",
            "severity": "HIGH",
            "detail": "Bio contains promotional or solicitation keywords frequently associated with sybil clusters."
        })

    # 4. Wayback Machine Archive History (For Twitter / X)
    archived_snapshots = extracted.get("archived_status_count", 0)
    if platform.lower() in ("twitter", "x", "twitter.com", "x.com"):
        if archived_snapshots > 0:
            score -= 20
            anomalies.append({
                "indicator": f"Historical Wayback Archive Footprint Confirmed ({archived_snapshots} snapshots)",
                "severity": "LOW",
                "detail": "Public status archives exist in the Wayback Machine, evidencing authentic historical tenure."
            })
        else:
            score += 10
            anomalies.append({
                "indicator": "Zero Historical Wayback Machine Snapshots",
                "severity": "MEDIUM",
                "detail": "No historical status archives found in CDX index, suggesting newly minted or ephemeral profile."
            })

    # 5. Search visibility
    total_results = telemetry.get("total_results", 0)
    if total_results == 0:
        score += 15
        anomalies.append({
            "indicator": "Zero Indexed Public Search Citations",
            "severity": "HIGH",
            "detail": "Account handle has zero historical indexed citations across primary search caches."
        })
    elif total_results >= 5:
        score -= 10

    # Clamp 0 - 100
    fake_prob = max(5, min(95, score))
    authenticity_score = 100 - fake_prob

    if fake_prob >= 70:
        risk_tier = "CRITICAL"
        verdict = "HIGH PROBABILITY SYNTHETIC BOT / SOCK-PUPPET"
        summary = (
            f"Forensic reconnaissance indicates a high likelihood of automated or synthetic behavior for @{target}. "
            f"Telemetry isolates multiple irregular indicators including anomalous graph ratios, absent bio markers, "
            f"and ephemeral timeline footprint."
        )
    elif fake_prob >= 40:
        risk_tier = "ELEVATED"
        verdict = "SUSPICIOUS / INORGANIC ACTIVITY DETECTED"
        summary = (
            f"Reconnaissance telemetry for @{target} exhibits mixed authenticity markers. "
            f"While basic presence exists, behavioral ratios and archival presence display anomalies "
            f"warranting continuous monitoring."
        )
    else:
        risk_tier = "NOMINAL"
        verdict = "LIKELY AUTHENTIC ORGANIC OPERATOR"
        summary = (
            f"Forensic signals for @{target} are consistent with an established, authentic user profile. "
            f"Verified search citations, organic audience graph, and lack of synthetic patterns indicate legitimate operation."
        )

    return {
        "fake_probability_percent": fake_prob,
        "authenticity_score": authenticity_score,
        "risk_tier": risk_tier,
        "verdict_headline": verdict,
        "executive_summary": summary,
        "anomaly_indicators": anomalies,
        "wayback_forensics": (
            f"Wayback CDX crawler verified {archived_snapshots} archival status records. "
            f"{'Historical presence confirmed in public internet memory.' if archived_snapshots > 0 else 'No historical snapshots cataloged in internet archives.'}"
        ),
        "identity_graph_breakdown": (
            f"Target: @{target} on {platform.upper()}. "
            f"Audience graph: {followers_str} followers vs {following_str} following across {posts_str} posts. "
            f"Total search citations isolated: {total_results}."
        ),
        "recommended_actions": [
            "Monitor correlated IP and network autonomous systems (ASN) for multi-account orchestration.",
            "Cross-reference handle syntax across secondary platforms using OSINT dorking syntax.",
            "Inspect engagement velocity (reposts vs replies) for automated bot schedule cadences."
        ],
        "ai_engine_used": "Deterministic Defense Heuristic"
    }

def analyze_profile_telemetry(telemetry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point to perform AI forensic analysis on scraped governmental social media telemetry.
    Attempts Groq LPU first, falls back to Google Gemma 2, and finally to deterministic heuristic engine.
    """
    config = _load_env_config()
    target = telemetry.get("target", "unknown")
    platform = telemetry.get("platform", "unknown")
    extracted = telemetry.get("extracted_data", {})
    twitter_archive = telemetry.get("twitter_archive") or {}
    citations = extracted.get("indexed_citations", [])

    citations_summary = []
    for c in citations[:5]:
        title = c.get("title", "")
        desc = c.get("description", "")
        link = c.get("link", "")
        citations_summary.append(f"- [{title}] ({link}): {desc[:120]}")
    citations_text = "\n".join(citations_summary) if citations_summary else "No search citations indexed."

    prompt = f"""You are Threat Netra's Senior OSINT & Counter-Intelligence Forensic Analyst.
Evaluate the following governmental intelligence telemetry scraped for a target social media profile:

TARGET: @{target}
PLATFORM: {platform}
PRIMARY URL: {telemetry.get('primary_profile_url', 'N/A')}
BIO EXTRACT: "{extracted.get('bio', 'None')}"
AUDIENCE STATS: Followers: {extracted.get('follower_count', 'N/A')} | Following: {extracted.get('following_count', 'N/A')} | Posts: {extracted.get('posts_count', 'N/A')}
SEARCH RECONNAISSANCE: {telemetry.get('total_results', 0)} public results indexed on Bing RSS.
SAMPLE SEARCH SNIPPETS:
{citations_text}

WAYBACK MACHINE ARCHIVE STATUS (Twitter/X):
- Archival Status: {extracted.get('wayback_archive_status', 'N/A')}
- Total Historical Snapshots: {extracted.get('archived_status_count', 0)}
- Archive Sample: {json.dumps(twitter_archive.get('snapshots', [])[:3]) if twitter_archive else 'None'}

TASK:
Provide a rigorous, production-grade intelligence assessment determining whether this profile is FAKE / SYNTHETIC (bot, troll-farm operative, sock-puppet, impersonator) or AUTHENTIC (genuine organic human).

YOU MUST RETURN STRICT JSON MATCHING THIS EXACT SCHEMA:
{{
  "fake_probability_percent": <integer between 0 and 100 representing probability that this account is fake/bot>,
  "authenticity_score": <integer between 0 and 100 representing probability of being genuine (100 - fake_probability_percent)>,
  "risk_tier": "<one of: CRITICAL, HIGH, ELEVATED, NOMINAL>",
  "verdict_headline": "<Short uppercase military verdict, e.g. HIGH PROBABILITY SYNTHETIC BOT / DISINFORMATION VECTOR or LIKELY AUTHENTIC ENTITY>",
  "executive_summary": "<2-3 paragraph authoritative intelligence summary evaluating the account's digital footprint, behavioral markers, and legitimacy>",
  "anomaly_indicators": [
    {{
      "indicator": "<Name of anomaly, e.g. Skewed Following Velocity>",
      "severity": "<HIGH | MEDIUM | LOW>",
      "detail": "<Specific factual evidence from the telemetry>"
    }}
  ],
  "wayback_forensics": "<Specific analysis of whether the presence or absence of Wayback historical snapshots proves organic longevity or newly minted burner/bot status>",
  "identity_graph_breakdown": "<Analysis of audience ratios, bio keywords, and cross-platform presence>",
  "recommended_actions": [
    "<Specific technical investigative step 1>",
    "<Specific technical investigative step 2>",
    "<Specific technical investigative step 3>"
  ]
}}
"""

    preferred_provider = config.get("AI_PROVIDER", "groq").lower()

    # 1. Primary provider
    if preferred_provider == "groq":
        result = _call_groq_analysis(prompt, config)
        if result and "fake_probability_percent" in result:
            return _normalize_result(result)
        # Failover to Gemma
        result = _call_gemma_analysis(prompt, config)
        if result and "fake_probability_percent" in result:
            return _normalize_result(result)
    else:
        result = _call_gemma_analysis(prompt, config)
        if result and "fake_probability_percent" in result:
            return _normalize_result(result)
        # Failover to Groq
        result = _call_groq_analysis(prompt, config)
        if result and "fake_probability_percent" in result:
            return _normalize_result(result)

    # 2. Heuristic fallback
    return _heuristic_analysis(telemetry)

def _normalize_result(res: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitizes and enforces field constraints."""
    try:
        fake_prob = int(res.get("fake_probability_percent", 50))
    except Exception:
        fake_prob = 50
    fake_prob = max(0, min(100, fake_prob))
    res["fake_probability_percent"] = fake_prob
    res["authenticity_score"] = 100 - fake_prob

    if "risk_tier" not in res:
        if fake_prob >= 75:
            res["risk_tier"] = "CRITICAL"
        elif fake_prob >= 50:
            res["risk_tier"] = "HIGH"
        elif fake_prob >= 25:
            res["risk_tier"] = "ELEVATED"
        else:
            res["risk_tier"] = "NOMINAL"

    if "anomaly_indicators" not in res or not isinstance(res["anomaly_indicators"], list):
        res["anomaly_indicators"] = []

    if "recommended_actions" not in res or not isinstance(res["recommended_actions"], list):
        res["recommended_actions"] = ["Flag profile for automated graph monitoring."]

    return res
