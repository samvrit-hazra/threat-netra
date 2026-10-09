import os
import json
import time
import logging
from google import genai
from google.genai.errors import APIError
from groq import Groq

logger = logging.getLogger(__name__)

def _build_prompt(feeds: list, scenarios: list) -> str:
    """Centralized prompt engineer logic for all providers."""
    return f"""
    You are an autonomous Cyber Threat Intelligence (CTI) analyst engine.
    Read the feed items and determine if they EXPLICITLY state that a user scenario has occurred.

    User Custom Scenarios to Alert On: {json.dumps(scenarios)}

    RULES FOR SCENARIO MATCHING:
    1. Read the article title and description carefully.
    2. Does it EXPLICITLY and CLEARLY state that the scenario happened? 
    3. If it only talks about related topics (like "war" or "tensions") but does NOT say it ended or the specific event happened, then it is NOT a match.
    4. "is_scenario_match" MUST be false unless the exact event occurred.

    Raw Feed Items:
    {json.dumps(feeds)}
    
    Respond ONLY with a valid JSON object containing a single key "analysis" which holds an array of objects. Do not include markdown formatting.
    Structure:
    {{
        "analysis": [
            {{
                "item_title": "Original title of the item",
                "reasoning": "Explain step-by-step why it does or does not match the scenario.",
                "is_threat": true or false,
                "is_scenario_match": true or false,
                "matched_scenario_name": "If is_scenario_match is true, put the exact scenario name here. If false, put exactly 'None'.",
                "summary": "A brief 1-2 sentence cyber threat intelligence summary of the item."
            }}
        ]
    }}
    """

def _extract_json(raw_text: str) -> list:
    """Safely extracts the analysis array from raw LLM output."""
    raw_text = raw_text.strip()
    if raw_text.startswith("```json"):
        raw_text = raw_text.split("```json")[1].split("```")[0].strip()
    elif raw_text.startswith("```"):
        raw_text = raw_text.split("```")[1].split("```")[0].strip()
        
    try:
        data = json.loads(raw_text)
        results = data.get("analysis", [])
        
        # Normalize the output so the frontend doesn't break
        for r in results:
            if not r.get("is_scenario_match"):
                r["scenario_matched"] = None
            else:
                name = r.get("matched_scenario_name")
                r["scenario_matched"] = None if name in ["None", "null", "false", "", "N/A", "no"] else name
                
        return results
    except json.JSONDecodeError as e:
        logger.error(f"JSON Parse Error: {e} | Raw string: {raw_text}")
        return []

def _mock_response(feeds: list, scenarios: list, missing_key_msg: str) -> list:
    mock_results = []
    for f in feeds:
        title = f.get("title", "")
        is_scen_match = any(scen.lower() in title.lower() for scen in scenarios) if scenarios else False
        mock_results.append({
            "item_title": title,
            "is_threat": is_scen_match,
            "scenario_matched": scenarios[0] if is_scen_match and scenarios else None,
            "summary": f"[MOCK] {missing_key_msg}. This is a simulated fallback response."
        })
    return mock_results

def analyze_with_groq(feeds: list, scenarios: list) -> list:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key or api_key == "your_actual_api_key_here":
        logger.warning("GROQ_API_KEY is missing, generating mock response.")
        return _mock_response(feeds, scenarios, "GROQ_API_KEY is missing")
        
    client = Groq(api_key=api_key)
    capped_feeds = feeds[:4]
    prompt = _build_prompt(capped_feeds, scenarios)
    
    model_name = "qwen/qwen3.8-27b"
    
    try:
        logger.info(f"Attempting inference with Groq ({model_name})...")
        chat_completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=model_name,
            temperature=0.0, 
            max_tokens=800,
            response_format={"type": "json_object"}
        )
        return _extract_json(chat_completion.choices[0].message.content)
    except Exception as e:
        logger.error(f"Error calling Groq: {e}")
        
        if "model_not_found" in str(e) or "404" in str(e) or "rate_limit_exceeded" in str(e):
            fallback_model = "allam-2-7b"
            logger.info(f"Model {model_name} failed, attempting fallback to {fallback_model}...")
            try:
                chat_completion = client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}],
                    model=fallback_model,
                    temperature=0.0,
                    max_tokens=800,
                    response_format={"type": "json_object"}
                )
                return _extract_json(chat_completion.choices[0].message.content)
            except Exception as inner_e:
                logger.error(f"Groq Fallback API Error: {str(inner_e)}")
                return [{"error": f"Groq Fallback API Error: {str(inner_e)}"}]
                
        return [{"error": f"Groq API Error: {str(e)}"}]

import httpx

def analyze_with_google(feeds: list, scenarios: list) -> list:
    api_key = os.environ.get("OPEN_ROUTER_GEMMA")
    if not api_key or api_key == "your_actual_api_key_here":
        logger.warning("OPEN_ROUTER_GEMMA is missing, generating mock response.")
        return _mock_response(feeds, scenarios, "OPEN_ROUTER_GEMMA is missing")
        
    capped_feeds = feeds[:4]
    prompt = _build_prompt(capped_feeds, scenarios)
    
    model_name = "google/gemma-4-26b-a4b-it:free"
    
    try:
        logger.info(f"Attempting inference with OpenRouter ({model_name})...")
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
            "response_format": {"type": "json_object"}
        }
        
        with httpx.Client(timeout=30.0) as client:
            max_retries = 3
            base_delay = 2.0
            
            for attempt in range(max_retries):
                resp = client.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload)
                
                if resp.status_code == 429:
                    if attempt < max_retries - 1:
                        sleep_time = base_delay * (2 ** attempt)
                        logger.warning(f"OpenRouter Rate Limit hit (429). Retrying in {sleep_time}s...")
                        time.sleep(sleep_time)
                        continue
                    else:
                        raise Exception(f"OpenRouter API rate limit exceeded after {max_retries} retries.")
                
                resp.raise_for_status()
                break
                
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return _extract_json(content)
            
    except Exception as e:
        logger.error(f"Error calling OpenRouter: {e}")
        return [{"error": f"OpenRouter API Error: {str(e)}"}]

# ---- Main Exported Function ----
def analyze_feeds(feeds: list, scenarios: list, provider: str = "google") -> list:
    """Routes the analysis request to the designated LLM provider."""
    if provider == "groq":
        results = analyze_with_groq(feeds, scenarios)
    else:
        results = analyze_with_google(feeds, scenarios)
        
    for r in results:
        title = r.get("item_title", "")
        for f in feeds:
            if f.get("title") == title:
                r["extracted_urls"] = f.get("extracted_urls", [])
                break
                
    return results
