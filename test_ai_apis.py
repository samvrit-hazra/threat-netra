"""
Diagnostic script to test Gemma (Google AI Studio) and Groq APIs.
Reads keys directly from .env and verifies API connectivity, models, and latency.
"""

import os
import sys
import json
import time
import ssl
import urllib.request
import urllib.error
from pathlib import Path

def load_env(env_path: Path) -> dict:
    env_vars = {}
    if not env_path.exists():
        return env_vars
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env_vars[k.strip()] = v.strip().strip("'\"")
    return env_vars

def test_gemma(api_key: str, model: str):
    print(f"\n{'='*50}")
    print(f"[TEST 1] Testing Gemma API (Google AI Studio)")
    print(f"Model: {model}")
    print(f"{'='*50}")

    if not api_key or "your_" in api_key:
        print("[FAIL] GEMMA_API_KEY is not configured in .env.")
        return False

    context = ssl.create_default_context()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": "State in one brief sentence: Threat Netra Gemma API connection verified successfully."}
                ]
            }
        ]
    }

    start = time.time()
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )

    try:
        with urllib.request.urlopen(req, context=context, timeout=20) as resp:
            elapsed = time.time() - start
            res = json.loads(resp.read().decode())
            candidate = res.get("candidates", [{}])[0]
            parts = candidate.get("content", {}).get("parts", [{}])
            text = parts[0].get("text", "").strip()
            print(f"[SUCCESS] Status: 200 OK (Latency: {elapsed:.2f}s)")
            print(f"Response: {text}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[FAIL] HTTP Error {e.code}: {e.reason}")
        print("Details:", e.read().decode("utf-8", errors="ignore"))
        return False
    except Exception as e:
        print(f"[FAIL] Error: {e}")
        return False

def test_groq(api_key: str, model: str):
    print(f"\n{'='*50}")
    print(f"[TEST 2] Testing Groq API")
    print(f"Model: {model}")
    print(f"{'='*50}")

    if not api_key or "your_" in api_key:
        print("[FAIL] GROQ_API_KEY is not configured in .env.")
        return False

    context = ssl.create_default_context()
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "ThreatNetra/1.0",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are an assistant for Threat Netra."},
            {"role": "user", "content": "State in one brief sentence: Threat Netra Groq API connection verified successfully."}
        ],
        "max_tokens": 100
    }

    start = time.time()
    req = urllib.request.Request(
        url,
        headers=headers,
        data=json.dumps(payload).encode("utf-8")
    )

    try:
        with urllib.request.urlopen(req, context=context, timeout=20) as resp:
            elapsed = time.time() - start
            res = json.loads(resp.read().decode())
            content = res["choices"][0]["message"]["content"].strip()
            usage = res.get("usage", {})
            print(f"[SUCCESS] Status: 200 OK (Latency: {elapsed:.2f}s)")
            print(f"Response: {content}")
            print(f"Usage: {usage.get('total_tokens', 'N/A')} total tokens (queue: {usage.get('queue_time', 'N/A')}s, prompt: {usage.get('prompt_time', 'N/A')}s)")
            return True
    except urllib.error.HTTPError as e:
        print(f"[FAIL] HTTP Error {e.code}: {e.reason}")
        print("Details:", e.read().decode("utf-8", errors="ignore"))
        return False
    except Exception as e:
        print(f"[FAIL] Error: {e}")
        return False

def main():
    env_file = Path(__file__).resolve().parent / ".env"
    env_vars = load_env(env_file)

    gemma_key = env_vars.get("GEMMA_API_KEY", "")
    gemma_model = env_vars.get("GEMMA_MODEL", "gemma-4-26b-a4b-it")

    groq_key = env_vars.get("GROQ_API_KEY", "")
    groq_model = env_vars.get("GROQ_MODEL", "openai/gpt-oss-120b")

    gemma_ok = test_gemma(gemma_key, gemma_model)
    groq_ok = test_groq(groq_key, groq_model)

    print(f"\n{'='*50}")
    print("Summary:")
    print(f" - Gemma ({gemma_model}): {'PASSED' if gemma_ok else 'FAILED'}")
    print(f" - Groq  ({groq_model}): {'PASSED' if groq_ok else 'FAILED'}")
    print(f"{'='*50}\n")

if __name__ == "__main__":
    main()
