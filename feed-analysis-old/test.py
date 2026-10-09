import os
import sys
from google import genai
from google.genai.errors import APIError

# 1. Ensure API key is configured
api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    print(
        "Error: GEMINI_API_KEY environment variable is not set.\n"
        "Get your API key at: https://aistudio.google.com/\n"
        "Set it in your terminal with: export GEMINI_API_KEY='your_api_key'",
        file=sys.stderr,
    )
    sys.exit(1)

# 2. Initialize Google GenAI client
client = genai.Client(api_key=api_key)

# 3. Use an existing Gemma model (e.g., 'gemma-2-27b-it' or 'gemma-2-9b-it')
MODEL_NAME = "gemma-2-27b-it"

try:
    response = client.models.generate_content(
        model=MODEL_NAME,
        contents="Explain quantum computing in simple terms.",
    )
    print(response.text)
except APIError as e:
    print(f"API Error ({e.code}): {e.message}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred: {e}", file=sys.stderr)
    sys.exit(1)
