import os
import sys
from dotenv import load_dotenv
from rich.console import Console

console = Console()

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
MAX_CHARS_PER_CALL = int(os.getenv("MAX_CHARS_PER_CALL", 25000))

def check_setup():
    if not GROQ_API_KEY:
        console.print("[bold red]Error:[/bold red] GROQ_API_KEY is not set in the .env file.")
        console.print("Please copy .env.example to .env and add your API key.")
        sys.exit(1)
