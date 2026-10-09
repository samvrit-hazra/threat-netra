import os
from dotenv import load_dotenv

# Load .env file from project root
load_dotenv()

_raw_url = os.getenv("SUPABASE_URL", "").strip()
if "/rest/v1" in _raw_url:
    _raw_url = _raw_url.split("/rest/v1")[0]
SUPABASE_URL = _raw_url.rstrip("/")

SUPABASE_KEY = os.getenv("SUPABASE_KEY", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

OWNER_EMAIL = os.getenv("OWNER_EMAIL", "admin@threatnetra.com").strip().lower()

DEMO_EMAIL = os.getenv("DEMO_EMAIL", "demo@threatnetra.com").strip().lower()
DEMO_PASSWORD = os.getenv("DEMO_PASSWORD", "threatnetra-demo-2026")

def is_supabase_configured() -> bool:
    return bool(SUPABASE_URL and SUPABASE_KEY and not SUPABASE_URL.startswith("your_"))
