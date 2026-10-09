import logging
from typing import Optional
from supabase import create_client, Client
from src.auth.backend.config import (
    SUPABASE_URL,
    SUPABASE_KEY,
    SUPABASE_SERVICE_ROLE_KEY,
    is_supabase_configured,
)

logger = logging.getLogger("threatnetra.auth")

_supabase_client: Optional[Client] = None
_supabase_admin_client: Optional[Client] = None

def get_supabase_client() -> Optional[Client]:
    """Returns the anon Supabase client for client-tier operations."""
    global _supabase_client
    if not is_supabase_configured():
        return None
    if _supabase_client is None:
        try:
            _supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
        except Exception as e:
            logger.error(f"Failed to initialize Supabase anon client: {e}")
            return None
    return _supabase_client

def get_supabase_admin_client() -> Optional[Client]:
    """Returns the service-role Supabase client for admin operations."""
    global _supabase_admin_client
    if not is_supabase_configured():
        return None
    if _supabase_admin_client is None:
        key = SUPABASE_SERVICE_ROLE_KEY or SUPABASE_KEY
        try:
            _supabase_admin_client = create_client(SUPABASE_URL, key)
        except Exception as e:
            logger.error(f"Failed to initialize Supabase admin client: {e}")
            return None
    return _supabase_admin_client
