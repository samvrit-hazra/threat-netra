import logging
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, status
from fastapi.responses import RedirectResponse

from src.auth.backend.config import is_supabase_configured, OWNER_EMAIL
from src.auth.backend.client import get_supabase_client, get_supabase_admin_client
from src.auth.backend.mock_store import get_user_from_mock_token, find_mock_user_by_id

logger = logging.getLogger("threatnetra.auth")

def get_token_from_request(request: Request) -> Optional[str]:
    """Extract auth token from cookie or Authorization header."""
    token = request.cookies.get("sb_access_token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
    return token

def is_html_request(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    if "/api/" in request.url.path:
        return False
    if "application/json" in accept and "text/html" not in accept:
        return False
    return True

async def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    """
    Retrieves the currently authenticated user and their profile.
    Returns None if unauthenticated.
    """
    token = get_token_from_request(request)
    if not token:
        return None

    # If mock token or Supabase unconfigured, use mock store directly
    if not is_supabase_configured() or token.startswith("mock-"):
        mock_u = get_user_from_mock_token(token)
        if mock_u:
            return mock_u
        if not is_supabase_configured():
            return None

    try:
        supabase = get_supabase_client()
        admin_client = get_supabase_admin_client()
        if not supabase:
            return get_user_from_mock_token(token)

        # Verify access token with Supabase Auth
        user_response = supabase.auth.get_user(token)
        if not user_response or not user_response.user:
            return get_user_from_mock_token(token)

        auth_user = user_response.user
        user_id = str(auth_user.id)
        email = auth_user.email or ""

        # Fetch profile from public.profiles
        profile_data = {}
        if admin_client:
            res = admin_client.table("profiles").select("*").eq("id", user_id).execute()
            if res.data and len(res.data) > 0:
                profile_data = res.data[0]
            else:
                is_owner = (email.strip().lower() == OWNER_EMAIL)
                new_profile = {
                    "id": user_id,
                    "email": email,
                    "full_name": auth_user.user_metadata.get("full_name") or auth_user.user_metadata.get("name") or email.split("@")[0],
                    "role": "admin" if is_owner else None,
                    "status": "approved" if is_owner else "pending_approval"
                }
                admin_client.table("profiles").insert(new_profile).execute()
                profile_data = new_profile

        # Ensure site owner always has admin role and approved status
        if email.strip().lower() == OWNER_EMAIL and (profile_data.get("role") != "admin" or profile_data.get("status") != "approved"):
            if admin_client:
                admin_client.table("profiles").update({"role": "admin", "status": "approved"}).eq("id", user_id).execute()
                profile_data["role"] = "admin"
                profile_data["status"] = "approved"

        return {
            "id": user_id,
            "email": email,
            "full_name": profile_data.get("full_name") or email.split("@")[0],
            "role": profile_data.get("role"),
            "status": profile_data.get("status", "pending_approval"),
            "created_at": profile_data.get("created_at"),
        }
    except Exception as e:
        logger.error(f"Error authenticating user via Supabase: {e}")
        return get_user_from_mock_token(token)

async def require_approved_user(request: Request) -> Dict[str, Any]:
    """
    Enforces that the user is logged in and approved.
    Redirects browser requests or raises HTTPException for API requests.
    """
    user = await get_current_user(request)
    is_html = is_html_request(request)

    if not user:
        if is_html:
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                headers={"Location": "/auth/login?next=" + request.url.path}
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    if user.get("status") == "pending_approval":
        if is_html:
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                headers={"Location": "/auth/pending"}
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is pending administrator approval."
        )

    if user.get("status") == "rejected":
        if is_html:
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                headers={"Location": "/auth/pending?rejected=1"}
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account access has been rejected or revoked."
        )

    return user

async def require_admin_user(request: Request) -> Dict[str, Any]:
    """
    Enforces that the user is logged in, approved, and has the 'admin' role.
    """
    user = await require_approved_user(request)
    if user.get("role") != "admin":
        is_html = is_html_request(request)
        if is_html:
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                headers={"Location": "/dashboard?error=admin_required"}
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required."
        )
    return user
