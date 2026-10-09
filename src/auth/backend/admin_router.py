import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Request, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from src.auth.backend.config import is_supabase_configured
from src.auth.backend.client import get_supabase_admin_client
from src.auth.backend.dependencies import require_admin_user
from src.auth.backend.mock_store import MOCK_USERS

logger = logging.getLogger("threatnetra.admin")

router = APIRouter(prefix="/admin", tags=["admin"])
templates = Jinja2Templates(directory="src")

async def get_all_profiles() -> List[Dict[str, Any]]:
    """Fetch all user profiles from Supabase or fallback mock store."""
    if is_supabase_configured():
        admin_client = get_supabase_admin_client()
        if admin_client:
            res = admin_client.table("profiles").select("*").order("created_at", desc=True).execute()
            if res.data is not None:
                try:
                    auth_users = {u.id: u.user_metadata for u in admin_client.auth.admin.list_users()}
                    for p in res.data:
                        meta = auth_users.get(p.get("id"), {})
                        p["requested_role"] = meta.get("requested_role")
                except Exception:
                    pass
                return res.data
    # Fallback to mock store
    return list(MOCK_USERS.values())

async def update_user_status_and_role(user_id: str, status: str, role: Optional[str] = None) -> bool:
    """Updates user approval status and assigned role."""
    if is_supabase_configured():
        admin_client = get_supabase_admin_client()
        if admin_client:
            update_payload: Dict[str, Any] = {"status": status}
            if role is not None:
                update_payload["role"] = role
            res = admin_client.table("profiles").update(update_payload).eq("id", user_id).execute()
            return bool(res.data)
    # Mock store fallback
    if user_id in MOCK_USERS:
        MOCK_USERS[user_id]["status"] = status
        if role is not None:
            MOCK_USERS[user_id]["role"] = role
        return True
    return False

@router.get("/users", response_class=HTMLResponse)
async def admin_users_page(request: Request, current_user: dict = Depends(require_admin_user)):
    """Owner approval dashboard listing all users and pending requests."""
    all_profiles = await get_all_profiles()

    pending_users = [u for u in all_profiles if u.get("status") == "pending_approval"]
    approved_gov = [u for u in all_profiles if u.get("status") == "approved" and u.get("role") == "governmental_user"]
    approved_normal = [u for u in all_profiles if u.get("status") == "approved" and u.get("role") == "normal_user"]
    admins = [u for u in all_profiles if u.get("role") == "admin"]
    rejected_users = [u for u in all_profiles if u.get("status") == "rejected"]

    return templates.TemplateResponse(
        request=request,
        name="auth/frontend/admin_users.html",
        context={
            "current_user": current_user,
            "pending_users": pending_users,
            "approved_gov": approved_gov,
            "approved_normal": approved_normal,
            "admins": admins,
            "rejected_users": rejected_users,
            "is_supabase_live": is_supabase_configured(),
        }
    )

@router.post("/users/{user_id}/approve")
async def approve_user(
    user_id: str,
    role: str = Form(...),
    current_user: dict = Depends(require_admin_user)
):
    """
    Owner action: approve a user and assign either 'governmental_user' or 'normal_user'.
    """
    if role not in ("normal_user", "governmental_user"):
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'governmental_user' or 'normal_user'.")

    success = await update_user_status_and_role(user_id, status="approved", role=role)
    if not success:
        raise HTTPException(status_code=404, detail="User not found or update failed.")

    return RedirectResponse(url="/admin/users?success=approved", status_code=303)

@router.post("/users/{user_id}/role")
async def change_user_role(
    user_id: str,
    role: str = Form(...),
    current_user: dict = Depends(require_admin_user)
):
    """Owner action: switch an approved user's role between normal and governmental."""
    if role not in ("normal_user", "governmental_user"):
        raise HTTPException(status_code=400, detail="Invalid role.")

    success = await update_user_status_and_role(user_id, status="approved", role=role)
    if not success:
        raise HTTPException(status_code=404, detail="User not found or update failed.")

    return RedirectResponse(url="/admin/users?success=role_updated", status_code=303)

@router.post("/users/{user_id}/reject")
async def reject_user(
    user_id: str,
    current_user: dict = Depends(require_admin_user)
):
    """Owner action: reject or revoke user access."""
    success = await update_user_status_and_role(user_id, status="rejected")
    if not success:
        raise HTTPException(status_code=404, detail="User not found or update failed.")

    return RedirectResponse(url="/admin/users?success=rejected", status_code=303)
