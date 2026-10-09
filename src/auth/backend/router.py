import logging
from typing import Optional
from fastapi import APIRouter, Request, Response, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from src.auth.backend.config import (
    SUPABASE_URL,
    SUPABASE_KEY,
    OWNER_EMAIL,
    DEMO_EMAIL,
    DEMO_PASSWORD,
    is_supabase_configured,
)
from src.auth.backend.client import get_supabase_client, get_supabase_admin_client
from src.auth.backend.dependencies import get_current_user
from src.auth.backend.mock_store import (
    create_mock_user,
    find_mock_user_by_email,
    create_mock_session,
    MOCK_USERS,
)

logger = logging.getLogger("threatnetra.auth")

router = APIRouter(prefix="/auth", tags=["auth"])
templates = Jinja2Templates(directory="src")

class SessionPayload(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None

@router.get("/config")
async def get_auth_config():
    """Returns public configuration needed by frontend Supabase JS."""
    return {
        "configured": is_supabase_configured(),
        "supabase_url": SUPABASE_URL if is_supabase_configured() else "",
        "supabase_key": SUPABASE_KEY if is_supabase_configured() else "",
        "demo_email": DEMO_EMAIL,
        "demo_password": DEMO_PASSWORD,
    }

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = await get_current_user(request)
    if user:
        if user.get("status") == "approved":
            return RedirectResponse(url="/dashboard", status_code=303)
        return RedirectResponse(url="/auth/pending", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="auth/frontend/login.html",
        context={
            "is_configured": is_supabase_configured(),
            "demo_email": DEMO_EMAIL,
            "demo_password": DEMO_PASSWORD,
        }
    )

@router.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    user = await get_current_user(request)
    if user:
        if user.get("status") == "approved":
            return RedirectResponse(url="/dashboard", status_code=303)
        return RedirectResponse(url="/auth/pending", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="auth/frontend/signup.html",
        context={
            "is_configured": is_supabase_configured(),
        }
    )

@router.get("/pending", response_class=HTMLResponse)
async def pending_page(request: Request):
    user = await get_current_user(request)
    is_rejected = request.query_params.get("rejected") == "1" or (user and user.get("status") == "rejected")
    return templates.TemplateResponse(
        request=request,
        name="auth/frontend/pending.html",
        context={
            "user": user,
            "is_rejected": is_rejected,
            "owner_email": OWNER_EMAIL,
        }
    )

@router.get("/callback", response_class=HTMLResponse)
async def callback_page(request: Request):
    """Client-side OAuth callback page that captures Google OAuth tokens."""
    return templates.TemplateResponse(
        request=request,
        name="auth/frontend/callback.html",
        context={}
    )

@router.post("/session")
async def set_session(payload: SessionPayload, response: Response, request: Request):
    """
    Receives access_token from frontend (Supabase Auth / Google OAuth)
    and sets an HTTP-only cookie.
    """
    token = payload.access_token
    # Set cookie for 14 days
    res = JSONResponse({"status": "ok"})
    res.set_cookie(
        key="sb_access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,  # Set to True in HTTPS production
        max_age=14 * 24 * 3600,
        path="/"
    )
    return res

@router.post("/login")
async def process_login(
    email: str = Form(...),
    password: str = Form(...)
):
    email = email.strip().lower()

    if is_supabase_configured():
        supabase = get_supabase_client()
        try:
            auth_res = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
            token = auth_res.session.access_token

            # Check profile status
            admin_client = get_supabase_admin_client()
            profile_res = admin_client.table("profiles").select("*").eq("id", str(auth_res.user.id)).execute()
            status = "pending_approval"
            role = None
            if profile_res.data:
                status = profile_res.data[0].get("status", "pending_approval")
                role = profile_res.data[0].get("role")

            redirect_target = "/dashboard" if status == "approved" else "/auth/pending"
            response = RedirectResponse(url=redirect_target, status_code=303)
            response.set_cookie(
                key="sb_access_token",
                value=token,
                httponly=True,
                samesite="lax",
                secure=False,
                max_age=14 * 24 * 3600,
                path="/"
            )
            return response
        except Exception as e:
            logger.error(f"Supabase login failed: {e}")
            return RedirectResponse(url=f"/auth/login?error={str(e)}", status_code=303)

    # Mock login fallback
    mock_user = find_mock_user_by_email(email)
    if not mock_user or mock_user.get("password") != password:
        return RedirectResponse(url="/auth/login?error=Invalid+email+or+password", status_code=303)

    token = create_mock_session(mock_user["id"])
    redirect_target = "/dashboard" if mock_user.get("status") == "approved" else "/auth/pending"
    response = RedirectResponse(url=redirect_target, status_code=303)
    response.set_cookie(
        key="sb_access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=14 * 24 * 3600,
        path="/"
    )
    return response

@router.post("/signup")
async def process_signup(
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...)
):
    email = email.strip().lower()

    if is_supabase_configured():
        supabase = get_supabase_client()
        try:
            auth_res = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "full_name": full_name
                    }
                }
            })
            token = auth_res.session.access_token if auth_res.session else None
            # Redirect to pending approval notice
            response = RedirectResponse(url="/auth/pending?new=1", status_code=303)
            if token:
                response.set_cookie(
                    key="sb_access_token",
                    value=token,
                    httponly=True,
                    samesite="lax",
                    secure=False,
                    max_age=14 * 24 * 3600,
                    path="/"
                )
            return response
        except Exception as e:
            logger.error(f"Supabase sign up failed: {e}")
            return RedirectResponse(url=f"/auth/signup?error={str(e)}", status_code=303)

    # Mock signup fallback
    if find_mock_user_by_email(email):
        return RedirectResponse(url="/auth/signup?error=Email+already+registered", status_code=303)

    user = create_mock_user(email=email, password=password, full_name=full_name)
    token = create_mock_session(user["id"])
    redirect_target = "/dashboard" if user.get("status") == "approved" else "/auth/pending?new=1"
    response = RedirectResponse(url=redirect_target, status_code=303)
    response.set_cookie(
        key="sb_access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=14 * 24 * 3600,
        path="/"
    )
    return response

@router.get("/demo-login")
@router.post("/demo-login")
async def demo_login():
    """Instant login for demonstration and testing with full governmental access."""
    if is_supabase_configured():
        supabase = get_supabase_client()
        admin_client = get_supabase_admin_client()
        try:
            # Attempt login with demo credentials
            auth_res = supabase.auth.sign_in_with_password({
                "email": DEMO_EMAIL,
                "password": DEMO_PASSWORD
            })
            token = auth_res.session.access_token
            # Ensure demo account has governmental_user role and approved status
            if admin_client:
                admin_client.table("profiles").upsert({
                    "id": str(auth_res.user.id),
                    "email": DEMO_EMAIL,
                    "role": "governmental_user",
                    "status": "approved"
                }).execute()

            response = RedirectResponse(url="/dashboard", status_code=303)
            response.set_cookie(
                key="sb_access_token",
                value=token,
                httponly=True,
                samesite="lax",
                secure=False,
                max_age=14 * 24 * 3600,
                path="/"
            )
            return response
        except Exception as e:
            logger.warning(f"Supabase demo login error (falling back to mock session): {e}")

    # Fallback mock demo login
    token = "mock-jwt-demo"
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="sb_access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=14 * 24 * 3600,
        path="/"
    )
    return response

@router.get("/me")
async def get_me(request: Request):
    """API endpoint to get current user info and approval status."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse({"authenticated": False}, status_code=401)
    return JSONResponse({
        "authenticated": True,
        "user": user
    })

@router.get("/logout")
@router.post("/logout")
async def logout(response: Response):
    """Log out user and clear authentication cookies."""
    redirect = RedirectResponse(url="/auth/login", status_code=303)
    redirect.delete_cookie(key="sb_access_token", path="/")
    return redirect
