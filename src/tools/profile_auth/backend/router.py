from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional

from src.auth.backend.dependencies import require_approved_user

router = APIRouter(prefix="/tools/profile_auth", tags=["profile_auth"])
templates = Jinja2Templates(directory="src")

class ScrapingRequest(BaseModel):
    handle: str
    platform: str
    extract_followers: bool = True
    extract_posts: bool = True

class DorkSearchRequest(BaseModel):
    query_target: str
    platforms: Optional[list] = None

@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def read_profile_auth(
    request: Request,
    current_user: dict = Depends(require_approved_user)
):
    role = current_user.get("role", "normal_user")
    is_governmental = (role in ("governmental_user", "admin"))

    return templates.TemplateResponse(
        request=request,
        name="tools/profile_auth/frontend/index.html",
        context={
            "user": current_user,
            "role": role,
            "is_governmental": is_governmental,
        }
    )

@router.post("/api/scrape")
async def execute_gov_scraping(
    payload: ScrapingRequest,
    current_user: dict = Depends(require_approved_user)
):
    """
    Direct Automated Scraping API.
    Strictly restricted to Governmental Users and Admins.
    """
    role = current_user.get("role")
    if role not in ("governmental_user", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Access Denied: Direct social media scraping requires verified Governmental User tier."
        )

    # Simulated forensic scraping result
    return JSONResponse({
        "status": "success",
        "mode": "governmental_automated_scraping",
        "target": payload.handle,
        "platform": payload.platform,
        "extracted_data": {
            "bio": f"Official metadata extracted via direct crawler for {payload.handle}",
            "follower_count": 1420,
            "following_count": 89,
            "account_created": "2023-04-12",
            "bot_risk_score": "Low (14%)",
            "suspicious_patterns": []
        }
    })

@router.post("/api/dork")
async def execute_normal_dork(
    payload: DorkSearchRequest,
    current_user: dict = Depends(require_approved_user)
):
    """
    OSINT Search Operator Query Builder for Normal Users.
    Compliant with legal search regulations.
    """
    target = payload.query_target
    generated_dorks = [
        f'site:twitter.com intext:"{target}"',
        f'site:linkedin.com/in/ "{target}"',
        f'site:instagram.com "{target}" -site:instagram.com/p/',
        f'"{target}" (inurl:profile | inurl:user | inurl:author)',
        f'"{target}" filetype:pdf OR filetype:docx'
    ]

    return JSONResponse({
        "status": "success",
        "mode": "normal_osint_dorking",
        "target": target,
        "generated_operators": generated_dorks,
        "legal_compliance_notice": "Standard tier: Automated direct account scraping disabled. Manual OSINT search operators generated."
    })
