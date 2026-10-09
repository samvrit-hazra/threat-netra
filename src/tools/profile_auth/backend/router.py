from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, List

from src.auth.backend.dependencies import require_approved_user
from src.tools.profile_auth.backend.bing_scanner import BingProfileScanner
from src.tools.profile_auth.backend.twitter_archive import TwitterArchiveScraper
from src.tools.profile_auth.backend.ai_analyzer import analyze_profile_telemetry

router = APIRouter(prefix="/tools/profile_auth", tags=["profile_auth"])
templates = Jinja2Templates(directory="src")

class ProfileScanRequest(BaseModel):
    handle: str
    platform: str

class ScrapingRequest(BaseModel):
    handle: str
    platform: str
    extract_followers: bool = True
    extract_posts: bool = True

class TwitterArchiveRequest(BaseModel):
    handle: str

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

@router.post("/api/scan")
async def scan_profile_bing_rss(
    payload: ProfileScanRequest,
    current_user: dict = Depends(require_approved_user)
):
    """
    Scans a profile using Bing Search RSS feeds.
    Includes Twitter / X Wayback Machine archive endpoints when querying Twitter/X.
    """
    if not payload.handle or not payload.handle.strip():
        raise HTTPException(status_code=400, detail="Target username/handle cannot be empty.")

    scan_result = await BingProfileScanner.scan_profile(
        handle=payload.handle,
        platform=payload.platform
    )
    return JSONResponse(scan_result)

@router.post("/api/twitter-archive")
async def get_twitter_archive(
    payload: TwitterArchiveRequest,
    current_user: dict = Depends(require_approved_user)
):
    """
    Generates and scrapes Twitter status archives via the Wayback Machine:
    https://web.archive.org/web/*/https://twitter.com/USERNAME/status/*
    https://web.archive.org/web/*/https://x.com/USERNAME/status/*
    """
    if not payload.handle or not payload.handle.strip():
        raise HTTPException(status_code=400, detail="Username cannot be empty.")

    archive_data = await TwitterArchiveScraper.scrape_twitter_archive(payload.handle)
    return JSONResponse(archive_data)

@router.post("/api/scrape")
async def execute_gov_scraping(
    payload: ScrapingRequest,
    current_user: dict = Depends(require_approved_user)
):
    """
    Direct Automated Scraping / Deep Forensic Collection & AI Analysis API.
    Utilizes live Bing RSS reconnaissance combined with Wayback Machine archive forensics for Twitter/X,
    followed by AI-driven multi-vector synthetic bot and fake account probability analysis.
    Strictly restricted to Governmental Users and Admins.
    """
    role = current_user.get("role")
    if role not in ("governmental_user", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Access Denied: Direct social media scraping requires verified Governmental User tier."
        )

    scan_result = await BingProfileScanner.scan_profile(
        handle=payload.handle,
        platform=payload.platform
    )

    metadata = scan_result.get("metadata", {})
    twitter_archive_data = None
    
    # If Twitter/X, scrape Wayback Machine archive for historical status entries
    if payload.platform.lower() in ("twitter", "x", "twitter.com", "x.com"):
        twitter_archive_data = await TwitterArchiveScraper.scrape_twitter_archive(payload.handle)

    raw_telemetry = {
        "status": "success",
        "mode": "governmental_automated_scraping",
        "target": payload.handle,
        "platform": payload.platform,
        "search_query": scan_result.get("search_query"),
        "rss_url": scan_result.get("rss_url"),
        "total_results": scan_result.get("total_results", 0),
        "primary_profile_url": scan_result.get("primary_profile_url"),
        "twitter_archive": twitter_archive_data,
        "extracted_data": {
            "bio": metadata.get("bio_snippet") or f"Metadata indexed for {payload.handle}",
            "follower_count": metadata.get("followers", "N/A"),
            "following_count": metadata.get("following", "N/A"),
            "posts_count": metadata.get("posts", "N/A"),
            "presence_status": scan_result.get("presence_status"),
            "bot_risk_score": f"{metadata.get('bot_risk_estimate', 'Low')} (Score: {metadata.get('authenticity_score', 80)}/100)",
            "indexed_citations": scan_result.get("results", []),
            "wayback_archive_status": twitter_archive_data.get("cdx_status") if twitter_archive_data else None,
            "archived_status_count": twitter_archive_data.get("total_snapshots_found", 0) if twitter_archive_data else 0
        }
    }

    # Execute deep AI analysis to determine fake account probability and threat assessment
    ai_analysis = analyze_profile_telemetry(raw_telemetry)

    return JSONResponse({
        "status": "success",
        "target": payload.handle,
        "platform": payload.platform,
        "raw_telemetry": raw_telemetry,
        "ai_analysis": ai_analysis
    })

@router.post("/api/dork")
async def execute_normal_dork(
    payload: DorkSearchRequest,
    current_user: dict = Depends(require_approved_user)
):
    """
    OSINT Search Operator Query Builder for Normal Users.
    """
    target = payload.query_target.strip().lstrip("@")
    generated_dorks = [
        f'site:twitter.com intext:"{target}"',
        f'site:linkedin.com/in/ "{target}"',
        f'site:instagram.com "{target}" -site:instagram.com/p/',
        f'site:github.com "{target}"',
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
