import os
import base64
import logging
from typing import Dict, Any, Optional
from pathlib import Path

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import httpx

from src.auth.backend.dependencies import require_approved_user
from src.tools.feed_monitor.backend.models import AnalyzeRequest, ScanRequest
from src.tools.feed_monitor.backend.fetcher import fetch_telegram, fetch_bing
from src.tools.feed_monitor.backend.analyzer import analyze_feeds

logger = logging.getLogger("feed_monitor.router")

router = APIRouter(tags=["feed_monitor"])
templates = Jinja2Templates(directory="src")

def _get_vt_api_key() -> Optional[str]:
    # Check OS env first
    for key_name in ["URL_API", "VIRUSTOTAL_API_KEY"]:
        if os.environ.get(key_name):
            return os.environ.get(key_name)

    # Check .env file
    env_path = Path(__file__).resolve().parents[4] / ".env"
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    if k in ["URL_API", "VIRUSTOTAL_API_KEY"]:
                        val = v.strip().strip("'\"")
                        if val:
                            return val
    return None

# -------------------------------------------------------------------------
# UI ROUTE
# -------------------------------------------------------------------------
@router.get("/tools/feed_monitor", response_class=HTMLResponse)
@router.get("/tools/feed_monitor/", response_class=HTMLResponse)
async def read_feed_monitor(
    request: Request,
    current_user: dict = Depends(require_approved_user)
):
    """Renders the Defense-grade Autonomous Feed Monitoring Dashboard."""
    vt_configured = bool(_get_vt_api_key())
    return templates.TemplateResponse(
        request=request,
        name="tools/feed_monitor/frontend/index.html",
        context={
            "user": current_user,
            "vt_configured": vt_configured
        }
    )

# -------------------------------------------------------------------------
# CTI ANALYSIS ENDPOINT
# -------------------------------------------------------------------------
@router.post("/tools/feed_monitor/api/analyze")
@router.post("/threat/api/v1/analyze")
@router.post("/api/v1/analyze")
async def api_analyze_threats(
    req: AnalyzeRequest,
    current_user: dict = Depends(require_approved_user)
):
    try:
        source_type = req.source_type.lower().strip()
        query = req.query.strip()
        limit = min(max(req.limit, 1), 20)

        logger.info(f"Feed analysis requested: source={source_type}, query='{query}', provider={req.provider}")

        # 1. Fetch raw feeds based on source
        feed_url = ""
        feeds = []
        if source_type == "telegram":
            feeds, feed_url = await fetch_telegram(query, limit)
        elif source_type == "bing":
            feeds, feed_url = await fetch_bing(query, limit)
        else:
            raise HTTPException(status_code=400, detail="Invalid source_type. Must be 'telegram' or 'bing'.")

        if not feeds:
            return {
                "message": "No feeds found or channel is empty/unreachable.",
                "results": [],
                "raw_feeds": [],
                "metadata": {
                    "source": source_type,
                    "query": query,
                    "provider_used": req.provider,
                    "feed_count": 0,
                    "feed_url": feed_url
                }
            }

        # 2. Run AI threat analysis with scenario matching
        analysis = analyze_feeds(feeds, req.scenarios, provider=req.provider)

        return {
            "metadata": {
                "source": source_type,
                "query": query,
                "provider_used": req.provider,
                "feed_count": len(feeds),
                "feed_url": feed_url
            },
            "raw_feeds": feeds,
            "results": analysis
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during feed analysis: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------------------------------------------------------
# VIRUSTOTAL URL SCANNER ENDPOINT
# -------------------------------------------------------------------------
@router.post("/tools/feed_monitor/api/scan-url")
@router.post("/threat/api/v1/scan-url")
@router.post("/api/v1/scan-url")
async def scan_url(
    req: ScanRequest,
    current_user: dict = Depends(require_approved_user)
):
    api_key = _get_vt_api_key()
    if not api_key:
        return {
            "status": "unconfigured",
            "message": "VirusTotal API key not configured (set URL_API in .env).",
            "url": req.url,
            "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
        }

    try:
        url_id = base64.urlsafe_b64encode(req.url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(vt_url, headers={"x-apikey": api_key})

            if resp.status_code == 404:
                return {
                    "status": "unscanned",
                    "url": req.url,
                    "message": "URL not found in VirusTotal database. Not yet submitted for scanning.",
                    "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
                }
            elif resp.status_code != 200:
                logger.warning(f"VirusTotal API response status {resp.status_code}: {resp.text}")
                return {
                    "status": "error",
                    "message": f"VirusTotal API error ({resp.status_code}): {resp.text[:120]}",
                    "url": req.url
                }

            data = resp.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})

            return {
                "status": "scanned",
                "url": req.url,
                "stats": stats,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }
    except Exception as e:
        logger.error(f"Error calling VirusTotal: {e}", exc_info=True)
        return {
            "status": "error",
            "message": f"Scanning service exception: {str(e)}",
            "url": req.url
        }
