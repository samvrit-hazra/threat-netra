from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from src.auth.backend.dependencies import require_approved_user

router = APIRouter()
templates = Jinja2Templates(directory="src")

@router.get("/dashboard", response_class=HTMLResponse)
async def read_dashboard(
    request: Request,
    current_user: dict = Depends(require_approved_user)
):
    role = current_user.get("role", "normal_user")
    is_governmental = (role in ("governmental_user", "admin"))

    # Tool definitions with role-tailored descriptions
    tools = [
        {\
            "id": "feed_monitor",
            "title": "Web / Social Media Feed Monitoring",
            "url": "/tools/feed_monitor",
            "badge": "Active",
            "badge_class": "badge-status-live",
            "description": "Continuous real-time threat intelligence monitoring and scenario-based alerting across digital networks and GIS maps."
        },
        {\
            "id": "profile_auth",
            "title": "Online Account Authenticity Checker",
            "url": "/tools/profile_auth",
            "badge": "Governmental Tier (Scraping)" if is_governmental else "Standard Tier (OSINT Dorks)",
            "badge_class": "badge-gov" if is_governmental else "badge-normal",
            "description": (
                "Direct automated web & social media scraping for deep forensic analysis: extracts profile bio, follower/following graphs, and timeline posts to detect state-sponsored bots and fake profiles."
                if is_governmental else
                "OSINT web search operator suite: runs advanced Google dorks and public index queries to discover digital footprints and verify account legitimacy within legal compliance boundaries."
            )
        },
        {\
            "id": "logs_analyze",
            "title": "AI Log & Network Forensic Analyzer",
            "url": "/tools/logs_analyze",
            "badge": "Active",
            "badge_class": "badge-status-live",
            "description": "Autonomous multi-source ingestion and forensic analysis of Syslog, Web, Firewall, and Windows Event streams with AI incident reconstruction."
        },
        {\
            "id": "legal_contract",
            "title": "Legal Contract & Document Intelligence",
            "url": "/tools/contract_intel",
            "badge": "Active",
            "badge_class": "badge-status-live",
            "description": "Autonomous contract forensic engine: discovers hidden loophole clauses, auto-renewal traps, early termination liabilities, and financial commitments with verbatim hallucination defense."
        }
    ]

    return templates.TemplateResponse(
        request=request,
        name="dashboard/frontend/dashboard.html",
        context={
            "user": current_user,
            "role": role,
            "is_governmental": is_governmental,
            "tools": tools,
        }
    )
