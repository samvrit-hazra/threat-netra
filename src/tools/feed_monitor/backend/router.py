from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from src.auth.backend.dependencies import require_approved_user

router = APIRouter()
templates = Jinja2Templates(directory="src")

@router.get("/tools/feed_monitor", response_class=HTMLResponse)
async def read_feed_monitor(
    request: Request,
    current_user: dict = Depends(require_approved_user)
):
    return templates.TemplateResponse(
        request=request,
        name="tools/feed_monitor/frontend/index.html",
        context={"user": current_user}
    )
