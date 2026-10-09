from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="src")

@router.get("/tools/feed_monitor", response_class=HTMLResponse)
async def read_feed_monitor(request: Request):
    return templates.TemplateResponse(request=request, name="tools/feed_monitor/frontend/index.html")
