from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="src")

@router.get("/", response_class=HTMLResponse)
async def read_landing(request: Request):
    return templates.TemplateResponse(request=request, name="landing/frontend/landing.html")
