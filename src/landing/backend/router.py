from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from src.auth.backend.dependencies import get_current_user

router = APIRouter()
templates = Jinja2Templates(directory="src")

@router.get("/", response_class=HTMLResponse)
async def read_landing(request: Request):
    user = await get_current_user(request)
    return templates.TemplateResponse(
        request=request,
        name="landing/frontend/landing.html",
        context={"user": user}
    )
