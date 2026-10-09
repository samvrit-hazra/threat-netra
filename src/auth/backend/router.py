from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter(prefix="/auth", tags=["auth"])
templates = Jinja2Templates(directory="src")

@router.get("/login", response_class=HTMLResponse)
async def read_login(request: Request):
    return templates.TemplateResponse(request=request, name="auth/frontend/login.html")

# Placeholder for the future Supabase POST request
@router.post("/login")
async def process_login(request: Request):
    # Form processing and Supabase connection will go here
    pass
