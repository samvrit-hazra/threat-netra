from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from src.landing.backend.router import router as landing_router
from src.dashboard.backend.router import router as dashboard_router
from src.tools.feed_monitor.backend.router import router as feed_monitor_router
from src.tools.profile_auth.backend.router import router as profile_auth_router
from src.tools.logs_analyze.backend.router import router as logs_analyze_router
from src.auth.backend.router import router as auth_router
from src.auth.backend.admin_router import router as admin_router

app = FastAPI(title="Threat Netra")

# Mount the static files from the shared frontend directory
app.mount("/static", StaticFiles(directory="src/shared/frontend/static"), name="static")

# Include the routers
app.include_router(landing_router)
app.include_router(dashboard_router)
app.include_router(feed_monitor_router)
app.include_router(profile_auth_router)
app.include_router(logs_analyze_router)
app.include_router(auth_router)
app.include_router(admin_router)
