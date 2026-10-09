import logging
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
from dotenv import load_dotenv

from app.models import AnalyzeRequest
from app.services.fetcher import fetch_telegram, fetch_bing
from app.services.analyzer import analyze_feeds

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

load_dotenv()  # Loads .env file if present

app = FastAPI(title="Threat Intelligence API", version="1.0.0")

# Add CORS Middleware for production readiness
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to frontend domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Static directory to serve the frontend
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def serve_frontend():
    """Serves the minimal testing dashboard."""
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

@app.post("/api/v1/analyze")
async def api_analyze_threats(req: AnalyzeRequest):
    try:
        logger.info(f"Received analysis request: source={req.source_type}, query='{req.query}', provider={req.provider}")
        
        # 1. Fetch raw feeds based on source type
        feed_url = ""
        if req.source_type == "telegram":
            feeds, feed_url = await fetch_telegram(req.query, req.limit)
        elif req.source_type == "bing":
            feeds, feed_url = await fetch_bing(req.query, req.limit)
        else:
            logger.warning(f"Invalid source type requested: {req.source_type}")
            raise HTTPException(status_code=400, detail="Invalid source_type. Must be 'telegram' or 'bing'.")
            
        if not feeds:
            logger.info("No feeds found for query.")
            return {
                "message": "No feeds found or channel is empty.", 
                "results": [], 
                "raw_feeds": [],
                "metadata": {"feed_url": feed_url}
            }
            
        # 2. Run AI threat analysis using the requested provider
        analysis = analyze_feeds(feeds, req.scenarios, provider=req.provider)
        
        logger.info(f"Successfully analyzed {len(feeds)} items via {req.provider}.")
        return {
            "metadata": {
                "source": req.source_type,
                "query": req.query,
                "provider_used": req.provider,
                "feed_count": len(feeds),
                "feed_url": feed_url
            },
            "raw_feeds": feeds,
            "results": analysis
        }
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

from pydantic import BaseModel
import base64
import httpx

class ScanRequest(BaseModel):
    url: str

@app.post("/api/v1/scan-url")
async def scan_url(req: ScanRequest):
    api_key = os.environ.get("URL_API")
    if not api_key:
        raise HTTPException(status_code=500, detail="VirusTotal API key (URL_API) not configured.")
        
    url_id = base64.urlsafe_b64encode(req.url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(vt_url, headers={"x-apikey": api_key})
        
        if resp.status_code == 404:
            return {"status": "unscanned", "message": "URL not found in VirusTotal database."}
        elif resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=f"VirusTotal API Error: {resp.text}")
            
        data = resp.json().get("data", {})
        stats = data.get("attributes", {}).get("last_analysis_stats", {})
        
        return {
            "status": "scanned",
            "stats": stats,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0)
        }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
