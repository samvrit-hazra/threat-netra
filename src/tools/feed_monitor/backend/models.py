from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class AnalyzeRequest(BaseModel):
    source_type: str  # "telegram" or "bing"
    query: str        # channel username or search term
    scenarios: List[str] = []
    limit: int = 5
    provider: str = "auto" # "auto", "groq", or "gemma"

class ScanRequest(BaseModel):
    url: str

class FeedItem(BaseModel):
    title: str
    link: str
    description: str
    pub_date: str
    extracted_urls: List[str] = []

class AnalysisResult(BaseModel):
    item_title: str
    reasoning: Optional[str] = None
    is_threat: bool = False
    is_scenario_match: bool = False
    scenario_matched: Optional[str] = None
    matched_scenario_name: Optional[str] = None
    summary: str
    extracted_urls: List[str] = []
    is_geolocated: bool = False
    location_name: Optional[str] = None
    coordinates: Optional[List[float]] = None  # [lat, lon]
    threat_category: Optional[str] = None       # "war_conflict", "terrorism", "state_leak", "critical_infra", "cyber_ops"
