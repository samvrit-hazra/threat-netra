from pydantic import BaseModel
from typing import List, Optional

class AnalyzeRequest(BaseModel):
    source_type: str  # "telegram" or "bing"
    query: str        # channel username or search term
    scenarios: List[str] = []
    limit: int = 5
    provider: str = "google" # "google" or "groq"

class FeedItem(BaseModel):
    title: str
    link: str
    description: str
    pub_date: str

class AnalysisResult(BaseModel):
    item_title: str
    is_threat: bool
    scenario_matched: Optional[str]
    summary: str
