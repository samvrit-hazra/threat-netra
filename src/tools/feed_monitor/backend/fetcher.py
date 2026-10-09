import os
import re
import html
import random
import logging
from urllib.parse import quote_plus
from typing import List, Tuple, Dict, Any
from pathlib import Path
import httpx
import feedparser

logger = logging.getLogger("feed_monitor.fetcher")

URL_PATTERN = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
TAG_RE = re.compile(r'<[^>]+>')

def clean_html(raw_html: str) -> str:
    """Removes HTML tags and decodes entities."""
    if not raw_html:
        return ""
    text = TAG_RE.sub(" ", raw_html)
    text = html.unescape(text)
    return re.sub(r'\s+', ' ', text).strip()

def extract_urls(text: str) -> List[str]:
    """Extracts valid URLs from text."""
    if not text:
        return []
    matches = URL_PATTERN.findall(text)
    cleaned_urls = []
    for u in matches:
        u = u.rstrip('.,;!?:)]}"\'')
        if u.startswith('www.'):
            u = f'https://{u}'
        if u and u not in cleaned_urls:
            cleaned_urls.append(u)
    return cleaned_urls

def get_telegram_bridges() -> List[str]:
    """Reads available RSS-Bridge instances prioritized by responsiveness."""
    bridge_file = Path(__file__).resolve().parent / "bridges.txt"
    bridges = []
    try:
        if bridge_file.exists():
            with open(bridge_file, "r", encoding="utf-8") as f:
                bridges = [line.strip().rstrip("/") for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        logger.warning(f"Error reading bridges.txt: {e}")

    if not bridges:
        bridges = [
            "https://rss-bridge.lewd.tech",
            "https://rss.bloat.cat",
            "https://rss-bridge.org/bridge01",
            "https://bridge.suumitsu.eu"
        ]
    return bridges

async def _fetch_feed_content(url: str, timeout: float = 5.0) -> str:
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 ThreatNetra/1.0",
        "Accept": "application/atom+xml,application/xml,text/xml,*/*"
    }
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        return resp.text

def _parse_entries(feed_xml: str, limit: int) -> List[Dict[str, Any]]:
    parsed = feedparser.parse(feed_xml)
    items: List[Dict[str, Any]] = []

    for entry in parsed.entries[:limit]:
        title = getattr(entry, "title", "Untitled Telemetry Record")
        link = getattr(entry, "link", "")
        summary_raw = getattr(entry, "summary", getattr(entry, "description", ""))
        cleaned_desc = clean_html(summary_raw)
        pub_date = getattr(entry, "published", getattr(entry, "updated", "Recent"))
        
        # Extract URLs from title and description
        found_urls = extract_urls(f"{title} {summary_raw} {link}")

        items.append({
            "title": title.strip(),
            "link": link.strip(),
            "description": cleaned_desc,
            "pub_date": pub_date,
            "extracted_urls": found_urls
        })
    return items

async def fetch_telegram(username: str, limit: int = 5) -> Tuple[List[Dict[str, Any]], str]:
    """Fetches Telegram channel posts via RSS-Bridge with fast node failover (max 3 attempts)."""
    # Normalize username
    clean_user = username.strip()
    clean_user = re.sub(r'^(https?://)?(t\.me/|telegram\.me/|@)', '', clean_user).strip().strip('/')
    
    bridges = get_telegram_bridges()
    # Prioritize known fast bridges
    fast_priority = ["https://rss-bridge.lewd.tech", "https://rss.bloat.cat", "https://rss-bridge.org/bridge01"]
    ordered_bridges = [b for b in fast_priority if b in bridges] + [b for b in bridges if b not in fast_priority]
    
    last_error = None
    target_feed_url = ""
    
    # Try up to 3 candidate bridges with 4.5s timeout each
    for bridge in ordered_bridges[:3]:
        target_feed_url = f"{bridge}/?action=display&bridge=TelegramBridge&username={clean_user}&format=Atom"
        try:
            logger.info(f"Attempting Telegram ingestion for @{clean_user} via {bridge}")
            xml_text = await _fetch_feed_content(target_feed_url, timeout=4.5)
            items = _parse_entries(xml_text, limit)
            if items:
                logger.info(f"Successfully retrieved {len(items)} items from {bridge}")
                return items, target_feed_url
        except Exception as e:
            last_error = e
            logger.warning(f"Bridge {bridge} failed for @{clean_user}: {e}. Trying next bridge...")
            continue

    if last_error:
        logger.error(f"Telegram bridges failed for @{clean_user}. Last error: {last_error}")
    
    return [], target_feed_url

async def fetch_bing(query: str, limit: int = 5) -> Tuple[List[Dict[str, Any]], str]:
    """Fetches real-time OSINT news via Bing News RSS."""
    clean_q = query.strip() or "cyber threat intelligence"
    encoded_query = quote_plus(clean_q)
    feed_url = f"https://www.bing.com/news/search?q={encoded_query}&qft=sortbydate%3d%221%22&form=YFNR&format=rss"
    
    try:
        logger.info(f"Querying Bing News RSS: {clean_q}")
        xml_text = await _fetch_feed_content(feed_url, timeout=10.0)
        items = _parse_entries(xml_text, limit)
        return items, feed_url
    except Exception as e:
        logger.error(f"Error fetching Bing News RSS: {e}", exc_info=True)
        return [], feed_url
