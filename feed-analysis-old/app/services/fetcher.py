import httpx
import feedparser
import os
import random
import logging
from urllib.parse import quote_plus
from typing import List, Tuple

logger = logging.getLogger(__name__)

def get_telegram_bridges() -> List[str]:
    # Reads the active bridges from the bridge.txt file we generated earlier
    bridge_file = os.path.join(os.path.dirname(__file__), '../../bridge.txt')
    try:
        with open(bridge_file, 'r') as f:
            return [line.strip().rstrip('/') for line in f if line.strip()]
    except FileNotFoundError:
        logger.warning("bridge.txt not found, using fallback bridge.")
        return ["https://rss-bridge.lewd.tech"]  # Fallback

async def fetch_telegram(username: str, limit: int = 5) -> Tuple[List[dict], str]:
    bridges = get_telegram_bridges()
    base_url = random.choice(bridges)
    url = f"{base_url}/?action=display&bridge=TelegramBridge&username={username}&format=Atom"
    logger.info(f"Fetching Telegram feed for {username} via {base_url}")
    results = await _fetch_rss(url, limit)
    return results, url

async def fetch_bing(query: str, limit: int = 5) -> Tuple[List[dict], str]:
    encoded_query = quote_plus(query)
    url = f"https://www.bing.com/news/search?q={encoded_query}&qft=sortbydate%3d%221%22&form=YFNR&format=rss"
    logger.info(f"Fetching Bing news for query: {query}")
    results = await _fetch_rss(url, limit)
    return results, url

async def _fetch_rss(url: str, limit: int) -> List[dict]:
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CTI Platform Bot"}
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers, timeout=15.0)
            resp.raise_for_status()
            
            feed = feedparser.parse(resp.text)
            results = []
            
            import re
            url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
            
            for entry in feed.entries[:limit]:
                text_content = getattr(entry, "summary", getattr(entry, "description", ""))
                urls = list(set(url_pattern.findall(text_content)))
                
                results.append({
                    "title": getattr(entry, "title", "No Title"),
                    "link": getattr(entry, "link", ""),
                    "description": text_content,
                    "pub_date": getattr(entry, "published", ""),
                    "extracted_urls": urls
                })
            logger.info(f"Successfully parsed {len(results)} items from RSS.")
            return results
    except Exception as e:
        logger.error(f"Error fetching RSS from {url}: {str(e)}", exc_info=True)
        raise
