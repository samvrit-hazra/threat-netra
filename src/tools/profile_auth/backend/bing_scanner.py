import re
import html
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
import httpx
from src.tools.profile_auth.backend.twitter_archive import TwitterArchiveScraper

PLATFORM_DOMAINS = {
    "instagram": "instagram.com",
    "instagram.com": "instagram.com",
    "twitter": "twitter.com",
    "x": "x.com",
    "twitter.com": "twitter.com",
    "x.com": "x.com",
    "linkedin": "linkedin.com",
    "linkedin.com": "linkedin.com",
    "facebook": "facebook.com",
    "facebook.com": "facebook.com",
    "telegram": "t.me",
    "t.me": "t.me",
    "github": "github.com",
    "github.com": "github.com",
    "youtube": "youtube.com",
    "youtube.com": "youtube.com",
    "reddit": "reddit.com",
    "reddit.com": "reddit.com",
    "tiktok": "tiktok.com",
    "tiktok.com": "tiktok.com",
    "threads": "threads.net",
    "threads.net": "threads.net",
    "medium": "medium.com",
    "medium.com": "medium.com",
    "pinterest": "pinterest.com",
    "pinterest.com": "pinterest.com",
}

STATS_REGEX = re.compile(
    r'(?:(?P<followers>[\d\.,]+[KkMmBb]?)\s+Followers?)?'
    r'(?:[,\s]+(?P<following>[\d\.,]+[KkMmBb]?)\s+Following)?'
    r'(?:[,\s]+(?P<posts>[\d\.,]+[KkMmBb]?)\s+Posts?)?',
    re.IGNORECASE
)

TAG_RE = re.compile(r'<[^>]+>')


def clean_html_text(raw_text: str) -> str:
    """Removes HTML tags and unescapes entities."""
    if not raw_text:
        return ""
    stripped = TAG_RE.sub('', raw_text)
    return html.unescape(stripped).strip()


class BingProfileScanner:
    @staticmethod
    def resolve_domain(platform_input: str) -> str:
        """Resolves a platform name or custom domain to a canonical hostname."""
        cleaned = (platform_input or "").strip().lower()
        cleaned = re.sub(r'^https?://', '', cleaned)
        cleaned = cleaned.rstrip('/')
        
        if cleaned in PLATFORM_DOMAINS:
            return PLATFORM_DOMAINS[cleaned]
        
        if "." in cleaned:
            return cleaned
            
        return f"{cleaned}.com" if cleaned else "instagram.com"

    @staticmethod
    def sanitize_handle(handle_input: str, domain: str) -> str:
        """Extracts and sanitizes the username handle from text or full URLs."""
        trimmed = (handle_input or "").strip()
        
        if "://" in trimmed or "/" in trimmed:
            parsed = urllib.parse.urlparse(trimmed if "://" in trimmed else f"https://{trimmed}")
            path_parts = [p for p in parsed.path.strip("/").split("/") if p]
            if path_parts:
                if path_parts[0] in ("in", "user", "profile", "channel") and len(path_parts) > 1:
                    trimmed = path_parts[1]
                else:
                    trimmed = path_parts[0]
                    
        trimmed = trimmed.lstrip("@").strip("\"' \t\r\n")
        return trimmed

    @classmethod
    def build_search_query(cls, domain: str, username: str) -> str:
        """Constructs the search term, e.g. site:instagram.com "itsfoss" """
        return f'site:{domain} "{username}"'

    @classmethod
    def build_rss_url(cls, search_query: str) -> str:
        """
        Constructs the Bing RSS feed URL.
        Example: https://www.bing.com/search?q=site%3Ainstagram.com+%22itsfoss%22&form=QBLH&sp=-1&lq=0&pq=site%3Ainstagram.com+%22itsfoss%22&format=rss
        """
        encoded_q = urllib.parse.quote_plus(search_query)
        return f"https://www.bing.com/search?q={encoded_q}&form=QBLH&sp=-1&lq=0&pq={encoded_q}&format=rss"

    @classmethod
    def build_web_search_url(cls, search_query: str) -> str:
        """Constructs standard Bing web search URL for browser navigation."""
        encoded_q = urllib.parse.quote_plus(search_query)
        return f"https://www.bing.com/search?q={encoded_q}"

    @classmethod
    async def scan_profile(cls, handle: str, platform: str) -> Dict[str, Any]:
        """
        Executes the Bing RSS feed profile scan, parses entries, and attributes signals.
        Filters out Bing's unrelated fallback / recommendation items.
        Augments Twitter / X scans with Wayback Machine archive forensics.
        """
        domain = cls.resolve_domain(platform)
        clean_user = cls.sanitize_handle(handle, domain)
        
        if not clean_user:
            return {
                "status": "error",
                "message": "Username / handle cannot be empty."
            }

        search_query = cls.build_search_query(domain, clean_user)
        rss_url = cls.build_rss_url(search_query)
        web_search_url = cls.build_web_search_url(search_query)

        # Include Twitter/X Wayback Machine Archive status URLs
        is_twitter = domain in ("twitter.com", "x.com")
        twitter_archive_data = None
        if is_twitter:
            twitter_archive_data = TwitterArchiveScraper.get_archive_urls(clean_user)

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "application/rss+xml,application/xml,text/xml,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
        }

        try:
            async with httpx.AsyncClient(timeout=15.0, headers=headers, follow_redirects=True) as client:
                resp = await client.get(rss_url)
                
            if resp.status_code != 200:
                return {
                    "status": "error",
                    "status_code": resp.status_code,
                    "search_query": search_query,
                    "rss_url": rss_url,
                    "web_search_url": web_search_url,
                    "twitter_archive": twitter_archive_data,
                    "message": f"Bing RSS search returned HTTP {resp.status_code}."
                }

            # Parse XML
            xml_text = resp.text
            root = ET.fromstring(xml_text)
            
            channel = root.find("channel")
            channel_title = channel.findtext("title", "") if channel is not None else ""
            
            raw_items = root.findall(".//item")
            parsed_results: List[Dict[str, Any]] = []
            
            extracted_followers = None
            extracted_following = None
            extracted_posts = None
            primary_profile_link = None
            sample_bio = ""

            clean_user_lower = clean_user.lower()
            domain_lower = domain.lower()
            
            for item in raw_items:
                link = (item.findtext("link", "") or "").strip()
                if not link:
                    continue

                parsed_link = urllib.parse.urlparse(link)
                item_netloc = parsed_link.netloc.lower()

                # CRITICAL FILTER: Ensure the result belongs to the requested platform domain.
                is_target_domain = (item_netloc == domain_lower or item_netloc.endswith("." + domain_lower))
                # For Twitter / X cross-domain matching (twitter.com vs x.com)
                if is_twitter and (item_netloc in ("twitter.com", "x.com") or item_netloc.endswith(".twitter.com") or item_netloc.endswith(".x.com")):
                    is_target_domain = True

                if not is_target_domain:
                    continue

                title = clean_html_text(item.findtext("title", ""))
                description = clean_html_text(item.findtext("description", ""))
                pub_date = (item.findtext("pubDate", "") or "").strip()

                # Determine if link represents direct profile
                path_slugs = [s for s in parsed_link.path.strip("/").split("/") if s]
                is_direct = False
                
                if path_slugs:
                    if path_slugs[0].lower() == clean_user_lower or (len(path_slugs) > 1 and path_slugs[1].lower() == clean_user_lower):
                        is_direct = True
                        if not primary_profile_link:
                            primary_profile_link = link
                elif clean_user_lower in link.lower() and not primary_profile_link:
                    primary_profile_link = link

                # Try parsing follower / post stats from snippet
                if not extracted_followers:
                    stats_match = STATS_REGEX.search(description)
                    if stats_match:
                        extracted_followers = stats_match.group("followers")
                        extracted_following = stats_match.group("following")
                        extracted_posts = stats_match.group("posts")

                if not sample_bio and len(description) > 15:
                    sample_bio = description

                parsed_results.append({
                    "title": title,
                    "link": link,
                    "description": description,
                    "pub_date": pub_date,
                    "is_profile_match": is_direct
                })

            total_results = len(parsed_results)
            if total_results > 0:
                presence_status = "INDEXED_ACTIVE"
                authenticity_score = 85 if primary_profile_link else 65
                bot_risk = "Low" if (primary_profile_link and extracted_followers) else "Medium"
            else:
                presence_status = "NOT_FOUND_OR_UNINDEXED"
                authenticity_score = 15
                bot_risk = "Elevated (Unindexed / Private)"

            return {
                "status": "success",
                "handle": clean_user,
                "platform": platform,
                "domain": domain,
                "search_query": search_query,
                "rss_url": rss_url,
                "web_search_url": web_search_url,
                "channel_title": channel_title,
                "total_results": total_results,
                "presence_status": presence_status,
                "primary_profile_url": primary_profile_link or (f"https://{domain}/{clean_user}" if domain != "t.me" else f"https://t.me/{clean_user}"),
                "twitter_archive": twitter_archive_data,
                "metadata": {
                    "followers": extracted_followers or "N/A",
                    "following": extracted_following or "N/A",
                    "posts": extracted_posts or "N/A",
                    "bio_snippet": sample_bio or "No description snippet available on target platform index.",
                    "bot_risk_estimate": bot_risk,
                    "authenticity_score": authenticity_score
                },
                "results": parsed_results
            }

        except ET.ParseError as pe:
            return {
                "status": "error",
                "search_query": search_query,
                "rss_url": rss_url,
                "web_search_url": web_search_url,
                "twitter_archive": twitter_archive_data,
                "message": f"XML parse error from Bing RSS: {str(pe)}"
            }
        except Exception as e:
            return {
                "status": "error",
                "search_query": search_query,
                "rss_url": rss_url,
                "web_search_url": web_search_url,
                "twitter_archive": twitter_archive_data,
                "message": f"Error querying Bing RSS: {str(e)}"
            }
