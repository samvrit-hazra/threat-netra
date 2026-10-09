import re
import asyncio
import urllib.parse
from typing import Dict, Any, List, Optional
import httpx

class TwitterArchiveScraper:
    @staticmethod
    def sanitize_username(handle: str) -> str:
        """Strips URL prefixes, @ symbols, and trailing slashes."""
        u = (handle or "").strip()
        if "://" in u or "/" in u:
            try:
                parsed = urllib.parse.urlparse(u if "://" in u else f"https://{u}")
                parts = [p for p in parsed.path.strip("/").split("/") if p]
                if parts:
                    u = parts[0]
            except Exception:
                pass
        return u.lstrip("@").strip("\"' \t\r\n")

    @classmethod
    def get_archive_urls(cls, username: str) -> Dict[str, str]:
        """
        Builds the exact Wayback Machine wildcard status archive URLs:
        https://web.archive.org/web/*/https://twitter.com/USERNAME/status/*
        https://web.archive.org/web/*/https://x.com/USERNAME/status/*
        """
        clean_user = cls.sanitize_username(username)
        return {
            "twitter_status_archive": f"https://web.archive.org/web/*/https://twitter.com/{clean_user}/status/*",
            "x_status_archive": f"https://web.archive.org/web/*/https://x.com/{clean_user}/status/*",
            "twitter_profile_archive": f"https://web.archive.org/web/*/https://twitter.com/{clean_user}",
            "x_profile_archive": f"https://web.archive.org/web/*/https://x.com/{clean_user}"
        }

    @classmethod
    async def _fetch_cdx_pattern(cls, client: httpx.AsyncClient, pattern: str, limit: int) -> List[Dict[str, Any]]:
        """Queries CDX server for a specific wildcard pattern."""
        # Note: Do not quote slashes or asterisks for the url parameter in Wayback CDX!
        url = f"https://web.archive.org/cdx/search/cdx?url={pattern}&output=json&limit={limit}&fl=timestamp,original,statuscode,mimetype"
        items = []
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) > 1:
                    # First row is column headers: ['timestamp', 'original', 'statuscode', 'mimetype']
                    for row in data[1:]:
                        if len(row) >= 3:
                            ts = str(row[0])
                            orig = str(row[1])
                            status_code = str(row[2])
                            
                            # Format timestamp nicely: YYYY-MM-DD HH:MM:SS
                            formatted_date = ts
                            if len(ts) >= 14:
                                formatted_date = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}:{ts[12:14]} UTC"
                            elif len(ts) >= 8:
                                formatted_date = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"

                            # Extract numeric tweet ID if present
                            id_match = re.search(r'/status(?:es)?/(\d+)', orig, re.IGNORECASE)
                            tweet_id = id_match.group(1) if id_match else "Status Root"

                            playback_url = f"https://web.archive.org/web/{ts}/{orig}"
                            items.append({
                                "tweet_id": tweet_id,
                                "timestamp": ts,
                                "formatted_date": formatted_date,
                                "original_url": orig,
                                "wayback_url": playback_url,
                                "status_code": status_code
                            })
        except Exception:
            pass
        return items

    @classmethod
    async def _fetch_profile_availability(cls, client: httpx.AsyncClient, username: str) -> Optional[Dict[str, Any]]:
        """Checks if a direct profile snapshot is available via Wayback Availability API."""
        try:
            avail_url = f"https://archive.org/wayback/available?url=https://twitter.com/{username}"
            resp = await client.get(avail_url)
            if resp.status_code == 200:
                data = resp.json()
                snapshots = data.get("archived_snapshots", {})
                closest = snapshots.get("closest")
                if closest and closest.get("available"):
                    return {
                        "timestamp": closest.get("timestamp"),
                        "wayback_url": closest.get("url"),
                        "status_code": closest.get("status")
                    }
        except Exception:
            pass
        return None

    @classmethod
    async def scrape_twitter_archive(cls, username: str, limit: int = 25) -> Dict[str, Any]:
        """
        Executes live scraping of Twitter / X status captures using Wayback Machine.
        Queries both twitter.com and x.com wildcard paths concurrently.
        """
        clean_user = cls.sanitize_username(username)
        archive_urls = cls.get_archive_urls(clean_user)

        if not clean_user:
            return {
                "status": "error",
                "message": "Username cannot be empty.",
                "archive_urls": archive_urls
            }

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9"
        }

        # Internet Archive CDX responses typically take 12-25 seconds; 30s timeout is required.
        timeout = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)

        async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
            # Query CDX patterns and profile availability in parallel
            task_twitter = cls._fetch_cdx_pattern(client, f"twitter.com/{clean_user}/status/*", limit)
            task_x = cls._fetch_cdx_pattern(client, f"x.com/{clean_user}/status/*", limit)
            task_profile = cls._fetch_profile_availability(client, clean_user)

            results = await asyncio.gather(task_twitter, task_x, task_profile, return_exceptions=True)

            twitter_snapshots = results[0] if isinstance(results[0], list) else []
            x_snapshots = results[1] if isinstance(results[1], list) else []
            profile_avail = results[2] if isinstance(results[2], dict) else None

        # Combine snapshots, removing duplicates by wayback_url
        seen_urls = set()
        combined_snapshots: List[Dict[str, Any]] = []
        for s in (twitter_snapshots + x_snapshots):
            if s["wayback_url"] not in seen_urls:
                seen_urls.add(s["wayback_url"])
                combined_snapshots.append(s)

        # Sort by timestamp descending (most recent first)
        combined_snapshots.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        cdx_status = "operational" if len(combined_snapshots) > 0 else "completed_no_status_snapshots"

        return {
            "status": "success",
            "username": clean_user,
            "archive_urls": archive_urls,
            "profile_snapshot": profile_avail,
            "cdx_status": cdx_status,
            "total_snapshots_found": len(combined_snapshots),
            "snapshots": combined_snapshots,
            "note": (
                f"Successfully extracted {len(combined_snapshots)} archived status snapshots from the Wayback Machine."
                if len(combined_snapshots) > 0 else
                "No individual status snapshots indexed in CDX. You can explore complete historical snapshots via the direct archive calendar links."
            )
        }
