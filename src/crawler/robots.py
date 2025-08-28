from __future__ import annotations
from urllib.parse import urlparse
from urllib import robotparser
import asyncio
import aiohttp
from ..utils.logger import get_logger

logger = get_logger("robots")

class RobotsCache:
    """
    Simple robots.txt cache per host. If robots can't be fetched, default to allow.
    """
    def __init__(self, user_agent: str = "AgenticScanner/0.2", timeout: int = 10) -> None:
        self._cache: dict[str, robotparser.RobotFileParser | None] = {}
        self.user_agent = user_agent
        self.timeout = timeout
        self._lock = asyncio.Lock()

    async def allowed(self, session: aiohttp.ClientSession, url: str) -> bool:
        parsed = urlparse(url)
        host = parsed.netloc
        if not host:
            return True
        async with self._lock:
            rp = self._cache.get(host)
            if rp is None and host not in self._cache:
                robots_url = f"{parsed.scheme}://{host}/robots.txt"
                try:
                    async with session.get(robots_url, timeout=self.timeout) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            rp = robotparser.RobotFileParser()
                            rp.parse(text.splitlines())
                            self._cache[host] = rp
                        else:
                            # mark as no parser (allow-by-default)
                            self._cache[host] = None
                            return True
                except Exception as e:
                    logger.debug(f"Failed to fetch robots.txt for {host}: {e}")
                    self._cache[host] = None
                    return True
            # if cached as None, it means allow-by-default
            rp = self._cache.get(host)
            if rp is None:
                return True
            return rp.can_fetch(self.user_agent, url)
