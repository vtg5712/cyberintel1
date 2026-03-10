"""
CyberIntel Platform — Anonymized Networking Layer

All external HTTP requests MUST go through this module.
Supports: direct, proxy chain, Tor, custom proxy.
Includes: UA randomization, rate limiting, safe crawling.
"""
import asyncio
import time
import random
import logging
from typing import Optional
from contextlib import asynccontextmanager

import httpx
from fake_useragent import UserAgent

from app.core.config import settings, AnonymizationMode

logger = logging.getLogger("cyberintel.network")


class RateLimiter:
    """Token-bucket rate limiter for outgoing requests."""

    def __init__(self, rps: float = 2.0):
        self.rps = rps
        self.interval = 1.0 / rps
        self._last_request = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self.interval:
                await asyncio.sleep(self.interval - elapsed)
            self._last_request = time.monotonic()


class ProxyRotator:
    """Round-robin proxy rotation from a configured list."""

    def __init__(self, proxies: list[str]):
        self._proxies = proxies
        self._index = 0

    def next(self) -> Optional[str]:
        if not self._proxies:
            return None
        proxy = self._proxies[self._index % len(self._proxies)]
        self._index += 1
        return proxy


class AnonymizedNetwork:
    """
    Central networking module.
    Every external request in the system goes through this class.
    """

    def __init__(self):
        self._ua = UserAgent(fallback="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        self._rate_limiter = RateLimiter(rps=settings.RATE_LIMIT_RPS)
        self._proxy_rotator = ProxyRotator(settings.PROXY_LIST)
        self._mode = settings.ANONYMIZATION_MODE
        logger.info(f"Network layer initialized | mode={self._mode.value}")

    @property
    def random_user_agent(self) -> str:
        try:
            return self._ua.random
        except Exception:
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    def _resolve_proxy(self) -> Optional[str]:
        """Return the proxy URL based on the current anonymization mode."""
        if self._mode == AnonymizationMode.DIRECT:
            return None
        elif self._mode == AnonymizationMode.TOR:
            return settings.TOR_PROXY
        elif self._mode == AnonymizationMode.PROXY_CHAIN:
            return self._proxy_rotator.next()
        elif self._mode == AnonymizationMode.CUSTOM:
            return settings.CUSTOM_PROXY
        return None

    def _build_headers(self, extra_headers: Optional[dict] = None) -> dict:
        headers = {
            "User-Agent": self.random_user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "DNT": "1",
        }
        if extra_headers:
            headers.update(extra_headers)
        return headers

    @asynccontextmanager
    async def client(self, timeout: float = 30.0, follow_redirects: bool = True):
        """Yield an httpx.AsyncClient configured with anonymization."""
        await self._rate_limiter.acquire()

        proxy = self._resolve_proxy()
        transport = None

        if proxy:
            transport = httpx.AsyncHTTPTransport(proxy=proxy)

        async with httpx.AsyncClient(
            transport=transport,
            headers=self._build_headers(),
            timeout=httpx.Timeout(timeout),
            follow_redirects=follow_redirects,
            verify=False,  # Investigating phishing sites — certs may be invalid
        ) as client:
            yield client

    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Anonymized GET request."""
        async with self.client() as client:
            logger.debug(f"GET {url} | mode={self._mode.value}")
            return await client.get(url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Anonymized POST request."""
        async with self.client() as client:
            logger.debug(f"POST {url} | mode={self._mode.value}")
            return await client.post(url, **kwargs)

    async def head(self, url: str, **kwargs) -> httpx.Response:
        """Anonymized HEAD request."""
        async with self.client() as client:
            return await client.head(url, **kwargs)

    def get_playwright_proxy(self) -> Optional[dict]:
        """Return proxy config dict for Playwright browser context."""
        proxy_url = self._resolve_proxy()
        if not proxy_url:
            return None
        return {"server": proxy_url}

    def set_mode(self, mode: AnonymizationMode):
        self._mode = mode
        logger.info(f"Anonymization mode changed to: {mode.value}")

    def set_custom_proxy(self, proxy_url: str):
        settings.CUSTOM_PROXY = proxy_url
        self._mode = AnonymizationMode.CUSTOM
        logger.info(f"Custom proxy set: {proxy_url}")

    def set_proxy_list(self, proxies: list[str]):
        self._proxy_rotator = ProxyRotator(proxies)
        logger.info(f"Proxy list updated: {len(proxies)} proxies")


# Singleton instance — import this everywhere
network = AnonymizedNetwork()
