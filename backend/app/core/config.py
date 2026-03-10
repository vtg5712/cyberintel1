"""
CyberIntel Platform — Configuration
"""
from pydantic_settings import BaseSettings
from enum import Enum
from typing import Optional


class AnonymizationMode(str, Enum):
    DIRECT = "direct"
    PROXY_CHAIN = "proxy_chain"
    TOR = "tor"
    CUSTOM = "custom"


class Settings(BaseSettings):
    # ── Application ──────────────────────────────────────────
    APP_NAME: str = "CyberIntel Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # ── Neo4j ────────────────────────────────────────────────
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "investigation_secret"

    # ── Redis / Celery ───────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # ── Anonymization ────────────────────────────────────────
    ANONYMIZATION_MODE: AnonymizationMode = AnonymizationMode.DIRECT
    TOR_PROXY: str = "socks5://tor:9050"
    CUSTOM_PROXY: Optional[str] = None
    PROXY_LIST: list[str] = []
    ROTATE_PROXIES: bool = False
    RATE_LIMIT_RPS: float = 2.0
    SAFE_CRAWL_MODE: bool = True

    # ── Crawler ──────────────────────────────────────────────
    SCREENSHOT_DIR: str = "/app/screenshots"
    CRAWLER_TIMEOUT: int = 30000
    MAX_CRAWL_DEPTH: int = 2

    # ── Discovery ────────────────────────────────────────────
    DNS_TIMEOUT: float = 10.0
    WHOIS_TIMEOUT: float = 15.0
    TLS_TIMEOUT: float = 10.0

    # ── Campaign Detection ───────────────────────────────────
    SIMILARITY_THRESHOLD: float = 0.75
    CAMPAIGN_TIME_WINDOW_DAYS: int = 30

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
