"""
CyberIntel Platform — Celery Workers

Async task processing for infrastructure discovery, crawling,
and campaign detection.
"""
import logging
import asyncio
from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

logger = logging.getLogger("cyberintel.workers")

# ── Celery App ───────────────────────────────────────────────

celery_app = Celery(
    "cyberintel",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=600,  # 10 min max per task
    task_soft_time_limit=540,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    beat_schedule={
        "detect-campaigns-hourly": {
            "task": "app.workers.celery_app.detect_campaigns_task",
            "schedule": crontab(minute=0),  # Every hour
        },
    },
)


def run_async(coro):
    """Helper to run async code in sync Celery tasks."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── Tasks ────────────────────────────────────────────────────

@celery_app.task(bind=True, name="investigate_domain", max_retries=2)
def investigate_domain_task(self, domain: str, depth: int = 1):
    """
    Full investigation pipeline for a domain:
    1. Infrastructure discovery (DNS, WHOIS, TLS, Hosting)
    2. Website fingerprinting (Playwright crawl)
    3. Graph ingestion
    4. Campaign analysis
    """
    logger.info(f"[Task] Investigating domain: {domain} (depth={depth})")

    async def _run():
        from app.core.database import GraphDB
        from app.discovery.engine import DiscoveryEngine
        from app.crawler.fingerprint import WebsiteCrawler
        from app.graph.engine import GraphEngine
        from app.campaign.detector import CampaignDetector

        await GraphDB.connect()

        discovery_engine = DiscoveryEngine()
        crawler = WebsiteCrawler()
        graph_engine = GraphEngine()
        campaign_detector = CampaignDetector()

        result = {"domain": domain, "status": "running", "errors": []}

        # Step 1: Infrastructure discovery
        try:
            discovery = await discovery_engine.investigate_domain(domain)
            result["discovery"] = discovery
        except Exception as e:
            result["errors"].append(f"Discovery failed: {str(e)}")
            discovery = {}

        # Step 2: Website fingerprinting
        fingerprint = None
        try:
            fingerprint = await crawler.crawl(domain)
            result["fingerprint"] = fingerprint
        except Exception as e:
            result["errors"].append(f"Crawling failed: {str(e)}")

        # Step 3: Graph ingestion
        try:
            await graph_engine.ingest_discovery(domain, discovery, fingerprint)
        except Exception as e:
            result["errors"].append(f"Graph ingestion failed: {str(e)}")

        # Step 4: Campaign analysis
        try:
            campaigns = await campaign_detector.analyze_domain(domain)
            result["campaigns"] = campaigns
        except Exception as e:
            result["errors"].append(f"Campaign detection failed: {str(e)}")

        # Step 5: Expand related domains (if depth > 1)
        if depth > 1:
            related = discovery.get("related_domains", [])
            for rel_domain in related[:10]:  # Limit expansion
                investigate_domain_task.delay(rel_domain, depth=depth - 1)

        result["status"] = "completed"
        return result

    try:
        return run_async(_run())
    except Exception as exc:
        logger.error(f"[Task] Failed for {domain}: {exc}")
        self.retry(exc=exc, countdown=30)


@celery_app.task(bind=True, name="investigate_ip")
def investigate_ip_task(self, ip_address: str):
    """Investigate an IP address."""
    logger.info(f"[Task] Investigating IP: {ip_address}")

    async def _run():
        from app.core.database import GraphDB
        from app.discovery.engine import DiscoveryEngine
        from app.graph.engine import GraphEngine

        await GraphDB.connect()
        engine = DiscoveryEngine()
        graph = GraphEngine()

        result = await engine.investigate_ip(ip_address)

        # Store in graph
        hosting = result.get("hosting", {})
        await graph.upsert_ip(ip_address, {
            "country": hosting.get("country", ""),
            "city": hosting.get("city", ""),
        })

        if hosting.get("asn"):
            await graph.upsert_asn(hosting["asn"])
            await graph.link_ip_to_asn(ip_address, hosting["asn"])

        if hosting.get("hosting_provider"):
            await graph.upsert_hosting_provider(hosting["hosting_provider"])
            await graph.link_ip_to_hosting(ip_address, hosting["hosting_provider"])

        # Investigate reverse DNS domains
        for hostname in result.get("reverse_dns", []):
            investigate_domain_task.delay(hostname, depth=1)

        return result

    try:
        return run_async(_run())
    except Exception as exc:
        logger.error(f"[Task] IP investigation failed: {exc}")
        raise


@celery_app.task(name="detect_campaigns")
def detect_campaigns_task():
    """Periodic campaign detection scan."""
    logger.info("[Task] Running campaign detection...")

    async def _run():
        from app.core.database import GraphDB
        from app.campaign.detector import CampaignDetector

        await GraphDB.connect()
        detector = CampaignDetector()
        return await detector.detect_campaigns()

    return run_async(_run())


@celery_app.task(name="crawl_website")
def crawl_website_task(url: str):
    """Standalone website crawl task."""
    logger.info(f"[Task] Crawling: {url}")

    async def _run():
        from app.crawler.fingerprint import WebsiteCrawler
        crawler = WebsiteCrawler()
        return await crawler.crawl(url)

    return run_async(_run())
