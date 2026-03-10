"""
CyberIntel Platform — REST API Endpoints
"""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from celery.result import AsyncResult

from app.models.schemas import (
    ArtifactSubmission, ArtifactResponse, InvestigationStatus,
    GraphData, CampaignInfo, NetworkConfig, TaskStatus,
    ArtifactType, AnonymizationModeEnum,
)
from app.workers.celery_app import (
    investigate_domain_task, investigate_ip_task,
    detect_campaigns_task, crawl_website_task, celery_app,
)
from app.graph.engine import GraphEngine
from app.campaign.detector import CampaignDetector
from app.core.network import network
from app.core.config import AnonymizationMode
from app.core.database import GraphDB

logger = logging.getLogger("cyberintel.api")

router = APIRouter()
graph_engine = GraphEngine()
campaign_detector = CampaignDetector()


# ── Artifact Submission ──────────────────────────────────────

@router.post("/artifact", response_model=ArtifactResponse, tags=["Investigation"])
async def submit_artifact(submission: ArtifactSubmission):
    """
    Submit an artifact for investigation.
    Starts async discovery pipeline via Celery.
    """
    logger.info(f"Artifact submitted: type={submission.type} value={submission.value}")

    task = None

    if submission.type == ArtifactType.DOMAIN:
        task = investigate_domain_task.delay(submission.value, depth=submission.depth)

    elif submission.type == ArtifactType.URL:
        # Extract domain from URL, also crawl directly
        from urllib.parse import urlparse
        parsed = urlparse(submission.value)
        domain = parsed.netloc or parsed.path.split("/")[0]
        task = investigate_domain_task.delay(domain, depth=submission.depth)

    elif submission.type == ArtifactType.IP:
        task = investigate_ip_task.delay(submission.value)

    elif submission.type == ArtifactType.TLS_FINGERPRINT:
        # Search graph for this cert fingerprint
        query = """
        MATCH (c:Certificate {fingerprint: $fp})<-[:USES_CERTIFICATE]-(d:Domain)
        RETURN d.name AS domain
        """
        records = await GraphDB.execute(query, {"fp": submission.value})
        if records:
            for r in records:
                investigate_domain_task.delay(r["domain"], depth=1)

        return ArtifactResponse(
            type=submission.type,
            value=submission.value,
            status=InvestigationStatus.RUNNING,
            task_id=None,
        )

    elif submission.type == ArtifactType.EMAIL_DOMAIN:
        # Extract domain from email and investigate
        domain = submission.value.split("@")[-1] if "@" in submission.value else submission.value
        task = investigate_domain_task.delay(domain, depth=submission.depth)

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported artifact type: {submission.type}")

    return ArtifactResponse(
        type=submission.type,
        value=submission.value,
        status=InvestigationStatus.RUNNING,
        task_id=task.id if task else None,
    )


# ── Task Status ──────────────────────────────────────────────

@router.get("/task/{task_id}", response_model=TaskStatus, tags=["Investigation"])
async def get_task_status(task_id: str):
    """Check the status of an investigation task."""
    result = AsyncResult(task_id, app=celery_app)
    return TaskStatus(
        task_id=task_id,
        status=result.status,
        result=result.result if result.ready() else None,
    )


# ── Graph Queries ────────────────────────────────────────────

@router.get("/graph", tags=["Graph"])
async def get_full_graph(limit: int = Query(default=500, le=5000)):
    """Return the full investigation graph."""
    return await graph_engine.get_full_graph(limit=limit)


@router.get("/graph/domain/{domain}", tags=["Graph"])
async def get_domain_graph(domain: str, depth: int = Query(default=2, ge=1, le=5)):
    """Return the subgraph around a specific domain."""
    return await graph_engine.get_domain_graph(domain, depth=depth)


@router.get("/graph/stats", tags=["Graph"])
async def get_graph_stats():
    """Return node and relationship counts."""
    return await graph_engine.get_graph_stats()


@router.get("/graph/related/{domain}", tags=["Graph"])
async def get_related_domains(domain: str):
    """Find all domains related to the given domain."""
    cert_related = await graph_engine.get_related_by_cert(domain)
    favicon_related = await graph_engine.get_related_by_favicon(domain)
    html_related = await graph_engine.get_related_by_html(domain)

    return {
        "domain": domain,
        "related_by_certificate": cert_related,
        "related_by_favicon": favicon_related,
        "related_by_html": html_related,
        "total_related": len(set(cert_related + favicon_related + html_related)),
    }


@router.get("/graph/search", tags=["Graph"])
async def search_graph(q: str = Query(..., min_length=1)):
    """Full-text search across graph nodes."""
    query = """
    MATCH (n)
    WHERE any(prop IN keys(n) WHERE toString(n[prop]) CONTAINS $search)
    RETURN labels(n)[0] AS type, properties(n) AS props
    LIMIT 50
    """
    records = await GraphDB.execute(query, {"search": q})
    return {"query": q, "results": records}


@router.get("/graph/nodes", tags=["Graph"])
async def get_graph_nodes_cytoscape(limit: int = Query(default=300, le=2000)):
    """
    Return graph in Cytoscape.js-compatible format.
    """
    node_query = """
    MATCH (n)
    RETURN elementId(n) AS id, labels(n)[0] AS type, properties(n) AS props
    LIMIT $limit
    """
    edge_query = """
    MATCH (a)-[r]->(b)
    RETURN elementId(a) AS source, elementId(b) AS target,
           type(r) AS relationship, properties(r) AS props
    LIMIT $limit
    """

    nodes_raw = await GraphDB.execute(node_query, {"limit": limit})
    edges_raw = await GraphDB.execute(edge_query, {"limit": limit})

    nodes = []
    for n in nodes_raw:
        props = n.get("props", {})
        label = (
            props.get("name")
            or props.get("address")
            or props.get("fingerprint", "")[:16]
            or props.get("hash", "")[:16]
            or props.get("number")
            or props.get("id")
            or str(n["id"])[:12]
        )
        nodes.append({
            "data": {
                "id": str(n["id"]),
                "label": str(label),
                "type": n["type"],
                **{k: str(v)[:100] for k, v in props.items()},
            }
        })

    edges = []
    for e in edges_raw:
        edges.append({
            "data": {
                "source": str(e["source"]),
                "target": str(e["target"]),
                "relationship": e["relationship"],
                "confidence": e.get("props", {}).get("confidence", 0.5),
            }
        })

    return {"nodes": nodes, "edges": edges}


# ── Campaigns ────────────────────────────────────────────────

@router.get("/campaigns", tags=["Campaigns"])
async def list_campaigns():
    """List all detected campaigns."""
    return await campaign_detector.get_all_campaigns()


@router.post("/campaigns/detect", tags=["Campaigns"])
async def trigger_campaign_detection():
    """Trigger a campaign detection scan."""
    task = detect_campaigns_task.delay()
    return {"task_id": task.id, "status": "detection_started"}


@router.get("/campaigns/{campaign_id}", tags=["Campaigns"])
async def get_campaign(campaign_id: str):
    """Get details of a specific campaign."""
    query = """
    MATCH (c:Campaign {id: $id})<-[r:BELONGS_TO_CAMPAIGN]-(d:Domain)
    RETURN c, COLLECT(d.name) AS domains
    """
    records = await GraphDB.execute(query, {"id": campaign_id})
    if not records:
        raise HTTPException(status_code=404, detail="Campaign not found")

    rec = records[0]
    return {
        "campaign": dict(rec["c"]),
        "domains": rec["domains"],
    }


# ── Network Configuration ───────────────────────────────────

@router.get("/network/config", tags=["Network"])
async def get_network_config():
    """Get current anonymization configuration."""
    from app.core.config import settings
    return {
        "mode": settings.ANONYMIZATION_MODE.value,
        "rate_limit_rps": settings.RATE_LIMIT_RPS,
        "safe_mode": settings.SAFE_CRAWL_MODE,
        "tor_proxy": settings.TOR_PROXY,
    }


@router.put("/network/config", tags=["Network"])
async def update_network_config(config: NetworkConfig):
    """Update anonymization mode and proxy settings."""
    mode_map = {
        AnonymizationModeEnum.DIRECT: AnonymizationMode.DIRECT,
        AnonymizationModeEnum.PROXY_CHAIN: AnonymizationMode.PROXY_CHAIN,
        AnonymizationModeEnum.TOR: AnonymizationMode.TOR,
        AnonymizationModeEnum.CUSTOM: AnonymizationMode.CUSTOM,
    }

    network.set_mode(mode_map[config.mode])

    if config.custom_proxy:
        network.set_custom_proxy(config.custom_proxy)

    if config.proxy_list:
        network.set_proxy_list(config.proxy_list)

    return {"status": "updated", "mode": config.mode}


# ── Health ───────────────────────────────────────────────────

@router.get("/health", tags=["System"])
async def health_check():
    """System health check."""
    neo4j_ok = False
    try:
        await GraphDB.execute("RETURN 1")
        neo4j_ok = True
    except Exception:
        pass

    redis_ok = False
    try:
        from redis import Redis
        r = Redis.from_url(settings.REDIS_URL)
        r.ping()
        redis_ok = True
    except Exception:
        pass

    from app.core.config import settings
    return {
        "status": "healthy" if (neo4j_ok and redis_ok) else "degraded",
        "neo4j": neo4j_ok,
        "redis": redis_ok,
        "version": settings.APP_VERSION,
    }
