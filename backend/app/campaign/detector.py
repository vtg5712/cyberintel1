"""
CyberIntel Platform — Campaign Detection Engine

Automatically clusters related infrastructure into campaigns
based on shared indicators: certificates, favicons, HTML fingerprints,
hosting, registration timing, and naming patterns.
"""
import logging
import re
import uuid
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict

from app.core.database import GraphDB
from app.core.config import settings
from app.graph.engine import GraphEngine

logger = logging.getLogger("cyberintel.campaign")


class CampaignDetector:
    """
    Detects and clusters phishing/scam campaigns based on
    shared infrastructure indicators.
    """

    # Weight factors for confidence scoring
    WEIGHTS = {
        "shared_certificate": 0.30,
        "shared_favicon": 0.20,
        "shared_html": 0.20,
        "shared_hosting": 0.10,
        "temporal_proximity": 0.10,
        "naming_pattern": 0.10,
    }

    def __init__(self):
        self.graph = GraphEngine()

    async def detect_campaigns(self) -> list[dict]:
        """
        Run campaign detection across all domains in the graph.
        Returns a list of detected campaign clusters.
        """
        logger.info("Starting campaign detection scan...")

        # 1. Find clusters based on shared indicators
        cert_clusters = await self._cluster_by_certificate()
        favicon_clusters = await self._cluster_by_favicon()
        html_clusters = await self._cluster_by_html()
        hosting_clusters = await self._cluster_by_hosting()

        # 2. Merge overlapping clusters
        all_clusters = self._merge_clusters(
            cert_clusters, favicon_clusters, html_clusters, hosting_clusters
        )

        # 3. Score and filter
        campaigns = []
        for cluster_domains in all_clusters:
            if len(cluster_domains) < 2:
                continue

            score = await self._score_cluster(cluster_domains)
            if score >= settings.SIMILARITY_THRESHOLD:
                campaign = await self._create_campaign(cluster_domains, score)
                campaigns.append(campaign)

        logger.info(f"Campaign detection complete: {len(campaigns)} campaigns found")
        return campaigns

    async def analyze_domain(self, domain: str) -> list[dict]:
        """Check if a specific domain belongs to any campaign pattern."""
        logger.info(f"Analyzing campaign membership for: {domain}")

        related_cert = await self._get_shared_cert_domains(domain)
        related_favicon = await self._get_shared_favicon_domains(domain)
        related_html = await self._get_shared_html_domains(domain)

        all_related = set(related_cert + related_favicon + related_html)
        all_related.discard(domain)

        if not all_related:
            return []

        cluster = list(all_related) + [domain]
        score = await self._score_cluster(cluster)

        if score >= settings.SIMILARITY_THRESHOLD:
            campaign = await self._create_campaign(cluster, score)
            return [campaign]

        return []

    # ── Clustering by Indicator ──────────────────────────────

    async def _cluster_by_certificate(self) -> list[set]:
        """Find groups of domains sharing the same TLS certificate."""
        query = """
        MATCH (d:Domain)-[:USES_CERTIFICATE]->(c:Certificate)<-[:USES_CERTIFICATE]-(d2:Domain)
        WHERE d.name < d2.name
        RETURN c.fingerprint AS cert, COLLECT(DISTINCT d.name) + COLLECT(DISTINCT d2.name) AS domains
        """
        records = await GraphDB.execute(query)
        return [set(r["domains"]) for r in records if len(set(r["domains"])) >= 2]

    async def _cluster_by_favicon(self) -> list[set]:
        query = """
        MATCH (d:Domain)-[:SHARES_FAVICON]->(f:FaviconHash)<-[:SHARES_FAVICON]-(d2:Domain)
        WHERE d.name < d2.name
        RETURN f.hash AS favicon, COLLECT(DISTINCT d.name) + COLLECT(DISTINCT d2.name) AS domains
        """
        records = await GraphDB.execute(query)
        return [set(r["domains"]) for r in records if len(set(r["domains"])) >= 2]

    async def _cluster_by_html(self) -> list[set]:
        query = """
        MATCH (d:Domain)-[:SIMILAR_HTML]->(h:HTMLFingerprint)<-[:SIMILAR_HTML]-(d2:Domain)
        WHERE d.name < d2.name
        RETURN h.hash AS html_hash, COLLECT(DISTINCT d.name) + COLLECT(DISTINCT d2.name) AS domains
        """
        records = await GraphDB.execute(query)
        return [set(r["domains"]) for r in records if len(set(r["domains"])) >= 2]

    async def _cluster_by_hosting(self) -> list[set]:
        query = """
        MATCH (d:Domain)-[:RESOLVES_TO]->(i:IP)-[:HOSTED_BY]->(h:HostingProvider)<-[:HOSTED_BY]-(i2:IP)<-[:RESOLVES_TO]-(d2:Domain)
        WHERE d.name < d2.name
        RETURN h.name AS provider, COLLECT(DISTINCT d.name) + COLLECT(DISTINCT d2.name) AS domains
        """
        records = await GraphDB.execute(query)
        return [set(r["domains"]) for r in records if len(set(r["domains"])) >= 2]

    # ── Cluster Merging ──────────────────────────────────────

    def _merge_clusters(self, *cluster_lists) -> list[set]:
        """Merge overlapping clusters using union-find."""
        all_clusters = []
        for cl in cluster_lists:
            all_clusters.extend(cl)

        if not all_clusters:
            return []

        # Union-find merge
        merged = True
        while merged:
            merged = False
            new_clusters = []
            used = set()

            for i, c1 in enumerate(all_clusters):
                if i in used:
                    continue
                current = set(c1)
                for j, c2 in enumerate(all_clusters):
                    if j <= i or j in used:
                        continue
                    if current & set(c2):
                        current |= set(c2)
                        used.add(j)
                        merged = True
                used.add(i)
                new_clusters.append(current)

            all_clusters = new_clusters

        return all_clusters

    # ── Scoring ──────────────────────────────────────────────

    async def _score_cluster(self, domains: list[str]) -> float:
        """
        Score a cluster of domains based on shared indicators.
        Returns a confidence score between 0.0 and 1.0.
        """
        if len(domains) < 2:
            return 0.0

        scores = {}

        # Shared certificate
        cert_query = """
        MATCH (d:Domain)-[:USES_CERTIFICATE]->(c:Certificate)
        WHERE d.name IN $domains
        WITH c, COLLECT(d.name) AS cert_domains
        WHERE SIZE(cert_domains) > 1
        RETURN COUNT(c) AS shared_certs
        """
        result = await GraphDB.execute(cert_query, {"domains": domains})
        scores["shared_certificate"] = 1.0 if result and result[0]["shared_certs"] > 0 else 0.0

        # Shared favicon
        fav_query = """
        MATCH (d:Domain)-[:SHARES_FAVICON]->(f:FaviconHash)
        WHERE d.name IN $domains
        WITH f, COLLECT(d.name) AS fav_domains
        WHERE SIZE(fav_domains) > 1
        RETURN COUNT(f) AS shared_favs
        """
        result = await GraphDB.execute(fav_query, {"domains": domains})
        scores["shared_favicon"] = 1.0 if result and result[0]["shared_favs"] > 0 else 0.0

        # Shared HTML fingerprint
        html_query = """
        MATCH (d:Domain)-[:SIMILAR_HTML]->(h:HTMLFingerprint)
        WHERE d.name IN $domains
        WITH h, COLLECT(d.name) AS html_domains
        WHERE SIZE(html_domains) > 1
        RETURN COUNT(h) AS shared_html
        """
        result = await GraphDB.execute(html_query, {"domains": domains})
        scores["shared_html"] = 1.0 if result and result[0]["shared_html"] > 0 else 0.0

        # Shared hosting
        host_query = """
        MATCH (d:Domain)-[:RESOLVES_TO]->(i:IP)-[:HOSTED_BY]->(h:HostingProvider)
        WHERE d.name IN $domains
        WITH h, COLLECT(DISTINCT d.name) AS hosted_domains
        WHERE SIZE(hosted_domains) > 1
        RETURN COUNT(h) AS shared_hosts
        """
        result = await GraphDB.execute(host_query, {"domains": domains})
        scores["shared_hosting"] = 1.0 if result and result[0]["shared_hosts"] > 0 else 0.0

        # Naming pattern similarity
        scores["naming_pattern"] = self._score_naming_pattern(domains)

        # Temporal proximity
        scores["temporal_proximity"] = await self._score_temporal(domains)

        # Weighted sum
        total = sum(
            scores.get(k, 0) * w for k, w in self.WEIGHTS.items()
        )

        return round(min(total, 1.0), 3)

    def _score_naming_pattern(self, domains: list[str]) -> float:
        """Score based on domain naming similarity patterns."""
        if len(domains) < 2:
            return 0.0

        # Extract base names (without TLD)
        bases = []
        for d in domains:
            parts = d.split(".")
            if len(parts) >= 2:
                bases.append(parts[0])

        # Check for common keywords (bank, login, secure, verify, account, etc.)
        phishing_keywords = [
            "login", "secure", "verify", "account", "bank", "update",
            "confirm", "signin", "auth", "payment", "wallet", "support",
        ]

        keyword_count = 0
        for base in bases:
            for kw in phishing_keywords:
                if kw in base.lower():
                    keyword_count += 1
                    break

        keyword_ratio = keyword_count / len(bases) if bases else 0

        # Check for common prefixes/suffixes
        if len(bases) >= 2:
            common_prefix = len(os.path.commonprefix(bases))
            avg_len = sum(len(b) for b in bases) / len(bases)
            prefix_score = common_prefix / avg_len if avg_len > 0 else 0
        else:
            prefix_score = 0

        return min((keyword_ratio + prefix_score) / 2, 1.0)

    async def _score_temporal(self, domains: list[str]) -> float:
        """Score based on temporal proximity of domain creation."""
        query = """
        MATCH (d:Domain)
        WHERE d.name IN $domains AND d.created_date IS NOT NULL
        RETURN d.created_date AS created
        """
        records = await GraphDB.execute(query, {"domains": domains})
        if len(records) < 2:
            return 0.0

        dates = []
        for r in records:
            try:
                if isinstance(r["created"], str):
                    dates.append(datetime.fromisoformat(r["created"]))
                else:
                    dates.append(r["created"])
            except Exception:
                continue

        if len(dates) < 2:
            return 0.0

        dates.sort()
        max_span = (dates[-1] - dates[0]).days
        window = settings.CAMPAIGN_TIME_WINDOW_DAYS

        if max_span <= window:
            return 1.0
        elif max_span <= window * 3:
            return 0.5
        return 0.0

    # ── Campaign Creation ────────────────────────────────────

    async def _create_campaign(self, domains: list[str], confidence: float) -> dict:
        """Create a campaign node and link all member domains."""
        campaign_id = f"CAMP-{uuid.uuid4().hex[:8].upper()}"
        name = f"Campaign {campaign_id}"

        await self.graph.upsert_campaign(campaign_id, {
            "name": name,
            "domain_count": len(domains),
            "confidence": confidence,
            "detected_at": datetime.utcnow().isoformat(),
        })

        for domain in domains:
            await self.graph.link_domain_to_campaign(domain, campaign_id, confidence)

        logger.info(f"Created campaign {campaign_id}: {len(domains)} domains, confidence={confidence}")

        return {
            "id": campaign_id,
            "name": name,
            "domain_count": len(domains),
            "domains": domains,
            "confidence": confidence,
            "detected_at": datetime.utcnow().isoformat(),
        }

    # ── Query Helpers ────────────────────────────────────────

    async def _get_shared_cert_domains(self, domain: str) -> list[str]:
        query = """
        MATCH (d:Domain {name: $domain})-[:USES_CERTIFICATE]->(c)<-[:USES_CERTIFICATE]-(other:Domain)
        RETURN DISTINCT other.name AS domain
        """
        records = await GraphDB.execute(query, {"domain": domain})
        return [r["domain"] for r in records]

    async def _get_shared_favicon_domains(self, domain: str) -> list[str]:
        query = """
        MATCH (d:Domain {name: $domain})-[:SHARES_FAVICON]->(f)<-[:SHARES_FAVICON]-(other:Domain)
        RETURN DISTINCT other.name AS domain
        """
        records = await GraphDB.execute(query, {"domain": domain})
        return [r["domain"] for r in records]

    async def _get_shared_html_domains(self, domain: str) -> list[str]:
        query = """
        MATCH (d:Domain {name: $domain})-[:SIMILAR_HTML]->(h)<-[:SIMILAR_HTML]-(other:Domain)
        RETURN DISTINCT other.name AS domain
        """
        records = await GraphDB.execute(query, {"domain": domain})
        return [r["domain"] for r in records]

    async def get_all_campaigns(self) -> list[dict]:
        """Return all detected campaigns with their domains."""
        query = """
        MATCH (c:Campaign)<-[r:BELONGS_TO_CAMPAIGN]-(d:Domain)
        RETURN c.id AS id, c.name AS name, c.confidence AS confidence,
               c.detected_at AS detected_at, COLLECT(d.name) AS domains
        ORDER BY c.detected_at DESC
        """
        records = await GraphDB.execute(query)
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "confidence": r["confidence"],
                "detected_at": r["detected_at"],
                "domains": r["domains"],
                "domain_count": len(r["domains"]),
            }
            for r in records
        ]


# Fix missing import
import os
