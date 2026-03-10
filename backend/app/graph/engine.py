"""
CyberIntel Platform — Graph Relationship Engine

Stores discovered artifacts and their relationships in Neo4j.
Creates and maintains the investigation intelligence graph.
"""
import logging
from datetime import datetime
from typing import Optional

from app.core.database import GraphDB

logger = logging.getLogger("cyberintel.graph.engine")


class GraphEngine:
    """
    Manages the intelligence graph.
    Ingests discovery results and builds relationship links.
    """

    # ── Node Creation ────────────────────────────────────────

    async def upsert_domain(self, domain: str, properties: dict = None) -> str:
        props = properties or {}
        query = """
        MERGE (d:Domain {name: $domain})
        ON CREATE SET d.created_at = datetime(), d += $props
        ON MATCH SET d += $props
        RETURN elementId(d) as id
        """
        result = await GraphDB.execute(query, {"domain": domain, "props": props})
        return result[0]["id"] if result else domain

    async def upsert_ip(self, address: str, properties: dict = None) -> str:
        props = properties or {}
        query = """
        MERGE (i:IP {address: $address})
        ON CREATE SET i.created_at = datetime(), i += $props
        ON MATCH SET i += $props
        RETURN elementId(i) as id
        """
        result = await GraphDB.execute(query, {"address": address, "props": props})
        return result[0]["id"] if result else address

    async def upsert_certificate(self, fingerprint: str, properties: dict = None) -> str:
        props = properties or {}
        query = """
        MERGE (c:Certificate {fingerprint: $fingerprint})
        ON CREATE SET c.created_at = datetime(), c += $props
        ON MATCH SET c += $props
        RETURN elementId(c) as id
        """
        result = await GraphDB.execute(query, {"fingerprint": fingerprint, "props": props})
        return result[0]["id"] if result else fingerprint

    async def upsert_favicon(self, hash_val: str) -> str:
        query = """
        MERGE (f:FaviconHash {hash: $hash})
        ON CREATE SET f.created_at = datetime()
        RETURN elementId(f) as id
        """
        result = await GraphDB.execute(query, {"hash": hash_val})
        return result[0]["id"] if result else hash_val

    async def upsert_html_fingerprint(self, hash_val: str, properties: dict = None) -> str:
        props = properties or {}
        query = """
        MERGE (h:HTMLFingerprint {hash: $hash})
        ON CREATE SET h.created_at = datetime(), h += $props
        ON MATCH SET h += $props
        RETURN elementId(h) as id
        """
        result = await GraphDB.execute(query, {"hash": hash_val, "props": props})
        return result[0]["id"] if result else hash_val

    async def upsert_asn(self, number: str, properties: dict = None) -> str:
        props = properties or {}
        query = """
        MERGE (a:ASN {number: $number})
        ON CREATE SET a.created_at = datetime(), a += $props
        ON MATCH SET a += $props
        RETURN elementId(a) as id
        """
        result = await GraphDB.execute(query, {"number": number, "props": props})
        return result[0]["id"] if result else number

    async def upsert_registrar(self, name: str) -> str:
        query = """
        MERGE (r:Registrar {name: $name})
        ON CREATE SET r.created_at = datetime()
        RETURN elementId(r) as id
        """
        result = await GraphDB.execute(query, {"name": name})
        return result[0]["id"] if result else name

    async def upsert_hosting_provider(self, name: str, properties: dict = None) -> str:
        props = properties or {}
        query = """
        MERGE (h:HostingProvider {name: $name})
        ON CREATE SET h.created_at = datetime(), h += $props
        ON MATCH SET h += $props
        RETURN elementId(h) as id
        """
        result = await GraphDB.execute(query, {"name": name, "props": props})
        return result[0]["id"] if result else name

    async def upsert_campaign(self, campaign_id: str, properties: dict = None) -> str:
        props = properties or {}
        query = """
        MERGE (c:Campaign {id: $id})
        ON CREATE SET c.created_at = datetime(), c += $props
        ON MATCH SET c += $props
        RETURN elementId(c) as eid
        """
        result = await GraphDB.execute(query, {"id": campaign_id, "props": props})
        return result[0]["eid"] if result else campaign_id

    # ── Relationship Creation ────────────────────────────────

    async def link_domain_to_ip(self, domain: str, ip: str, confidence: float = 1.0):
        query = """
        MATCH (d:Domain {name: $domain})
        MATCH (i:IP {address: $ip})
        MERGE (d)-[r:RESOLVES_TO]->(i)
        SET r.confidence = $confidence, r.updated_at = datetime()
        """
        await GraphDB.execute_write(query, {
            "domain": domain, "ip": ip, "confidence": confidence
        })

    async def link_domain_to_cert(self, domain: str, fingerprint: str, confidence: float = 1.0):
        query = """
        MATCH (d:Domain {name: $domain})
        MATCH (c:Certificate {fingerprint: $fingerprint})
        MERGE (d)-[r:USES_CERTIFICATE]->(c)
        SET r.confidence = $confidence, r.updated_at = datetime()
        """
        await GraphDB.execute_write(query, {
            "domain": domain, "fingerprint": fingerprint, "confidence": confidence
        })

    async def link_domain_to_favicon(self, domain: str, favicon_hash: str, confidence: float = 0.8):
        query = """
        MATCH (d:Domain {name: $domain})
        MATCH (f:FaviconHash {hash: $favicon_hash})
        MERGE (d)-[r:SHARES_FAVICON]->(f)
        SET r.confidence = $confidence, r.updated_at = datetime()
        """
        await GraphDB.execute_write(query, {
            "domain": domain, "favicon_hash": favicon_hash, "confidence": confidence
        })

    async def link_domain_to_html_fp(self, domain: str, html_hash: str, confidence: float = 0.7):
        query = """
        MATCH (d:Domain {name: $domain})
        MATCH (h:HTMLFingerprint {hash: $html_hash})
        MERGE (d)-[r:SIMILAR_HTML]->(h)
        SET r.confidence = $confidence, r.updated_at = datetime()
        """
        await GraphDB.execute_write(query, {
            "domain": domain, "html_hash": html_hash, "confidence": confidence
        })

    async def link_ip_to_asn(self, ip: str, asn: str, confidence: float = 1.0):
        query = """
        MATCH (i:IP {address: $ip})
        MATCH (a:ASN {number: $asn})
        MERGE (i)-[r:BELONGS_TO]->(a)
        SET r.confidence = $confidence, r.updated_at = datetime()
        """
        await GraphDB.execute_write(query, {
            "ip": ip, "asn": asn, "confidence": confidence
        })

    async def link_ip_to_hosting(self, ip: str, provider: str, confidence: float = 1.0):
        query = """
        MATCH (i:IP {address: $ip})
        MATCH (h:HostingProvider {name: $provider})
        MERGE (i)-[r:HOSTED_BY]->(h)
        SET r.confidence = $confidence, r.updated_at = datetime()
        """
        await GraphDB.execute_write(query, {
            "ip": ip, "provider": provider, "confidence": confidence
        })

    async def link_domain_to_registrar(self, domain: str, registrar: str, confidence: float = 1.0):
        query = """
        MATCH (d:Domain {name: $domain})
        MATCH (r:Registrar {name: $registrar})
        MERGE (d)-[rel:REGISTERED_WITH]->(r)
        SET rel.confidence = $confidence, rel.updated_at = datetime()
        """
        await GraphDB.execute_write(query, {
            "domain": domain, "registrar": registrar, "confidence": confidence
        })

    async def link_domain_to_campaign(self, domain: str, campaign_id: str, confidence: float = 0.5):
        query = """
        MATCH (d:Domain {name: $domain})
        MATCH (c:Campaign {id: $campaign_id})
        MERGE (d)-[r:BELONGS_TO_CAMPAIGN]->(c)
        SET r.confidence = $confidence, r.updated_at = datetime()
        """
        await GraphDB.execute_write(query, {
            "domain": domain, "campaign_id": campaign_id, "confidence": confidence
        })

    # ── Full Ingestion Pipeline ──────────────────────────────

    async def ingest_discovery(self, domain: str, discovery: dict, fingerprint: dict = None):
        """
        Take raw discovery + fingerprint results and build the full graph.
        """
        logger.info(f"Ingesting discovery data for {domain} into graph")

        # Domain node
        domain_props = {}
        whois_data = discovery.get("whois", {})
        if whois_data.get("creation_date"):
            domain_props["created_date"] = whois_data["creation_date"]
        if whois_data.get("expiration_date"):
            domain_props["expiration_date"] = whois_data["expiration_date"]

        await self.upsert_domain(domain, domain_props)

        # DNS → IP links
        dns_data = discovery.get("dns", {})
        for rtype in ["A", "AAAA"]:
            for ip in dns_data.get("records", {}).get(rtype, []):
                await self.upsert_ip(ip)
                await self.link_domain_to_ip(domain, ip)

                # Hosting info
                hosting = discovery.get("hosting", {})
                if hosting.get("asn"):
                    await self.upsert_asn(hosting["asn"], {
                        "organization": hosting.get("asn_org", "")
                    })
                    await self.link_ip_to_asn(ip, hosting["asn"])

                if hosting.get("hosting_provider"):
                    await self.upsert_hosting_provider(hosting["hosting_provider"], {
                        "country": hosting.get("country", ""),
                    })
                    await self.link_ip_to_hosting(ip, hosting["hosting_provider"])

        # TLS certificate
        tls_data = discovery.get("tls", {})
        if tls_data.get("fingerprint_sha256"):
            cert_props = {
                "issuer_cn": tls_data.get("issuer", {}).get("commonName", ""),
                "subject_cn": tls_data.get("subject", {}).get("commonName", ""),
                "not_before": tls_data.get("not_before", ""),
                "not_after": tls_data.get("not_after", ""),
                "san_count": len(tls_data.get("san_domains", [])),
            }
            await self.upsert_certificate(tls_data["fingerprint_sha256"], cert_props)
            await self.link_domain_to_cert(domain, tls_data["fingerprint_sha256"])

            # Link SAN domains to the same certificate
            for san in tls_data.get("san_domains", []):
                if san != domain:
                    await self.upsert_domain(san, {"discovered_via": "SAN"})
                    await self.link_domain_to_cert(san, tls_data["fingerprint_sha256"])

        # Registrar
        if whois_data.get("registrar"):
            await self.upsert_registrar(whois_data["registrar"])
            await self.link_domain_to_registrar(domain, whois_data["registrar"])

        # Website fingerprint data
        if fingerprint:
            if fingerprint.get("favicon_hash"):
                await self.upsert_favicon(fingerprint["favicon_hash"])
                await self.link_domain_to_favicon(domain, fingerprint["favicon_hash"])

            if fingerprint.get("html_structure_hash"):
                fp_props = {
                    "has_login_form": fingerprint.get("has_login_form", False),
                    "title": fingerprint.get("title", ""),
                }
                await self.upsert_html_fingerprint(
                    fingerprint["html_structure_hash"], fp_props
                )
                await self.link_domain_to_html_fp(
                    domain, fingerprint["html_structure_hash"]
                )

        logger.info(f"Graph ingestion complete for {domain}")

    # ── Query Helpers ────────────────────────────────────────

    async def get_domain_graph(self, domain: str, depth: int = 2) -> dict:
        """Return the subgraph around a domain up to N hops."""
        query = """
        MATCH path = (d:Domain {name: $domain})-[*1..$depth]-(connected)
        WITH nodes(path) AS ns, relationships(path) AS rs
        UNWIND ns AS n
        WITH COLLECT(DISTINCT n) AS nodes, rs
        UNWIND rs AS r
        RETURN nodes, COLLECT(DISTINCT r) AS relationships
        """
        records = await GraphDB.execute(query, {"domain": domain, "depth": depth})
        return self._format_graph_response(records)

    async def get_full_graph(self, limit: int = 500) -> dict:
        """Return the entire investigation graph (limited)."""
        query = """
        MATCH (n)
        OPTIONAL MATCH (n)-[r]-(m)
        WITH n, r, m
        LIMIT $limit
        RETURN COLLECT(DISTINCT n) AS nodes, COLLECT(DISTINCT r) AS relationships
        """
        records = await GraphDB.execute(query, {"limit": limit})
        return self._format_graph_response(records)

    async def get_related_by_cert(self, domain: str) -> list[str]:
        """Find domains sharing the same TLS certificate."""
        query = """
        MATCH (d:Domain {name: $domain})-[:USES_CERTIFICATE]->(c:Certificate)<-[:USES_CERTIFICATE]-(other:Domain)
        WHERE other.name <> $domain
        RETURN other.name AS domain
        """
        records = await GraphDB.execute(query, {"domain": domain})
        return [r["domain"] for r in records]

    async def get_related_by_favicon(self, domain: str) -> list[str]:
        query = """
        MATCH (d:Domain {name: $domain})-[:SHARES_FAVICON]->(f:FaviconHash)<-[:SHARES_FAVICON]-(other:Domain)
        WHERE other.name <> $domain
        RETURN other.name AS domain
        """
        records = await GraphDB.execute(query, {"domain": domain})
        return [r["domain"] for r in records]

    async def get_related_by_html(self, domain: str) -> list[str]:
        query = """
        MATCH (d:Domain {name: $domain})-[:SIMILAR_HTML]->(h:HTMLFingerprint)<-[:SIMILAR_HTML]-(other:Domain)
        WHERE other.name <> $domain
        RETURN other.name AS domain
        """
        records = await GraphDB.execute(query, {"domain": domain})
        return [r["domain"] for r in records]

    async def get_graph_stats(self) -> dict:
        """Return counts of all node and relationship types."""
        query = """
        CALL {
            MATCH (n) RETURN labels(n)[0] AS label, count(n) AS cnt
        }
        RETURN label, cnt ORDER BY cnt DESC
        """
        records = await GraphDB.execute(query)
        return {r["label"]: r["cnt"] for r in records}

    def _format_graph_response(self, records: list) -> dict:
        """Convert Neo4j records to frontend-friendly graph format."""
        nodes = []
        edges = []
        seen_nodes = set()
        seen_edges = set()

        for record in records:
            for node in record.get("nodes", []):
                if isinstance(node, dict):
                    nid = str(node.get("name", node.get("address", node.get(
                        "fingerprint", node.get("hash", node.get("number", node.get("id", "")))
                    ))))
                    if nid and nid not in seen_nodes:
                        seen_nodes.add(nid)
                        nodes.append({
                            "id": nid,
                            "label": nid[:40],
                            "type": "Unknown",
                            "properties": node,
                        })

        return {"nodes": nodes, "edges": edges}
