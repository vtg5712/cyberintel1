"""
CyberIntel Platform — Neo4j Graph Database Integration

Manages connection pool and provides query helpers for the
investigation graph.
"""
import logging
from typing import Optional, Any
from contextlib import asynccontextmanager

from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession

from app.core.config import settings

logger = logging.getLogger("cyberintel.graph")


class GraphDB:
    """Neo4j async driver wrapper."""

    _driver: Optional[AsyncDriver] = None

    @classmethod
    async def connect(cls):
        if cls._driver is None:
            cls._driver = AsyncGraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
                max_connection_pool_size=50,
            )
            logger.info(f"Connected to Neo4j at {settings.NEO4J_URI}")
            await cls._init_schema()

    @classmethod
    async def close(cls):
        if cls._driver:
            await cls._driver.close()
            cls._driver = None
            logger.info("Neo4j connection closed")

    @classmethod
    async def _init_schema(cls):
        """Create constraints and indexes for the investigation graph."""
        constraints = [
            "CREATE CONSTRAINT domain_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
            "CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE",
            "CREATE CONSTRAINT cert_unique IF NOT EXISTS FOR (c:Certificate) REQUIRE c.fingerprint IS UNIQUE",
            "CREATE CONSTRAINT favicon_unique IF NOT EXISTS FOR (f:FaviconHash) REQUIRE f.hash IS UNIQUE",
            "CREATE CONSTRAINT html_fp_unique IF NOT EXISTS FOR (h:HTMLFingerprint) REQUIRE h.hash IS UNIQUE",
            "CREATE CONSTRAINT asn_unique IF NOT EXISTS FOR (a:ASN) REQUIRE a.number IS UNIQUE",
            "CREATE CONSTRAINT registrar_unique IF NOT EXISTS FOR (r:Registrar) REQUIRE r.name IS UNIQUE",
            "CREATE CONSTRAINT campaign_unique IF NOT EXISTS FOR (c:Campaign) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT hosting_unique IF NOT EXISTS FOR (h:HostingProvider) REQUIRE h.name IS UNIQUE",
        ]
        indexes = [
            "CREATE INDEX domain_created IF NOT EXISTS FOR (d:Domain) ON (d.created_date)",
            "CREATE INDEX campaign_detected IF NOT EXISTS FOR (c:Campaign) ON (c.detected_at)",
        ]
        async with cls._driver.session() as session:
            for stmt in constraints + indexes:
                try:
                    await session.run(stmt)
                except Exception as e:
                    logger.warning(f"Schema init: {e}")
        logger.info("Graph schema initialized")

    @classmethod
    @asynccontextmanager
    async def session(cls) -> AsyncSession:
        if cls._driver is None:
            await cls.connect()
        async with cls._driver.session() as session:
            yield session

    @classmethod
    async def execute(cls, query: str, params: Optional[dict] = None) -> list[dict]:
        """Execute a Cypher query and return records as dicts."""
        async with cls.session() as session:
            result = await session.run(query, params or {})
            records = await result.data()
            return records

    @classmethod
    async def execute_write(cls, query: str, params: Optional[dict] = None):
        async with cls.session() as session:
            await session.run(query, params or {})
