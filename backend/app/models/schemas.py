"""
CyberIntel Platform — Data Models
"""
from datetime import datetime
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field
import uuid


# ── Enums ──────────────────────────────────────────────────────

class ArtifactType(str, Enum):
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    TLS_FINGERPRINT = "tls_fingerprint"
    EMAIL_DOMAIN = "email_domain"


class InvestigationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AnonymizationModeEnum(str, Enum):
    DIRECT = "direct"
    PROXY_CHAIN = "proxy_chain"
    TOR = "tor"
    CUSTOM = "custom"


# ── Request / Response Schemas ─────────────────────────────────

class ArtifactSubmission(BaseModel):
    type: ArtifactType
    value: str = Field(..., min_length=1, max_length=500)
    investigation_id: Optional[str] = None
    depth: int = Field(default=1, ge=1, le=5)


class ArtifactResponse(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: ArtifactType
    value: str
    status: InvestigationStatus = InvestigationStatus.PENDING
    task_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class InvestigationResult(BaseModel):
    artifact_id: str
    type: ArtifactType
    value: str
    status: InvestigationStatus
    dns: Optional[dict] = None
    whois: Optional[dict] = None
    tls: Optional[dict] = None
    hosting: Optional[dict] = None
    fingerprint: Optional[dict] = None
    relationships: list[dict] = []
    errors: list[str] = []


class GraphNode(BaseModel):
    id: str
    label: str
    type: str
    properties: dict[str, Any] = {}


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    properties: dict[str, Any] = {}
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class GraphData(BaseModel):
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []


class CampaignInfo(BaseModel):
    id: str
    name: str
    domain_count: int
    indicators: list[str] = []
    confidence: float
    detected_at: datetime
    properties: dict[str, Any] = {}


class NetworkConfig(BaseModel):
    mode: AnonymizationModeEnum
    custom_proxy: Optional[str] = None
    proxy_list: list[str] = []
    rate_limit_rps: float = Field(default=2.0, ge=0.1, le=50.0)
    safe_mode: bool = True


class TaskStatus(BaseModel):
    task_id: str
    status: str
    result: Optional[Any] = None
