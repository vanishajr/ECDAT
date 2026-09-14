from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError


class UsageState(str, Enum):
    CONFIRMED = "Confirmed"
    PROBABLE = "Probable"
    POSSIBLE = "Possible"
    PROVIDED_ONLY = "ProvidedOnly"
    FALSE_POSITIVE_SUPPRESSED = "FalsePositiveSuppressed"


class OperationType(str, Enum):
    ENCRYPT = "Encrypt"
    DECRYPT = "Decrypt"
    SIGN = "Sign"
    VERIFY = "Verify"
    KEY_EXCHANGE = "KeyExchange"
    HASH = "Hash"
    KDF = "KDF"
    TLS = "TLS"
    STORAGE = "Storage"
    KEY_MANAGEMENT = "KeyManagement"


class Exposure(str, Enum):
    INTERNET_FACING = "internet-facing"
    INTERNAL = "internal"
    OFFLINE = "offline"
    CLOUD = "cloud"
    THIRD_PARTY = "third-party"


class GraphNodeKind(str, Enum):
    ASSET = "asset"
    OPERATION = "operation"
    FILE = "file"
    SERVICE = "service"
    HOST = "host"
    LIBRARY = "library"
    KEY = "key"


class GraphRelationship(str, Enum):
    USES = "uses"
    CALLS = "calls"
    CONTAINS = "contains"
    DERIVES = "derives"
    PROTECTS = "protects"
    DEPENDS_ON = "depends_on"
    TERMINATES = "terminates"


class EvidenceSignal(BaseModel):
    tool: str = Field(..., min_length=1)
    detail: str = Field(..., min_length=1)
    confidence: Optional[float] = Field(None, ge=0, le=1)
    snippet: Optional[str] = None

    @field_validator("snippet")
    @classmethod
    def redact_snippet(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        redacted = v
        patterns = [
            (r"[A-Za-z0-9+/]{40,}={0,2}", "[REDACTED_BASE64]"),
            (r"-----BEGIN [A-Z ]+-----\n.*?\n-----END [A-Z ]+-----", "[REDACTED_PEM]"),
            (r"(?i)(password|secret|token|key|credential)\s*[:=]\s*\S+", "[REDACTED]"),
            (r"(?i)api[_-]?key\s*[:=]\s*\S+", "[REDACTED]"),
            (r"(?i)private[_-]?key\s*[:=]\s*\S+", "[REDACTED]"),
            (r"ssh-rsa\s+[A-Za-z0-9+/]{20,}={0,2}", "[REDACTED_SSH_KEY]"),
            (r"ssh-ed25519\s+[A-Za-z0-9+/]{20,}={0,2}", "[REDACTED_SSH_KEY]"),
            (r"ssh-ecdsa\s+[A-Za-z0-9+/]{20,}={0,2}", "[REDACTED_SSH_KEY]"),
        ]
        for pattern, replacement in patterns:
            redacted = re.sub(pattern, replacement, redacted, flags=re.DOTALL | re.IGNORECASE)
        return redacted


class Location(BaseModel):
    file: Optional[str] = None
    line: Optional[int] = Field(None, ge=1)
    column: Optional[int] = Field(None, ge=1)
    function: Optional[str] = None
    uri: Optional[str] = None


class Implementation(BaseModel):
    library: str = Field(..., min_length=1)
    version: Optional[str] = None
    provider: Optional[str] = None
    api: Optional[str] = None


class Context(BaseModel):
    exposure: Exposure
    environment: Optional[str] = None
    data_classification: Optional[str] = None
    notes: Optional[str] = None


class RiskInputs(BaseModel):
    usage_state: UsageState
    exposure: Optional[Exposure] = None
    sensitive_data: bool = False
    external_dependency: bool = False


class CryptoAsset(BaseModel):
    asset_id: str = Field(..., pattern=r"^ast:[0-9a-f]{16}$")
    canonical: str = Field(..., min_length=1)
    original: Optional[str] = None
    key_size: Optional[int] = Field(None, ge=1)
    mode: Optional[str] = None
    curve: Optional[str] = None
    protocol: Optional[str] = None
    library: Optional[str] = None
    usage_state: UsageState
    confidence: float = Field(..., ge=0, le=1)
    evidence: list[EvidenceSignal] = Field(default_factory=list)
    location: Optional[Location] = None
    implementation: Optional[Implementation] = None
    context: Optional[Context] = None
    risk_inputs: Optional[RiskInputs] = None


class CryptoOperation(BaseModel):
    operation_id: str = Field(..., pattern=r"^op:[0-9a-f]{16}$")
    operation_type: OperationType
    asset_id: str = Field(..., pattern=r"^ast:[0-9a-f]{16}$")
    confidence: float = Field(..., ge=0, le=1)
    evidence: list[EvidenceSignal] = Field(default_factory=list)
    function: Optional[str] = None
    location: Optional[Location] = None
    implementation: Optional[Implementation] = None
    context: Optional[Context] = None
    risk_inputs: Optional[RiskInputs] = None


class GraphNode(BaseModel):
    id: str = Field(..., min_length=1)
    kind: GraphNodeKind
    label: Optional[str] = None
    ref: Optional[str] = None


class GraphEdge(BaseModel):
    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)
    from_node: str = Field(..., min_length=1, alias="from", serialization_alias="from")
    to: str = Field(..., min_length=1)
    relationship: GraphRelationship


class Graph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class Stats(BaseModel):
    asset_count: int = Field(0, ge=0)
    operation_count: int = Field(0, ge=0)
    node_count: int = Field(0, ge=0)
    edge_count: int = Field(0, ge=0)


class CIRDocument(BaseModel):
    cir_version: str = "0.1"
    scan_id: str = Field(..., pattern=r"^scan:[0-9a-f]{16}$")
    target: str = Field(..., min_length=1)
    started_at: datetime
    finished_at: datetime
    tool_versions: dict[str, str] = Field(default_factory=dict)
    registry_version: str = Field(..., pattern=r"^\d{4}\.\d{2}\.\d{2}$")
    assets: list[CryptoAsset] = Field(default_factory=list)
    operations: list[CryptoOperation] = Field(default_factory=list)
    graph: Graph = Field(default_factory=Graph)
    stats: Stats = Field(default_factory=Stats)
    risks: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="after")
    def update_stats(self) -> CIRDocument:
        self.stats.asset_count = len(self.assets)
        self.stats.operation_count = len(self.operations)
        self.stats.node_count = len(self.graph.nodes)
        self.stats.edge_count = len(self.graph.edges)
        return self


def new_asset_id(canonical: str, key_size: Optional[int] = None, mode: Optional[str] = None,
                 curve: Optional[str] = None, protocol: Optional[str] = None,
                 file: Optional[str] = None, line: Optional[int] = None) -> str:
    parts = [canonical]
    if key_size:
        parts.append(str(key_size))
    if mode:
        parts.append(mode)
    if curve:
        parts.append(curve)
    if protocol:
        parts.append(protocol)
    if file:
        parts.append(file)
    if line:
        parts.append(str(line))
    seed = "|".join(parts)
    hash_val = hashlib.sha256(seed.encode()).hexdigest()[:16]
    return f"ast:{hash_val}"


def new_operation_id(operation_type: OperationType, asset_id: str,
                     function: Optional[str] = None, location: Optional[Location] = None) -> str:
    parts = [operation_type.value, asset_id]
    if function:
        parts.append(function)
    if location and location.file:
        parts.append(location.file)
    if location and location.line:
        parts.append(str(location.line))
    seed = "|".join(parts)
    hash_val = hashlib.sha256(seed.encode()).hexdigest()[:16]
    return f"op:{hash_val}"


def load_cir_json(path: str | Path) -> CIRDocument:
    with open(path) as f:
        data = json.load(f)
    return CIRDocument.model_validate(data)


def validate_cir_json(path: str | Path) -> CIRDocument:
    return load_cir_json(path)