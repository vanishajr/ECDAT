"""Person-1 ownership. CIR is the source of truth for all downstream stages.

Pure stdlib-only mapping layer mirroring cir.schema.json (CIR v0.1).
Frozen dataclasses with from_dict/to_dict only. No business logic and
no validation here — validation lives in cir_validate.py, canonical JSON
bytes live in api.py (Person-2). Never store raw key material.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field


def new_asset_id(
    canonical: str,
    key_size: int | None = None,
    mode: str | None = None,
    curve: str | None = None,
    protocol: str | None = None,
) -> str:
    """Deterministic asset id: ast:<blake2s-8B hex> over canonical|key_size|mode|curve|protocol."""
    material = "|".join(
        [
            canonical or "",
            str(key_size) if key_size is not None else "",
            mode or "",
            curve or "",
            protocol or "",
        ]
    ).encode("utf-8")
    return "ast:" + hashlib.blake2s(material, digest_size=8).hexdigest()


def new_operation_id(
    operation_type: str,
    asset_id: str,
    function: str | None = None,
    location: str | None = None,
) -> str:
    """Deterministic operation id: op:<blake2s-8B hex> over operation_type|asset_id|function|location."""
    material = "|".join(
        [
            operation_type or "",
            asset_id or "",
            function or "",
            location or "",
        ]
    ).encode("utf-8")
    return "op:" + hashlib.blake2s(material, digest_size=8).hexdigest()


def new_scan_id() -> str:
    """Random scan id: scan:<blake2s-8B hex> over 16 random bytes (hashlib only for id shaping)."""
    return "scan:" + hashlib.blake2s(secrets.token_bytes(16), digest_size=8).hexdigest()


@dataclass(frozen=True)
class EvidenceSignal:
    tool: str
    detail: str
    confidence: float | None = None
    snippet: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> EvidenceSignal:
        return cls(
            tool=d["tool"],
            detail=d["detail"],
            confidence=d.get("confidence"),
            snippet=d.get("snippet"),
        )

    def to_dict(self) -> dict:
        out: dict = {"tool": self.tool, "detail": self.detail}
        if self.confidence is not None:
            out["confidence"] = self.confidence
        if self.snippet is not None:
            out["snippet"] = self.snippet
        return out


@dataclass(frozen=True)
class Location:
    file: str | None = None
    line: int | None = None
    column: int | None = None
    function: str | None = None
    uri: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> Location:
        return cls(
            file=d.get("file"),
            line=d.get("line"),
            column=d.get("column"),
            function=d.get("function"),
            uri=d.get("uri"),
        )

    def to_dict(self) -> dict:
        out: dict = {}
        if self.file is not None:
            out["file"] = self.file
        if self.line is not None:
            out["line"] = self.line
        if self.column is not None:
            out["column"] = self.column
        if self.function is not None:
            out["function"] = self.function
        if self.uri is not None:
            out["uri"] = self.uri
        return out


@dataclass(frozen=True)
class Implementation:
    library: str
    version: str | None = None
    provider: str | None = None
    api: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> Implementation:
        return cls(
            library=d["library"],
            version=d.get("version"),
            provider=d.get("provider"),
            api=d.get("api"),
        )

    def to_dict(self) -> dict:
        out: dict = {"library": self.library}
        if self.version is not None:
            out["version"] = self.version
        if self.provider is not None:
            out["provider"] = self.provider
        if self.api is not None:
            out["api"] = self.api
        return out


@dataclass(frozen=True)
class Context:
    exposure: str
    environment: str | None = None
    data_classification: str | None = None
    notes: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> Context:
        return cls(
            exposure=d["exposure"],
            environment=d.get("environment"),
            data_classification=d.get("data_classification"),
            notes=d.get("notes"),
        )

    def to_dict(self) -> dict:
        out: dict = {"exposure": self.exposure}
        if self.environment is not None:
            out["environment"] = self.environment
        if self.data_classification is not None:
            out["data_classification"] = self.data_classification
        if self.notes is not None:
            out["notes"] = self.notes
        return out


@dataclass(frozen=True)
class RiskInputs:
    usage_state: str
    exposure: str | None = None
    sensitive_data: bool | None = None
    external_dependency: bool | None = None

    @classmethod
    def from_dict(cls, d: dict) -> RiskInputs:
        return cls(
            usage_state=d["usage_state"],
            exposure=d.get("exposure"),
            sensitive_data=d.get("sensitive_data"),
            external_dependency=d.get("external_dependency"),
        )

    def to_dict(self) -> dict:
        out: dict = {"usage_state": self.usage_state}
        if self.exposure is not None:
            out["exposure"] = self.exposure
        if self.sensitive_data is not None:
            out["sensitive_data"] = self.sensitive_data
        if self.external_dependency is not None:
            out["external_dependency"] = self.external_dependency
        return out


@dataclass(frozen=True)
class CryptoAsset:
    asset_id: str
    canonical: str
    usage_state: str
    confidence: float
    evidence: list[EvidenceSignal] = field(default_factory=list)
    original: str | None = None
    key_size: int | None = None
    mode: str | None = None
    curve: str | None = None
    protocol: str | None = None
    library: str | None = None
    location: Location | None = None
    implementation: Implementation | None = None
    context: Context | None = None
    risk_inputs: RiskInputs | None = None

    @classmethod
    def from_dict(cls, d: dict) -> CryptoAsset:
        return cls(
            asset_id=d["asset_id"],
            canonical=d["canonical"],
            usage_state=d["usage_state"],
            confidence=d["confidence"],
            evidence=[EvidenceSignal.from_dict(e) for e in d.get("evidence", [])],
            original=d.get("original"),
            key_size=d.get("key_size"),
            mode=d.get("mode"),
            curve=d.get("curve"),
            protocol=d.get("protocol"),
            library=d.get("library"),
            location=Location.from_dict(d["location"]) if d.get("location") is not None else None,
            implementation=Implementation.from_dict(d["implementation"])
            if d.get("implementation") is not None
            else None,
            context=Context.from_dict(d["context"]) if d.get("context") is not None else None,
            risk_inputs=RiskInputs.from_dict(d["risk_inputs"])
            if d.get("risk_inputs") is not None
            else None,
        )

    def to_dict(self) -> dict:
        out: dict = {
            "asset_id": self.asset_id,
            "canonical": self.canonical,
            "usage_state": self.usage_state,
            "confidence": self.confidence,
            "evidence": [e.to_dict() for e in self.evidence],
        }
        if self.original is not None:
            out["original"] = self.original
        if self.key_size is not None:
            out["key_size"] = self.key_size
        if self.mode is not None:
            out["mode"] = self.mode
        if self.curve is not None:
            out["curve"] = self.curve
        if self.protocol is not None:
            out["protocol"] = self.protocol
        if self.library is not None:
            out["library"] = self.library
        if self.location is not None:
            out["location"] = self.location.to_dict()
        if self.implementation is not None:
            out["implementation"] = self.implementation.to_dict()
        if self.context is not None:
            out["context"] = self.context.to_dict()
        if self.risk_inputs is not None:
            out["risk_inputs"] = self.risk_inputs.to_dict()
        return out


@dataclass(frozen=True)
class CryptoOperation:
    operation_id: str
    operation_type: str
    asset_id: str
    confidence: float
    evidence: list[EvidenceSignal] = field(default_factory=list)
    function: str | None = None
    location: Location | None = None
    implementation: Implementation | None = None
    context: Context | None = None
    risk_inputs: RiskInputs | None = None

    @classmethod
    def from_dict(cls, d: dict) -> CryptoOperation:
        return cls(
            operation_id=d["operation_id"],
            operation_type=d["operation_type"],
            asset_id=d["asset_id"],
            confidence=d["confidence"],
            evidence=[EvidenceSignal.from_dict(e) for e in d.get("evidence", [])],
            function=d.get("function"),
            location=Location.from_dict(d["location"]) if d.get("location") is not None else None,
            implementation=Implementation.from_dict(d["implementation"])
            if d.get("implementation") is not None
            else None,
            context=Context.from_dict(d["context"]) if d.get("context") is not None else None,
            risk_inputs=RiskInputs.from_dict(d["risk_inputs"])
            if d.get("risk_inputs") is not None
            else None,
        )

    def to_dict(self) -> dict:
        out: dict = {
            "operation_id": self.operation_id,
            "operation_type": self.operation_type,
            "asset_id": self.asset_id,
            "confidence": self.confidence,
            "evidence": [e.to_dict() for e in self.evidence],
        }
        if self.function is not None:
            out["function"] = self.function
        if self.location is not None:
            out["location"] = self.location.to_dict()
        if self.implementation is not None:
            out["implementation"] = self.implementation.to_dict()
        if self.context is not None:
            out["context"] = self.context.to_dict()
        if self.risk_inputs is not None:
            out["risk_inputs"] = self.risk_inputs.to_dict()
        return out


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str
    ref: str | None = None
    label: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> GraphNode:
        return cls(
            id=d["id"],
            kind=d["kind"],
            ref=d.get("ref"),
            label=d.get("label"),
        )

    def to_dict(self) -> dict:
        out: dict = {"id": self.id, "kind": self.kind}
        if self.ref is not None:
            out["ref"] = self.ref
        if self.label is not None:
            out["label"] = self.label
        return out


@dataclass(frozen=True)
class GraphEdge:
    from_id: str
    to_id: str
    relationship: str

    @classmethod
    def from_dict(cls, d: dict) -> GraphEdge:
        return cls(
            from_id=d["from"],
            to_id=d["to"],
            relationship=d["relationship"],
        )

    def to_dict(self) -> dict:
        return {"from": self.from_id, "to": self.to_id, "relationship": self.relationship}


@dataclass(frozen=True)
class RiskRecord:
    risk_id: str
    risk_class: str
    title: str
    confidence: float
    asset_id: str | None = None
    operation_id: str | None = None
    score: float | None = None
    description: str | None = None
    rationale: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> RiskRecord:
        return cls(
            risk_id=d["risk_id"],
            risk_class=d["class"],
            title=d["title"],
            confidence=d["confidence"],
            asset_id=d.get("asset_id"),
            operation_id=d.get("operation_id"),
            score=d.get("score"),
            description=d.get("description"),
            rationale=d.get("rationale"),
        )

    def to_dict(self) -> dict:
        out: dict = {
            "risk_id": self.risk_id,
            "class": self.risk_class,
            "title": self.title,
            "confidence": self.confidence,
        }
        if self.asset_id is not None:
            out["asset_id"] = self.asset_id
        if self.operation_id is not None:
            out["operation_id"] = self.operation_id
        if self.score is not None:
            out["score"] = self.score
        if self.description is not None:
            out["description"] = self.description
        if self.rationale is not None:
            out["rationale"] = self.rationale
        return out


@dataclass(frozen=True)
class Recommendation:
    recommendation_id: str
    title: str
    description: str | None = None
    priority: str | None = None
    asset_ids: list[str] = field(default_factory=list)
    pqc_target: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> Recommendation:
        return cls(
            recommendation_id=d["recommendation_id"],
            title=d["title"],
            description=d.get("description"),
            priority=d.get("priority"),
            asset_ids=list(d.get("asset_ids", [])),
            pqc_target=d.get("pqc_target"),
        )

    def to_dict(self) -> dict:
        out: dict = {"recommendation_id": self.recommendation_id, "title": self.title}
        if self.description is not None:
            out["description"] = self.description
        if self.priority is not None:
            out["priority"] = self.priority
        if self.asset_ids:
            out["asset_ids"] = list(self.asset_ids)
        if self.pqc_target is not None:
            out["pqc_target"] = self.pqc_target
        return out


@dataclass(frozen=True)
class CirDocument:
    cir_version: str
    scan_id: str
    target: str
    started_at: str
    finished_at: str
    tool_versions: dict[str, str] = field(default_factory=dict)
    registry_version: str = ""
    assets: list[CryptoAsset] = field(default_factory=list)
    operations: list[CryptoOperation] = field(default_factory=list)
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    risks: list[RiskRecord] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> CirDocument:
        graph = d.get("graph", {})
        return cls(
            cir_version=d["cir_version"],
            scan_id=d["scan_id"],
            target=d["target"],
            started_at=d["started_at"],
            finished_at=d["finished_at"],
            tool_versions=dict(d.get("tool_versions", {})),
            registry_version=d.get("registry_version", ""),
            assets=[CryptoAsset.from_dict(a) for a in d.get("assets", [])],
            operations=[CryptoOperation.from_dict(o) for o in d.get("operations", [])],
            nodes=[GraphNode.from_dict(n) for n in graph.get("nodes", [])],
            edges=[GraphEdge.from_dict(e) for e in graph.get("edges", [])],
            stats=dict(d.get("stats", {})),
            risks=[RiskRecord.from_dict(r) for r in d.get("risks", [])],
            recommendations=[Recommendation.from_dict(r) for r in d.get("recommendations", [])],
        )

    def to_dict(self) -> dict:
        out: dict = {
            "cir_version": self.cir_version,
            "scan_id": self.scan_id,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "tool_versions": dict(self.tool_versions),
            "registry_version": self.registry_version,
            "assets": [a.to_dict() for a in self.assets],
            "operations": [o.to_dict() for o in self.operations],
            "graph": {
                "nodes": [n.to_dict() for n in self.nodes],
                "edges": [e.to_dict() for e in self.edges],
            },
            "stats": dict(self.stats),
        }
        if self.risks:
            out["risks"] = [r.to_dict() for r in self.risks]
        if self.recommendations:
            out["recommendations"] = [r.to_dict() for r in self.recommendations]
        return out
