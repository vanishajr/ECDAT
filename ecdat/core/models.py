"""Typed view over the provisional canonical ECDAT v1 document.

PROVISIONAL — mirrors canonical_v1.json pending Person 1 + Person 2
sign-off. No business logic, no validation here (see validate.py).
Pure dataclass mapping: from_dict / to_dict only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class Finding:
    """One cryptographic finding. Required + optional v1 fields only."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    snippet: str = ""
    confidence: float | None = None
    metadata: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            rule_id=d["rule_id"],
            title=d["title"],
            severity=d["severity"],
            file=d["file"],
            line=d["line"],
            snippet=d.get("snippet", ""),
            confidence=d.get("confidence"),
            metadata=dict(d.get("metadata", {})),
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        # Keep output minimal: drop empty optional fields so fixtures
        # round-trip without invented keys.
        if d["snippet"] == "":
            d.pop("snippet")
        if d["confidence"] is None:
            d.pop("confidence")
        if d["metadata"] == {}:
            d.pop("metadata")
        return d


@dataclass(frozen=True)
class Scan:
    """One canonical scan document (top level of canonical_v1.json)."""

    schema_version: str
    scan_id: str
    target: str
    started_at: str
    finished_at: str
    tool_versions: dict
    findings: list[Finding]
    stats: dict

    @classmethod
    def from_dict(cls, d: dict) -> "Scan":
        return cls(
            schema_version=d["schema_version"],
            scan_id=d["scan_id"],
            target=d["target"],
            started_at=d["started_at"],
            finished_at=d["finished_at"],
            tool_versions=dict(d["tool_versions"]),
            findings=[Finding.from_dict(f) for f in d["findings"]],
            stats=dict(d["stats"]),
        )

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "tool_versions": dict(self.tool_versions),
            "findings": [f.to_dict() for f in self.findings],
            "stats": dict(self.stats),
        }
