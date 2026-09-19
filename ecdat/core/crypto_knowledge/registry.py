"""Canonical algorithm model + unified registry (Phase 8, additive).

Wraps — never replaces — the existing registries. The canonical model
carries identity (canonical/primitive/family/variant/aliases), encodings
(OIDs), parameters (modes/key_sizes/strengths), lifecycle (deprecated/
standards), and quantum posture (quantum_safe/pqc_successors).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Iterable

REGISTRY_VERSION = "2026.09.11"


def _norm(name: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "", str(name or "").upper())


@dataclass
class AlgorithmRecord:
    """One canonical algorithm entry."""

    canonical: str
    primitive: str = ""
    family: str = ""
    variant: str | None = None
    aliases: tuple[str, ...] = ()
    oids: tuple[str, ...] = ()
    modes: tuple[str, ...] = ()
    key_sizes: tuple[int, ...] = ()
    strengths: tuple[int, ...] = ()
    deprecated: bool = False
    standards: tuple[str, ...] = ()
    quantum_safe: bool = False
    pqc_successors: tuple[str, ...] = ()
    category: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class CryptoKnowledgeRegistry:
    """In-memory canonical registry with alias/OID lookup."""

    def __init__(self, records: Iterable[AlgorithmRecord] | None = None) -> None:
        self._records: dict[str, AlgorithmRecord] = {}
        self._alias_index: dict[str, str] = {}
        self._oid_index: dict[str, str] = {}
        for record in records or ():
            self.register(record)

    def register(self, record: AlgorithmRecord) -> None:
        """Add (or replace) one canonical record + its indexes."""
        self._records[record.canonical] = record
        for alias in (record.canonical, *record.aliases):
            key = _norm(alias)
            if key and key not in self._alias_index:
                self._alias_index[key] = record.canonical
            if alias not in self._alias_index:
                # Exact-form fallback for short names (e.g. "DH").
                self._alias_index.setdefault(alias, record.canonical)
        for oid in record.oids:
            self._oid_index[str(oid).strip()] = record.canonical

    def lookup(self, name: str) -> AlgorithmRecord | None:
        """Return the record for an alias/canonical/OID, or None."""
        if not name:
            return None
        text = str(name).strip()
        if text in self._records:
            return self._records[text]
        if text in self._oid_index:
            return self._records.get(self._oid_index[text])
        if text in self._alias_index:
            return self._records.get(self._alias_index[text])
        hit = self._alias_index.get(_norm(text))
        return self._records.get(hit) if hit else None

    def canonicalize(self, name: str) -> str:
        """Map an observed name to canonical form (unknown -> stripped input)."""
        hit = self.lookup(name)
        return hit.canonical if hit else str(name or "").strip()

    def get(self, canonical: str) -> AlgorithmRecord | None:
        """Exact canonical fetch (None when unknown)."""
        return self._records.get(str(canonical or ""))

    def all_canonicals(self) -> list[str]:
        """Sorted canonical names (deterministic)."""
        return sorted(self._records)

    def is_deprecated(self, name: str) -> bool:
        """True when the resolved record is marked deprecated."""
        hit = self.lookup(name)
        return bool(hit and hit.deprecated)

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly snapshot (version + records)."""
        return {
            "version": REGISTRY_VERSION,
            "algorithms": {
                name: {
                    "canonical": rec.canonical,
                    "primitive": rec.primitive,
                    "family": rec.family,
                    "variant": rec.variant,
                    "aliases": list(rec.aliases),
                    "oids": list(rec.oids),
                    "modes": list(rec.modes),
                    "key_sizes": list(rec.key_sizes),
                    "strengths": list(rec.strengths),
                    "deprecated": rec.deprecated,
                    "standards": list(rec.standards),
                    "quantum_safe": rec.quantum_safe,
                    "pqc_successors": list(rec.pqc_successors),
                    "category": rec.category,
                }
                for name, rec in sorted(self._records.items())
            },
        }


@lru_cache(maxsize=1)
def default_registry() -> CryptoKnowledgeRegistry:
    """Process-wide unified registry (seeded once, read-only afterwards)."""
    from ecdat.core.crypto_knowledge.algorithms import seed_algorithms
    return CryptoKnowledgeRegistry(seed_algorithms())


def lookup_algorithm(name: str) -> AlgorithmRecord | None:
    """Scanner-safe lookup: canonical record or None (never raises)."""
    try:
        return default_registry().lookup(name)
    except Exception:
        return None


def canonicalize(name: str) -> str:
    """Scanner-safe canonicalization (unknown -> stripped input)."""
    try:
        return default_registry().canonicalize(name)
    except Exception:
        return str(name or "").strip()


def get_algorithm_info(canonical: str) -> dict[str, Any] | None:
    """Scanner-safe info dict (None when unknown)."""
    rec = lookup_algorithm(canonical)
    if rec is None:
        return None
    return {
        "canonical": rec.canonical,
        "primitive": rec.primitive,
        "family": rec.family,
        "variant": rec.variant,
        "aliases": list(rec.aliases),
        "oids": list(rec.oids),
        "modes": list(rec.modes),
        "key_sizes": list(rec.key_sizes),
        "strengths": list(rec.strengths),
        "deprecated": rec.deprecated,
        "standards": list(rec.standards),
        "quantum_safe": rec.quantum_safe,
        "pqc_successors": list(rec.pqc_successors),
        "category": rec.category,
    }


def is_deprecated(name: str) -> bool:
    """Scanner-safe deprecation check (False when unknown)."""
    try:
        return default_registry().is_deprecated(name)
    except Exception:
        return False
