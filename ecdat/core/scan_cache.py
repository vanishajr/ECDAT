"""Phase 13: versioned scan caches + execution budgets (additive, stdlib-only).

Every cache layer carries its producer version in the key so stale rows
can never be mistaken for fresh results:

- parse/fact layer:     content bytes + parser + adapter versions;
- resolution layer:     function facts hash + resolver + registry versions;
- final scan layer:     input hash + scanner versions + registry + risk +
  recommendation + config + schema versions.

:class:`ScanCacheV2` is a small in-memory store with hit/miss accounting
and explicit invalidation when the version vector changes. :func:`check_budget`
enforces wall-clock time budgets; :func:`staged_escalation` encodes the
cheap -> parse -> direct -> dataflow -> fingerprint escalation order.
All helpers are pure (except the clock read in :func:`check_budget`) and
deterministic.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

__all__ = [
    "PARSER_VER",
    "ADAPTER_VER",
    "RESOLVER_VER",
    "REGISTRY_VER",
    "RISK_VER",
    "REC_VER",
    "SCHEMA_VER",
    "ESCALATION_STAGES",
    "parse_cache_key",
    "resolution_cache_key",
    "final_scan_cache_key",
    "ScanCacheV2",
    "check_budget",
    "budget_remaining",
    "staged_escalation",
    "next_stage",
]

PARSER_VER = "facts-v1"
ADAPTER_VER = "adapter-v1"
RESOLVER_VER = "resolver-v1"
REGISTRY_VER = "registry-v1"
RISK_VER = "risk-v1"
REC_VER = "rec-v1"
SCHEMA_VER = "cir-v1"

#: Cheap -> expensive escalation order for source analysis.
ESCALATION_STAGES: tuple[str, ...] = (
    "cheap",
    "parse",
    "direct",
    "dataflow",
    "fingerprint",
)


def _blake16(data: bytes) -> str:
    return hashlib.blake2s(data).hexdigest()[:16]


def _canon(value: Any) -> str:
    """Deterministic canonical rendering for cache-key material."""
    try:
        if isinstance(value, dict):
            items = sorted((str(k), _canon(v)) for k, v in value.items())
            return "{" + ",".join(f"{k}={v}" for k, v in items) + "}"
        if isinstance(value, (list, tuple)):
            return "[" + ",".join(_canon(v) for v in value) + "]"
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)
    except Exception:
        return str(value)


def parse_cache_key(content_hash: str, parser_ver: str = PARSER_VER,
                    adapter_ver: str = ADAPTER_VER) -> str:
    """Key for the parse/fact layer (content + parser + adapter)."""
    try:
        ch = str(content_hash or "")
        pv = str(parser_ver or PARSER_VER)
        av = str(adapter_ver or ADAPTER_VER)
    except Exception:
        ch, pv, av = "", PARSER_VER, ADAPTER_VER
    return f"parse:{ch}:{pv}:{av}"


def resolution_cache_key(func_hash: str,
                         resolver_ver: str = RESOLVER_VER,
                         registry_ver: str = REGISTRY_VER) -> str:
    """Key for the resolver layer (facts hash + resolver + registry)."""
    try:
        fh = str(func_hash or "")
        rv = str(resolver_ver or RESOLVER_VER)
        gv = str(registry_ver or REGISTRY_VER)
    except Exception:
        fh, rv, gv = "", RESOLVER_VER, REGISTRY_VER
    return f"resolve:{fh}:{rv}:{gv}"


def final_scan_cache_key(input_hash: str, scanner_vers: dict | None,
                         registry_ver: str = REGISTRY_VER,
                         risk_ver: str = RISK_VER,
                         rec_ver: str = REC_VER,
                         config: dict | None = None,
                         schema_ver: str = SCHEMA_VER) -> str:
    """Key for the final scan result (input + every producer version).

    ``scanner_vers`` maps scanner name -> version; ordering is
    normalised so dict order never affects the key. ``config`` covers
    profile/escalation flags that change output shape.
    """
    try:
        ih = str(input_hash or "")
        rv = str(registry_ver or REGISTRY_VER)
        kv = str(risk_ver or RISK_VER)
        cv = str(rec_ver or REC_VER)
        sv = str(schema_ver or SCHEMA_VER)
    except Exception:
        ih, rv, kv, cv, sv = "", REGISTRY_VER, RISK_VER, REC_VER, SCHEMA_VER
    try:
        scanners_canon = _canon(dict(scanner_vers or {}))
    except Exception:
        scanners_canon = "{}"
    try:
        config_canon = _canon(dict(config or {}))
    except Exception:
        config_canon = "{}"
    digest = _blake16(
        f"{scanners_canon}|{config_canon}".encode("utf-8"))
    return f"scan:{ih}:{scanners_canon}:{rv}:{kv}:{cv}:{sv}:{digest}"


class ScanCacheV2:
    """Version-aware in-memory cache with hit-rate accounting.

    Keys are namespaced (``namespace:key``). The ``versions`` vector
    records the producer versions active when entries were stored;
    :meth:`invalidate_on_version_change` drops all entries when the
    caller reports a new vector.
    """

    def __init__(self, versions: dict | None = None) -> None:
        try:
            self._versions: dict[str, str] = {
                str(k): str(v) for k, v in dict(versions or {}).items()}
        except Exception:
            self._versions = {}
        self._store: dict[str, Any] = {}
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _slot(namespace: str, key: str) -> str:
        return f"{namespace}:{key}"

    @property
    def versions(self) -> dict[str, str]:
        """Copy of the active version vector."""
        return dict(self._versions)

    @property
    def hit_rate(self) -> float:
        """Fraction of gets that hit (0.0 when nothing requested yet)."""
        total = self._hits + self._misses
        if total == 0:
            return 0.0
        return self._hits / total

    @property
    def stats(self) -> dict[str, int]:
        """Raw hit/miss/entry counters (copy)."""
        return {"hits": self._hits, "misses": self._misses,
                "entries": len(self._store)}

    def get(self, namespace: str, key: str) -> Any | None:
        """Return the cached value or None (counts a miss when absent)."""
        try:
            slot = self._slot(str(namespace), str(key))
        except Exception:
            self._misses += 1
            return None
        if slot in self._store:
            self._hits += 1
            return self._store[slot]
        self._misses += 1
        return None

    def set(self, namespace: str, key: str, value: Any) -> None:
        """Store ``value`` under ``namespace:key``."""
        try:
            slot = self._slot(str(namespace), str(key))
        except Exception:
            return
        self._store[slot] = value

    def invalidate(self) -> int:
        """Drop all entries; return the number dropped."""
        count = len(self._store)
        self._store.clear()
        return count

    def invalidate_on_version_change(self, new_versions: dict | None) -> bool:
        """Drop entries when ``new_versions`` differs; return True if dropped.

        The stored vector is replaced with ``new_versions`` either way so
        subsequent calls compare against the latest vector.
        """
        try:
            incoming = {str(k): str(v)
                        for k, v in dict(new_versions or {}).items()}
        except Exception:
            incoming = {}
        changed = incoming != self._versions
        if changed:
            self._store.clear()
            self._versions = incoming
            return True
        return False

    def __len__(self) -> int:
        return len(self._store)


def budget_remaining(deadline: float | None) -> float | None:
    """Seconds left until ``deadline`` (monotonic clock; None = unbounded)."""
    if deadline is None:
        return None
    try:
        return float(deadline) - time.monotonic()
    except Exception:
        return 0.0


def check_budget(deadline: float | None) -> bool:
    """Return True when work may continue (now < deadline; None = True)."""
    if deadline is None:
        return True
    try:
        return time.monotonic() < float(deadline)
    except Exception:
        return False


def staged_escalation(current: str | None = None) -> str | None:
    """Return the stage after ``current`` (None = first stage).

    Order: cheap -> parse -> direct -> dataflow -> fingerprint.
    Returns None when ``current`` is the last stage (nothing beyond
    fingerprint) or when ``current`` is unknown-but-terminal-safe.
    """
    if current is None:
        return ESCALATION_STAGES[0]
    try:
        label = str(current or "").strip().lower()
    except Exception:
        return None
    for idx, stage in enumerate(ESCALATION_STAGES):
        if stage == label:
            if idx + 1 < len(ESCALATION_STAGES):
                return ESCALATION_STAGES[idx + 1]
            return None
    return None


def next_stage(current: str | None = None) -> str | None:
    """Alias of :func:`staged_escalation` for call-site readability."""
    return staged_escalation(current)
