"""Policy notes over unified knowledge (Phase 8 note + thin helpers).

Deprecation/weakness signals stay owned by the versioned registries
(``weak`` section of ``signature_registry.json``); this subpackage only
re-exposes them through the canonical model so scanners and risk stages
share one predicate. No policy is invented here.
"""

from __future__ import annotations

__all__ = ["is_weak", "is_deprecated_policy", "POLICY_OWNERS"]

#: Predicate -> owning source (traceability, not logic).
POLICY_OWNERS: dict[str, str] = {
    "is_weak": "ecdat.core.registry:is_weak_asset",
    "is_deprecated": "ecdat.core.crypto_knowledge.registry:is_deprecated",
    "pqc_targets": "ecdat.core.registry:pqc_targets_for",
}


def is_weak(canonical: str, mode: str | None = None,
            key_size: int | None = None) -> bool:
    """Scanner-safe weakness check (False when unknown)."""
    try:
        from ecdat.core.registry import is_weak_asset
        return bool(is_weak_asset(canonical, mode=mode, key_size=key_size))
    except Exception:
        return False


def is_deprecated_policy(name: str) -> bool:
    """Scanner-safe deprecation check via the unified registry."""
    try:
        from ecdat.core.crypto_knowledge.registry import is_deprecated
        return bool(is_deprecated(name))
    except Exception:
        return False
