"""Person-1 ownership. CIR is the source of truth for all downstream stages.

Stdlib-only accessor for signature_registry.json: alias canonicalization,
OID lookup, library capabilities, weak-asset checks, and PQC targets.
No network, no sqlite, no business logic beyond registry lookup.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

REGISTRY_VERSION = "2026.09.11"

_REGISTRY_PATH = Path(__file__).with_name("signature_registry.json")


@lru_cache(maxsize=1)
def load_registry() -> dict:
    """Load and cache the versioned signature registry JSON."""
    with open(_REGISTRY_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _normalize(name: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "", name.upper())


def canonicalize(name: str) -> str:
    """Map an observed algorithm name to its canonical form.

    Case/separator-insensitive alias lookup; falls back to an
    upper-normalized form (stripped, internal whitespace/underscores to
    dashes, uppercased) for unknown names.
    """
    registry = load_registry()
    aliases: dict = registry.get("aliases", {})
    if name in aliases:
        return aliases[name]
    norm = _normalize(name)
    for alias_key, canonical in aliases.items():
        if _normalize(alias_key) == norm:
            return canonical
    fallback = re.sub(r"[\s_]+", "-", name.strip()).upper()
    return fallback


def lookup_oid(oid: str) -> str | None:
    """Return the canonical name for an OID string, or None if unknown."""
    registry = load_registry()
    oids: dict = registry.get("oids", {})
    return oids.get(oid)


def library_capabilities(library: str) -> list[str]:
    """Return capability list for a library name (exact key, else empty list)."""
    registry = load_registry()
    libraries: dict = registry.get("libraries", {})
    entry = libraries.get(library)
    if isinstance(entry, Mapping):
        caps = entry.get("capabilities", [])
        return list(caps)
    return []


def is_weak_asset(
    canonical: str,
    mode: str | None = None,
    key_size: int | None = None,
) -> bool:
    """Check weak algorithms, weak modes, and short RSA keys per registry."""
    registry = load_registry()
    weak: dict = registry.get("weak", {})
    weak_algos = {str(a).upper() for a in weak.get("algorithms", [])}
    weak_modes = {str(m).upper() for m in weak.get("modes", [])}
    min_rsa = weak.get("min_rsa", 2048)

    if canonical.upper() in weak_algos:
        return True
    # Canonical names like AES-ECB embed the mode; also check explicit mode.
    for token in (mode, canonical):
        if token and token.upper() in weak_modes:
            return True
        if token and "ECB" in _normalize(token):
            return True
    if canonical.upper() == "RSA" and key_size is not None:
        try:
            if int(key_size) < int(min_rsa):
                return True
        except (TypeError, ValueError):
            pass
    return False


def pqc_targets_for(asset: Any) -> list[str]:
    """Return PQC migration target(s) for an asset (dict, model, or name string)."""
    registry = load_registry()
    pqc_map: dict = registry.get("pqc_map", {})

    canonical: str | None = None
    extra_keys: list[str] = []
    if isinstance(asset, str):
        canonical = asset
    elif isinstance(asset, Mapping):
        canonical = asset.get("canonical") or asset.get("algorithm")
        for k in ("operation_type", "protocol", "mode", "curve"):
            v = asset.get(k)
            if v:
                extra_keys.append(str(v))
    else:
        canonical = getattr(asset, "canonical", None)
        for attr in ("operation_type", "protocol", "mode", "curve"):
            v = getattr(asset, attr, None)
            if v:
                extra_keys.append(str(v))

    if not canonical:
        return []
    candidates = [canonical, canonicalize(canonical), canonical.upper()]
    candidates.extend(extra_keys)
    targets: list[str] = []
    for key in candidates:
        hit = pqc_map.get(key)
        if hit and hit not in targets:
            targets.append(hit)
    # Generic fallbacks for RSA/EC families keyed by category suffix.
    upper = canonical.upper()
    if not targets:
        if upper == "RSA":
            for k in ("RSA-encryption", "RSA-signature"):
                if k in pqc_map and pqc_map[k] not in targets:
                    targets.append(pqc_map[k])
    return targets
