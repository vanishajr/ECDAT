from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from ecdat.core.cir_models import UsageState

_REGISTRY: dict[str, Any] | None = None
_REGISTRY_LOCK = threading.Lock()
# P3 integration note: P2's registry file is vendored as
# p2_signature_registry.json to avoid colliding with P1's
# signature_registry.json (different schema, same version string).
# P2 scanners canonicalize through this module only.
_REGISTRY_PATH = Path(__file__).parent / "p2_signature_registry.json"


def load_registry() -> dict[str, Any]:
    global _REGISTRY
    if _REGISTRY is not None:
        return _REGISTRY

    with _REGISTRY_LOCK:
        if _REGISTRY is not None:
            return _REGISTRY

        with open(_REGISTRY_PATH) as f:
            _REGISTRY = json.load(f)
        return _REGISTRY


def get_registry_version() -> str:
    reg = load_registry()
    return reg.get("version", "2026.09.11")


def normalize_algorithm(observed: str) -> tuple[str, Optional[str]]:
    """Normalize an observed algorithm name to canonical form.
    Returns (canonical, original).
    """
    reg = load_registry()
    observed_lower = observed.lower()

    for canonical, info in reg.get("algorithms", {}).items():
        aliases = [a.lower() for a in info.get("aliases", [])]
        if observed_lower in aliases or observed_lower == canonical.lower():
            return canonical, observed

    return observed, observed


def get_algorithm_info(canonical: str) -> dict[str, Any] | None:
    reg = load_registry()
    return reg.get("algorithms", {}).get(canonical)


def is_library_only(canonical: str) -> bool:
    info = get_algorithm_info(canonical)
    if info is None:
        return False
    return info.get("category") == "library"


def get_category(canonical: str) -> str | None:
    info = get_algorithm_info(canonical)
    if info is None:
        return None
    return info.get("category")


def get_key_sizes(canonical: str) -> list[int] | None:
    info = get_algorithm_info(canonical)
    if info is None:
        return None
    return info.get("key_sizes") or ([info.get("key_size")] if info.get("key_size") else None)


def get_curves(canonical: str) -> list[str] | None:
    info = get_algorithm_info(canonical)
    if info is None:
        return None
    return info.get("curves")


def get_mode(canonical: str) -> str | None:
    info = get_algorithm_info(canonical)
    if info is None:
        return None
    return info.get("mode")


def infer_usage_state(category: str | None, has_direct_evidence: bool, has_indirect_evidence: bool) -> UsageState:
    # A directly observed *invocation* of a library entry point (e.g.
    # EVP_CIPHER_fetch) is a confirmed operation with an unresolved
    # algorithm — not a mere capability reference. Library-canonical
    # findings only stay ProvidedOnly on indirect evidence.
    if category == "library" and not has_direct_evidence:
        return UsageState.PROVIDED_ONLY

    if has_direct_evidence:
        return UsageState.CONFIRMED
    elif has_indirect_evidence:
        return UsageState.PROBABLE
    else:
        return UsageState.POSSIBLE


def infer_operation_type(category: str | None, detail: str) -> OperationType | None:
    detail_lower = detail.lower()

    if category == "asymmetric":
        if any(kw in detail_lower for kw in ["encrypt", "public_encrypt"]):
            return OperationType.ENCRYPT
        elif any(kw in detail_lower for kw in ["decrypt", "private_decrypt"]):
            return OperationType.DECRYPT
        elif any(kw in detail_lower for kw in ["sign"]):
            return OperationType.SIGN
        elif any(kw in detail_lower for kw in ["verify"]):
            return OperationType.VERIFY
        elif any(kw in detail_lower for kw in ["key_exchange", "ecdh", "dh", "derive"]):
            return OperationType.KEY_EXCHANGE
        return OperationType.KEY_MANAGEMENT

    if category == "symmetric":
        if any(kw in detail_lower for kw in ["encrypt"]):
            return OperationType.ENCRYPT
        elif any(kw in detail_lower for kw in ["decrypt"]):
            return OperationType.DECRYPT
        return OperationType.STORAGE

    if category == "hash":
        return OperationType.HASH

    if category == "kdf":
        return OperationType.KDF

    if category in ("protocol", "library"):
        if any(kw in detail_lower for kw in ["tls", "ssl", "https"]):
            return OperationType.TLS
        if any(kw in detail_lower for kw in ["ssh"]):
            return OperationType.TLS

    if category == "key_exchange":
        return OperationType.KEY_EXCHANGE

    if category in ("pqc_kem", "pqc_sig"):
        if "sign" in detail_lower or "verify" in detail_lower:
            return OperationType.SIGN
        return OperationType.KEY_EXCHANGE

    return None


from ecdat.core.cir_models import OperationType
from typing import Optional