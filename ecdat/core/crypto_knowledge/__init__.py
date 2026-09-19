"""Phase 8: unified cryptographic knowledge (additive, read-only).

Single import surface for algorithm identity (canonical model), shared
fingerprint constants (Phase 5, consumable by source + binary scanners),
per-library API notes, and policy notes. Seeds from the existing
registries (:mod:`ecdat.core.registry`,
:mod:`ecdat.core.signature_registry`, ``EVP_CIPHER_TABLE``) so scanners
keep working unchanged; this package only *unifies lookups*.
"""

from __future__ import annotations

from ecdat.core.crypto_knowledge.registry import (
    REGISTRY_VERSION,
    AlgorithmRecord,
    CryptoKnowledgeRegistry,
    canonicalize,
    default_registry,
    get_algorithm_info,
    is_deprecated,
    lookup_algorithm,
)
from ecdat.core.crypto_knowledge.constants import (
    FINGERPRINT_CONSTANTS,
    FINGERPRINT_OID_STRINGS,
    FINGERPRINT_OIDS,
    FINGERPRINT_STRINGS,
    FINGERPRINT_SYMBOLS,
    fingerprint_prefilter_hit,
    is_crypto_prefilter_hit,
)

__all__ = [
    "REGISTRY_VERSION",
    "AlgorithmRecord",
    "CryptoKnowledgeRegistry",
    "canonicalize",
    "default_registry",
    "get_algorithm_info",
    "is_deprecated",
    "lookup_algorithm",
    "FINGERPRINT_CONSTANTS",
    "FINGERPRINT_OID_STRINGS",
    "FINGERPRINT_OIDS",
    "FINGERPRINT_STRINGS",
    "FINGERPRINT_SYMBOLS",
    "fingerprint_prefilter_hit",
    "is_crypto_prefilter_hit",
]
