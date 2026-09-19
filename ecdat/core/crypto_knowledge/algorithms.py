"""Algorithm seed table for the unified knowledge registry (Phase 8).

Sources (read-only, additive):
- ``ecdat/core/p2_signature_registry.json`` — P2 canonical algorithms,
  aliases, key sizes, curves, categories.
- ``ecdat/core/signature_registry.json`` — P1 alias -> canonical map,
  OID table, weak/deprecated signals, PQC map.
- ``EVP_CIPHER_TABLE`` in ``ecdat/scanners/source/api_knowledge.py`` —
  OpenSSL constructor -> (canonical, key_size, mode).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ecdat.core.crypto_knowledge.registry import AlgorithmRecord

_PRIMITIVE_BY_CATEGORY = {
    "symmetric": "block-cipher",
    "asymmetric": "public-key",
    "key_exchange": "key-exchange",
    "hash": "hash",
    "kdf": "kdf",
    "protocol": "protocol",
    "library": "provider",
    "pqc_kem": "kem",
    "pqc_sig": "signature",
}

_FAMILY_BY_CANONICAL = {
    "AES-128-GCM": "AES", "AES-192-GCM": "AES", "AES-256-GCM": "AES",
    "AES-128-CBC": "AES", "AES-192-CBC": "AES", "AES-256-CBC": "AES",
    "AES-128-ECB": "AES", "AES-256-ECB": "AES",
    "AES-128-CTR": "AES", "AES-256-CTR": "AES",
    "AES-CTR": "AES", "AES-CCM": "AES", "AES-GCM": "AES", "AES": "AES",
    "SHA-224": "SHA-2", "SHA-256": "SHA-2", "SHA-384": "SHA-2",
    "SHA-512": "SHA-2", "SHA-512/224": "SHA-2", "SHA-512/256": "SHA-2",
    "SHA-1": "SHA-1", "MD5": "MD5",
    "SHA-3-256": "SHA-3", "SHA-3-512": "SHA-3",
    "TLS1.2": "TLS", "TLS1.3": "TLS", "TLS": "TLS", "SSL": "TLS",
    "ML-KEM": "ML-KEM", "ML-DSA": "ML-DSA", "SLH-DSA": "SLH-DSA",
    "Falcon": "Falcon",
}

_PQC_SUCCESSORS = {
    "RSA": ("ML-KEM", "ML-DSA"), "ECDSA": ("ML-DSA",),
    "ECDH": ("ML-KEM",), "DH": ("ML-KEM",),
    "DSA": ("ML-DSA",), "Ed25519": ("ML-DSA",),
}

_STANDARDS = {
    "AES-128-GCM": ("NIST FIPS 197",), "AES-256-GCM": ("NIST FIPS 197",),
    "RSA": ("PKCS#1",), "ECDSA": ("FIPS 186-5",),
    "SHA-256": ("FIPS 180-4",), "SHA-512": ("FIPS 180-4",),
    "ML-KEM": ("FIPS 203",), "ML-DSA": ("FIPS 204",),
    "SLH-DSA": ("FIPS 205",),
}


def _load_json(name: str) -> dict[str, Any]:
    try:
        return json.loads(
            (Path(__file__).parent.parent / name).read_text(encoding="utf-8"))
    except Exception:
        return {}


def seed_algorithms() -> list[AlgorithmRecord]:
    """Build canonical records from existing registries + EVP table."""
    p2 = _load_json("p2_signature_registry.json")
    p1 = _load_json("signature_registry.json")
    p1_aliases: dict[str, str] = dict(p1.get("aliases", {}) or {})
    p1_oids: dict[str, str] = dict(p1.get("oids", {}) or {})
    weak_algos = {str(a).upper()
                  for a in (p1.get("weak", {}) or {}).get("algorithms", [])}
    pqc_map: dict[str, str] = dict(p1.get("pqc_map", {}) or {})

    try:
        from ecdat.scanners.source.api_knowledge import (
            EVP_CIPHER_TABLE as _EVP)
    except Exception:
        _EVP = {}

    # Invert P1 OID table: canonical -> [oids].
    oids_by_canonical: dict[str, list[str]] = {}
    for oid, canon in p1_oids.items():
        oids_by_canonical.setdefault(str(canon), []).append(str(oid))
    try:
        from ecdat.scanners.binary.crypto_signatures import (
            CRYPTO_OID_STRINGS as _OID_STRS)
        for oid, canon in dict(_OID_STRS).items():
            oids_by_canonical.setdefault(str(canon), []).append(str(oid))
    except Exception:
        pass

    records: dict[str, AlgorithmRecord] = {}
    for canonical, info in (p2.get("algorithms", {}) or {}).items():
        info = info or {}
        aliases = list(dict.fromkeys(
            [str(a) for a in info.get("aliases", []) if a]))
        for alias, target in p1_aliases.items():
            if target == canonical and alias not in aliases:
                aliases.append(alias)
        key_sizes: list[int] = []
        for key in ("key_sizes",):
            for size in info.get(key, []) or []:
                try:
                    key_sizes.append(int(size))
                except (TypeError, ValueError):
                    continue
        if info.get("key_size") is not None:
            try:
                key_sizes.append(int(info["key_size"]))
            except (TypeError, ValueError):
                pass
        modes: list[str] = []
        if info.get("mode"):
            modes.append(str(info["mode"]))
        category = str(info.get("category", "") or "")
        primitive = _PRIMITIVE_BY_CATEGORY.get(category, category or "other")
        family = _FAMILY_BY_CANONICAL.get(canonical, canonical)
        oids = sorted(set(oids_by_canonical.get(canonical, [])))
        successors = list(_PQC_SUCCESSORS.get(canonical, ()))
        if not successors and canonical in pqc_map:
            successors = [pqc_map[canonical]]
        records[canonical] = AlgorithmRecord(
            canonical=canonical, primitive=primitive, family=family,
            aliases=tuple(aliases), oids=tuple(oids), modes=tuple(modes),
            key_sizes=tuple(sorted(set(key_sizes))),
            deprecated=canonical.upper() in weak_algos,
            standards=tuple(_STANDARDS.get(canonical, ())),
            quantum_safe=canonical in ("ML-KEM", "ML-DSA", "SLH-DSA",
                                       "Falcon"),
            pqc_successors=tuple(successors), category=category,
            metadata={"curves": list(info.get("curves", []) or [])},
        )

    # Fold EVP constructors in as aliases/modes/key_sizes (no new code paths
    # in scanners: the knowledge layer just knows these spellings too).
    for ctor, triple in dict(_EVP).items():
        try:
            canonical, key_size, mode = triple
        except (TypeError, ValueError):
            continue
        rec = records.get(str(canonical))
        if rec is None:
            records[str(canonical)] = AlgorithmRecord(
                canonical=str(canonical), primitive="block-cipher",
                family=str(canonical), aliases=(str(ctor),),
                modes=tuple([str(mode)]) if mode else (),
                key_sizes=tuple([int(key_size)]) if key_size else (),
                category="symmetric")
            continue
        aliases = list(rec.aliases)
        if ctor not in aliases:
            aliases.append(ctor)
        modes = list(rec.modes)
        if mode and mode not in modes:
            modes.append(mode)
        sizes = list(rec.key_sizes)
        if key_size and key_size not in sizes:
            sizes.append(key_size)
        rec.aliases, rec.modes, rec.key_sizes = (
            tuple(aliases), tuple(modes), tuple(sorted(sizes)))

    # Ensure bare P1 canonicals absent from P2 still resolve (e.g. HMAC-SHA256).
    for alias, canonical in p1_aliases.items():
        if canonical not in records:
            records[canonical] = AlgorithmRecord(
                canonical=canonical, primitive="other", family=canonical,
                aliases=(alias,), category="")
        elif alias not in records[canonical].aliases:
            rec = records[canonical]
            rec.aliases = tuple(list(rec.aliases) + [alias])
    return [records[key] for key in sorted(records)]


def get_algorithm_table() -> dict[str, AlgorithmRecord]:
    """Canonical -> record mapping (seeded snapshot)."""
    return {rec.canonical: rec for rec in seed_algorithms()}


def list_canonicals() -> list[str]:
    """Sorted canonical names from the seed table."""
    return sorted(get_algorithm_table())
