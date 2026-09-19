"""Shared fingerprint constants, consumable by source + binary (Phase 5).

Single home for the cheap prefilter signals both scanner families share:
symbol tokens, string tokens, raw byte constants (hex), and OID forms.
Values mirror ``ecdat/scanners/binary/crypto_signatures.py`` (the binary
tables stay authoritative at runtime — these are re-exported here so
source-side pre-scan filtering cannot drift).

Prefilter contract: ``is_crypto_prefilter_hit`` / ``fingerprint_prefilter_hit``
are *inclusion* gates only — a hit means "worth a full scan", a miss means
"no known token present". They never create findings by themselves.
"""

from __future__ import annotations

from typing import Iterable

__all__ = [
    "FINGERPRINT_SYMBOLS",
    "FINGERPRINT_STRINGS",
    "FINGERPRINT_CONSTANTS",
    "FINGERPRINT_OIDS",
    "FINGERPRINT_OID_STRINGS",
    "CRYPTO_PREFILTER_TOKENS",
    "fingerprint_prefilter_hit",
    "is_crypto_prefilter_hit",
    "prefilter_hits",
]


def _load_binary_tables() -> dict[str, dict]:
    try:
        from ecdat.scanners.binary import crypto_signatures as _sig
        return {
            "symbols": dict(getattr(_sig, "CRYPTO_SYMBOLS", {})),
            "strings": dict(getattr(_sig, "CRYPTO_STRINGS", {})),
            "constants": dict(getattr(_sig, "CRYPTO_CONSTANTS", {})),
            "oids": dict(getattr(_sig, "CRYPTO_OIDS", {})),
            "oid_strings": dict(getattr(_sig, "CRYPTO_OID_STRINGS", {})),
        }
    except Exception:
        return {"symbols": {}, "strings": {}, "constants": {},
                "oids": {}, "oid_strings": {}}


_TABLES = _load_binary_tables()

#: Symbol/substring tokens (import names, function fragments).
FINGERPRINT_SYMBOLS: dict[str, str] = dict(_TABLES["symbols"])
#: Decoded-string tokens (algorithm names, mode strings, OIDs-as-text).
FINGERPRINT_STRINGS: dict[str, str] = dict(_TABLES["strings"])
#: Raw byte constants as lowercase hex (S-boxes, IVs, sigma strings).
FINGERPRINT_CONSTANTS: dict[str, str] = dict(_TABLES["constants"])
#: ASN.1 OIDs as DER hex.
FINGERPRINT_OIDS: dict[str, str] = dict(_TABLES["oids"])
#: ASN.1 OIDs in dotted form.
FINGERPRINT_OID_STRINGS: dict[str, str] = dict(_TABLES["oid_strings"])

#: Lowercased union of short tokens for fast substring prefiltering.
CRYPTO_PREFILTER_TOKENS: frozenset[str] = frozenset(
    {str(k).lower() for k in
     list(FINGERPRINT_SYMBOLS) + list(FINGERPRINT_STRINGS)})


def _coerce_text(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="ignore")
    return str(data)


def is_crypto_prefilter_hit(data: bytes | str | None) -> bool:
    """True when any shared fingerprint token appears (case-insensitive)."""
    text = _coerce_text(data).lower()
    if not text:
        return False
    for token in CRYPTO_PREFILTER_TOKENS:
        if token and len(token) >= 3 and token in text:
            return True
    return False


def fingerprint_prefilter_hit(data: bytes | str | None) -> str | None:
    """Return the canonical of the first matching token, else None."""
    text = _coerce_text(data).lower()
    if not text:
        return None
    for token in sorted(CRYPTO_PREFILTER_TOKENS, key=len, reverse=True):
        if token and len(token) >= 3 and token in text:
            for table in (FINGERPRINT_STRINGS, FINGERPRINT_SYMBOLS):
                for key, canonical in table.items():
                    if str(key).lower() == token:
                        return canonical
            return token
    return None


def prefilter_hits(data: bytes | str | None,
                   tokens: Iterable[str] | None = None) -> list[str]:
    """All matching prefilter tokens (bounded, deterministic order)."""
    text = _coerce_text(data).lower()
    wanted = {str(t).lower() for t in tokens} if tokens is not None else None
    hits = [t for t in sorted(CRYPTO_PREFILTER_TOKENS)
            if t and len(t) >= 3 and t in text
            and (wanted is None or t in wanted)]
    return hits[:64]
