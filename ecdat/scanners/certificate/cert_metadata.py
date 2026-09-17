"""Secret-safe certificate/key metadata helpers (Phase 5).

Rules: metadata only (fingerprint, type, size, curve, validity,
subject/issuer, path) — never raw private-key material. Fingerprints
identify the SAME key/cert across config references, files, and
endpoints so Phase 9 can link them without ever seeing secrets.
"""

from __future__ import annotations

import base64
import hashlib
import json

__all__ = [
    "sha256_fingerprint_hex",
    "openssh_fingerprint",
    "public_jwk_view",
    "jwk_fingerprint",
    "cert_fingerprint_note",
    "public_key_fingerprint_note",
]

#: JWK members that are safe to record (everything else — d, k, p, q,
#: dp, dq, qi, oth, private parts — is dropped, never stored).
_PUBLIC_JWK_MEMBERS = frozenset(
    {"kty", "crv", "x", "y", "n", "e", "alg", "use", "kid"})


def sha256_fingerprint_hex(data: bytes) -> str:
    """OpenSSL-style ``SHA256:AA:BB:...`` fingerprint (never raises)."""
    try:
        digest = hashlib.sha256(bytes(data or b"")).hexdigest().upper()
        return "SHA256:" + ":".join(
            digest[i:i + 2] for i in range(0, len(digest), 2))
    except Exception:
        return ""


def openssh_fingerprint(blob: bytes) -> str:
    """OpenSSH-style ``SHA256:<base64>`` fingerprint (never raises)."""
    try:
        raw = hashlib.sha256(bytes(blob or b"")).digest()
        return "SHA256:" + base64.b64encode(raw).decode("ascii").rstrip("=")
    except Exception:
        return ""


def public_jwk_view(key: object) -> dict:
    """JWK with private members stripped (never raises, never leaks)."""
    if not isinstance(key, dict):
        return {}
    return {k: v for k, v in key.items() if k in _PUBLIC_JWK_MEMBERS}


def jwk_fingerprint(key: object) -> str:
    """Fingerprint over the PUBLIC JWK view only (never raises)."""
    try:
        view = public_jwk_view(key)
        if not view:
            return ""
        canonical = json.dumps(view, sort_keys=True,
                               separators=(",", ":")).encode("utf-8")
        return sha256_fingerprint_hex(canonical)
    except Exception:
        return ""


def cert_fingerprint_note(cert: object) -> str:
    """``fingerprint=SHA256:..`` for an x509 object (never raises)."""
    try:
        from cryptography.hazmat.primitives import hashes
        raw = cert.fingerprint(hashes.SHA256())  # type: ignore[union-attr]
        fp = sha256_fingerprint_hex(bytes(raw)) if raw else ""
        return f"fingerprint={fp}" if fp else ""
    except Exception:
        return ""


def public_key_fingerprint_note(public_key: object) -> str:
    """``fingerprint=SHA256:..`` for a public-key object (never raises)."""
    try:
        from cryptography.hazmat.primitives import serialization
        raw = public_key.public_bytes(  # type: ignore[union-attr]
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        fp = sha256_fingerprint_hex(raw)
        return f"fingerprint={fp}" if fp else ""
    except Exception:
        return ""
