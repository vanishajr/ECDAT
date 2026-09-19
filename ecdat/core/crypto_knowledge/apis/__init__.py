"""Per-library API tables (Phase 8 note + thin helpers).

Authoritative call tables live in
:mod:`ecdat.scanners.source.api_knowledge` (registry-driven rows consumed
by the brace-language routers) and the Python pattern maps in
:mod:`ecdat.scanners.source.scanner`. This subpackage intentionally holds
no duplicate table: it only documents ownership and offers lookup helpers
so future libraries are added in exactly one place.
"""

from __future__ import annotations

__all__ = ["api_rows_for", "libraries", "API_TABLE_OWNERS"]

#: Where each library's observable API rows are defined (single source).
API_TABLE_OWNERS: dict[str, str] = {
    "openssl": "ecdat.scanners.source.api_knowledge:API_PATTERNS",
    "libsodium": "ecdat.scanners.source.api_knowledge:API_PATTERNS",
    "jca": "ecdat.scanners.source.api_knowledge:API_PATTERNS",
    "node-crypto": "ecdat.scanners.source.api_knowledge:API_PATTERNS",
    "webcrypto": "ecdat.scanners.source.api_knowledge:API_PATTERNS",
    "go-crypto": "ecdat.scanners.source.api_knowledge:API_PATTERNS",
    "dotnet": "ecdat.scanners.source.api_knowledge:API_PATTERNS",
    "rustcrypto": "ecdat.scanners.source.api_knowledge:API_PATTERNS",
    "python": "ecdat.scanners.source.scanner:PYTHON_CRYPTO_PATTERNS",
}


def api_rows_for(library: str) -> list[dict]:
    """Return knowledge rows whose ``library`` matches (case-insensitive)."""
    try:
        from ecdat.scanners.source.api_knowledge import API_PATTERNS
    except Exception:
        return []
    wanted = str(library or "").strip().lower()
    return [row for row in API_PATTERNS
            if str(row.get("library", "")).lower() == wanted]


def libraries() -> list[str]:
    """Sorted library names known to the API knowledge tables."""
    try:
        from ecdat.scanners.source.api_knowledge import API_PATTERNS
    except Exception:
        return sorted(API_TABLE_OWNERS)
    return sorted({str(row.get("library", "")) for row in API_PATTERNS
                   if row.get("library")})
