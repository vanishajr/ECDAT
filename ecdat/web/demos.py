"""Bundled demo inputs for the GUI (judge-friendly one-click scans).

Each demo is a directory under :data:`DEMOS_DIR` with a ``meta.json``
``{id, name, description, language, snippet_file}``. Snippet text is
served so the GUI paste-box can preview/edit a demo before analysis.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEMOS_DIR = Path(__file__).resolve().parent / "demos"

_FALLBACK = {
    "openssl_aes_gcm": {
        "name": "OpenSSL AES-256-GCM",
        "description": "Modern AEAD encryption via OpenSSL EVP.",
        "language": "c",
        "snippet_file": "aes_gcm_openssl.c",
    },
    "weak_hash_ecb": {
        "name": "Legacy MD5 / SHA-1 / AES-ECB",
        "description": "Deprecated hashes plus ECB misuse.",
        "language": "c",
        "snippet_file": "weak_hash_ecb.c",
    },
    "custom_aes": {
        "name": "Custom AES implementation",
        "description": "From-scratch AES (sbox/Rcon) with a caller.",
        "language": "c",
        "snippet_file": "main.c",
    },
    "legacy_tls": {
        "name": "Legacy TLS 1.0 (nginx)",
        "description": "Insecure protocol enabled in configuration.",
        "language": "nginx",
        "snippet_file": "nginx.conf",
    },
}

__all__ = ["DEMOS_DIR", "list_demos", "get_demo", "demo_snippet"]


def _meta(demo_id: str, directory: Path) -> dict[str, Any]:
    fallback = _FALLBACK.get(demo_id, {})
    try:
        raw = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return {**fallback, **raw, "id": demo_id}
    except OSError:
        pass
    return {"id": demo_id, **fallback}


def list_demos() -> list[dict[str, Any]]:
    """Metadata + snippet text for every bundled demo (sorted by id)."""
    if not DEMOS_DIR.is_dir():
        return []
    demos: list[dict[str, Any]] = []
    for directory in sorted(p for p in DEMOS_DIR.iterdir() if p.is_dir()):
        meta = _meta(directory.name, directory)
        meta["files"] = sorted(
            p.name for p in directory.iterdir()
            if p.is_file() and p.name != "meta.json")
        meta["code"] = demo_snippet(directory.name)
        demos.append(meta)
    return demos


def get_demo(demo_id: str) -> tuple[Path, dict[str, Any]]:
    """Return (directory, metadata) or raise KeyError/ValueError."""
    cleaned = str(demo_id or "").strip()
    if not cleaned or cleaned != Path(cleaned).name:
        raise ValueError("unknown demo")
    directory = DEMOS_DIR / cleaned
    if not directory.is_dir():
        raise ValueError("unknown demo")
    return directory, _meta(cleaned, directory)


def demo_snippet(demo_id: str) -> str:
    """Editable snippet text for a demo (its main file, capped)."""
    try:
        directory, meta = get_demo(demo_id)
    except (KeyError, ValueError):
        return ""
    snippet = str(meta.get("snippet_file") or "")
    candidates = [directory / snippet] if snippet else []
    candidates += sorted(p for p in directory.iterdir()
                         if p.is_file() and p.name != "meta.json")
    for path in candidates:
        try:
            if path.stat().st_size > 128 * 1024:
                continue
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return ""
