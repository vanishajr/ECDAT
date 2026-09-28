"""Idempotent scan persistence shared by CLI/CI (and available to GUI).

Deterministic scan IDs (adapters/normalize.deterministic_scan_id: target +
registry + tool versions + operation IDs + context seed) mean a re-scan of
identical input yields an identical ID. Historically the CLI treated that
``IntegrityError`` as a loud failure (``UNIQUE constraint failed:
scans.id``) while the GUI silently replaced. This module unifies the
semantics both surfaces agreed on:

- unseen scan ID -> insert scan + findings + plan/diagnostics;
- known scan ID + ``replace=False`` -> reuse the stored row (no write);
- known scan ID + ``replace=True`` -> delete (FK cascades to findings +
  scan_meta) and re-insert.

Same scan ID implies same target, registry, tools, findings, and context
(they are all in the ID seed), so reuse never confuses two different
scans. Only timestamps differ, and the stored (first) row wins.
"""

from __future__ import annotations

import sqlite3

from ecdat.store import findings as fstore
from ecdat.store import scans as sstore

__all__ = ["store_scan_result"]


def store_scan_result(
    conn: sqlite3.Connection,
    doc: dict,
    cir: dict | None = None,
    plan: dict | None = None,
    diagnostics: dict | None = None,
    replace: bool = False,
) -> tuple[str, bool]:
    """Persist one validated scan doc. Returns ``(scan_id, reused)``.

    ``reused=True`` means the ID was already stored and the row was left
    untouched. Raises the underlying ``sqlite3.Error`` on genuine write
    failures (never swallowed: persistence errors stay loud).
    """
    from ecdat.store.repository import save_meta as _save_meta

    scan_id = str(doc["scan_id"])
    existing = sstore.get_scan(conn, scan_id)
    if existing is None:
        sstore.insert_scan(conn, doc, cir)
        fstore.insert_findings_for_scan(conn, doc)
        _save_meta(conn, scan_id, plan, diagnostics)
        return scan_id, False
    if replace:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        sstore.insert_scan(conn, doc, cir)
        fstore.insert_findings_for_scan(conn, doc)
        _save_meta(conn, scan_id, plan, diagnostics)
        return scan_id, False
    return scan_id, True
