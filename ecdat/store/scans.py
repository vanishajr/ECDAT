"""Scan-row CRUD (Person 3 platform layer).

Consumes validated canonical docs — callers validate with
ecdat.core.validate.validate() first. No schema validation here.
The full canonical document is stored verbatim in scans.raw_json so
future schema evolution never loses the original.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

__all__ = [
    "insert_scan",
    "get_scan",
    "get_scan_doc",
    "get_scan_cir",
    "list_scans",
    "delete_scan",
    "count_scans",
]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def insert_scan(
    conn: sqlite3.Connection, doc: dict, cir: dict | None = None
) -> str:
    """Insert one validated canonical scan doc. Returns its scan id.

    ``cir`` is the enriched CIR sidecar stored under the same scan ID.
    """
    scan_id = doc["scan_id"]
    conn.execute(
        "INSERT INTO scans (id, target, started_at, finished_at, raw_json,"
        " cir_json, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            scan_id,
            doc["target"],
            doc["started_at"],
            doc["finished_at"],
            json.dumps(doc, sort_keys=True),
            json.dumps(cir, sort_keys=True) if cir is not None else None,
            _utcnow(),
        ),
    )
    conn.commit()
    return scan_id


def get_scan(conn: sqlite3.Connection, scan_id: str) -> dict | None:
    """Return the scans row (all columns) as a dict, or None."""
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return dict(row) if row is not None else None


def get_scan_doc(conn: sqlite3.Connection, scan_id: str) -> dict | None:
    """Return the preserved canonical document (parsed raw_json), or None."""
    row = conn.execute(
        "SELECT raw_json FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    return json.loads(row["raw_json"]) if row is not None else None


def get_scan_cir(conn: sqlite3.Connection, scan_id: str) -> dict | None:
    """Return the stored enriched CIR sidecar, or None.

    None means the scan is unknown or predates CIR persistence. Callers
    must not treat None as an empty CIR.
    """
    row = conn.execute(
        "SELECT cir_json FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    if row is None or row["cir_json"] is None:
        return None
    return json.loads(row["cir_json"])


def list_scans(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    """Newest-first scan rows (id, target, timestamps, created_at)."""
    rows = conn.execute(
        "SELECT id, target, started_at, finished_at, created_at"
        " FROM scans ORDER BY created_at DESC, id ASC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def delete_scan(conn: sqlite3.Connection, scan_id: str) -> int:
    """Delete a scan; findings cascade. Returns rows deleted (0/1)."""
    cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    return cur.rowcount


def count_scans(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()
    return int(row["n"])
