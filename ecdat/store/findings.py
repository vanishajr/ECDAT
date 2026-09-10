"""Finding-row CRUD (Person 3 platform layer).

Consumes validated canonical findings — callers validate the parent
scan doc first. No schema validation here. Queryable columns are a
subset of the canonical finding (snippet/metadata live on in
scans.raw_json, not in this table).
"""

from __future__ import annotations

import sqlite3

__all__ = [
    "insert_finding",
    "insert_findings_for_scan",
    "list_findings",
    "count_findings",
    "count_by_severity",
]


def insert_finding(
    conn: sqlite3.Connection, scan_id: str, finding: dict
) -> int:
    """Insert one finding row. Returns the integer row id."""
    cur = conn.execute(
        "INSERT INTO findings"
        " (scan_id, rule_id, severity, file, line, title, confidence)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            scan_id,
            finding["rule_id"],
            finding["severity"],
            finding["file"],
            finding["line"],
            finding["title"],
            finding.get("confidence"),
        ),
    )
    conn.commit()
    assert cur.lastrowid is not None
    return int(cur.lastrowid)


def insert_findings_for_scan(conn: sqlite3.Connection, doc: dict) -> list[int]:
    """Insert all findings of a validated canonical scan doc. Returns row ids."""
    ids: list[int] = []
    for f in doc["findings"]:
        cur = conn.execute(
            "INSERT INTO findings"
            " (scan_id, rule_id, severity, file, line, title, confidence)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                doc["scan_id"],
                f["rule_id"],
                f["severity"],
                f["file"],
                f["line"],
                f["title"],
                f.get("confidence"),
            ),
        )
        assert cur.lastrowid is not None
        ids.append(int(cur.lastrowid))
    conn.commit()
    return ids


def list_findings(
    conn: sqlite3.Connection, scan_id: str, severity: str | None = None
) -> list[dict]:
    """Findings for a scan, ordered by row id. Optional severity filter."""
    if severity is None:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? AND severity = ? ORDER BY id",
            (scan_id, severity),
        ).fetchall()
    return [dict(r) for r in rows]


def count_findings(
    conn: sqlite3.Connection, scan_id: str, severity: str | None = None
) -> int:
    if severity is None:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM findings WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM findings WHERE scan_id = ? AND severity = ?",
            (scan_id, severity),
        ).fetchone()
    return int(row["n"])


def count_by_severity(conn: sqlite3.Connection, scan_id: str) -> dict[str, int]:
    """Severity -> count for one scan (GROUP BY; served by the index)."""
    rows = conn.execute(
        "SELECT severity, COUNT(*) AS n FROM findings"
        " WHERE scan_id = ? GROUP BY severity",
        (scan_id,),
    ).fetchall()
    return {r["severity"]: int(r["n"]) for r in rows}
