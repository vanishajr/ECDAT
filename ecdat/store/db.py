"""SQLite connection + schema (Person 3 platform layer).

stdlib sqlite3 only — no ORM. WAL mode enabled per architecture.
Tables: scans, findings (+ index on findings(scan_id, severity)).

Schema versions:
  v1: scans(id, target, started_at, finished_at, raw_json, created_at)
      + findings (+ severity index).
  v2: adds scans.cir_json (nullable TEXT). NULL means a mock/legacy
      scan with no CIR sidecar; non-NULL is the full enriched CIR JSON
      for a real (P2/P1) scan stored under the same scan ID.

No second normalized asset/operation model: the canonical document
stays the queryable index and the CIR sidecar preserves full fidelity
(risk, recommendations, graph, evidence) for the GUI providers.

This module owns DDL only. Row CRUD lives in scans.py / findings.py.
Callers must pass validated canonical docs (see ecdat.core.validate);
no JSON Schema logic lives here.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

__all__ = ["connect", "init_schema", "open_db", "SCHEMA_VERSION"]

SCHEMA_VERSION = 2

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    title TEXT NOT NULL,
    confidence REAL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_scan_severity
    ON findings(scan_id, severity);
"""

_MIGRATIONS = {
    # version -> SQL applied when stored user_version is lower.
    2: "ALTER TABLE scans ADD COLUMN cir_json TEXT",
}


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Open a SQLite connection with FK enforcement and WAL mode.

    path=None (or ":memory:") gives a private in-memory DB for tests.
    WAL is requested best-effort: :memory: DBs report "memory" and
    ignore it, file DBs switch to "wal".
    """
    name = ":memory:" if path is None else str(path)
    conn = sqlite3.connect(name)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def _stored_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("PRAGMA user_version;").fetchone()
    try:
        return int(row[0])
    except (TypeError, ValueError, IndexError):
        return 0


def init_schema(conn: sqlite3.Connection) -> None:
    """Create tables + index, then apply additive migrations. Idempotent."""
    conn.executescript(_SCHEMA_SQL)
    stored = _stored_version(conn)
    for version in sorted(_MIGRATIONS):
        if stored < version:
            try:
                conn.execute(_MIGRATIONS[version])
            except sqlite3.OperationalError as exc:
                # ADD COLUMN is not idempotent on its own; a repeated run
                # against an already-migrated DB reports "duplicate column
                # name", which is the desired end state, not a failure.
                if "duplicate column name" not in str(exc).lower():
                    raise
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION};")
    conn.commit()


def open_db(path: str | Path | None = None) -> sqlite3.Connection:
    """Connect + init_schema in one call. Main entry point for the app."""
    conn = connect(path)
    init_schema(conn)
    return conn
