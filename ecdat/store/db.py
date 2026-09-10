"""SQLite connection + v1 schema (Person 3 platform layer).

stdlib sqlite3 only — no ORM. WAL mode enabled per architecture.
Tables: scans, findings (+ index on findings(scan_id, severity)).

This module owns DDL only. Row CRUD lives in scans.py / findings.py.
Callers must pass validated canonical docs (see ecdat.core.validate);
no JSON Schema logic lives here.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

__all__ = ["connect", "init_schema", "open_db", "SCHEMA_VERSION"]

SCHEMA_VERSION = 1

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


def init_schema(conn: sqlite3.Connection) -> None:
    """Create v1 tables + index. Idempotent; safe to call on every open."""
    conn.executescript(_SCHEMA_SQL)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION};")
    conn.commit()


def open_db(path: str | Path | None = None) -> sqlite3.Connection:
    """Connect + init_schema in one call. Main entry point for the app."""
    conn = connect(path)
    init_schema(conn)
    return conn
