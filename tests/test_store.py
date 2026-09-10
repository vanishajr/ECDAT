"""Tests for the SQLite store layer (Task 3).

Uses :memory: databases throughout (file-backed only for the WAL check).
Canonical docs come from the Task 1 fixtures, validated before insert —
the store itself performs no JSON Schema validation.
"""

import sqlite3
from pathlib import Path

import pytest

from ecdat.core.validate import load_json, validate
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore

FIXTURES = Path(__file__).parent / "fixtures" / "canonical"


@pytest.fixture()
def conn():
    c = db.open_db(None)  # :memory:
    yield c
    c.close()


def _validated(name: str) -> dict:
    return validate(load_json(FIXTURES / name))


def _store_doc(conn, name: str) -> dict:
    doc = _validated(name)
    sstore.insert_scan(conn, doc)
    fstore.insert_findings_for_scan(conn, doc)
    return doc


# --- initialization -------------------------------------------------------


def test_init_creates_tables_and_index(conn):
    tables = {
        r["name"]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    assert {"scans", "findings"} <= tables
    idx = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index'"
        " AND name = 'idx_findings_scan_severity'"
    ).fetchone()
    assert idx is not None


def test_init_is_idempotent(conn):
    db.init_schema(conn)  # second call must not fail or duplicate
    assert sstore.count_scans(conn) == 0


def test_foreign_keys_enforced(conn):
    row = conn.execute("PRAGMA foreign_keys").fetchone()
    assert row[0] == 1


def test_wal_mode_on_file_db(tmp_path):
    c = db.open_db(tmp_path / "ecdat.db")
    try:
        mode = c.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
    finally:
        c.close()


# --- scans ----------------------------------------------------------------


def test_insert_and_get_scan(conn):
    doc = _validated("minimal.json")
    scan_id = sstore.insert_scan(conn, doc)
    assert scan_id == doc["scan_id"]
    row = sstore.get_scan(conn, scan_id)
    assert row is not None
    assert row["id"] == doc["scan_id"]
    assert row["target"] == doc["target"]
    assert row["started_at"] == doc["started_at"]
    assert row["finished_at"] == doc["finished_at"]
    assert row["created_at"]  # set by the store, not the doc
    assert sstore.count_scans(conn) == 1


def test_get_missing_scan_returns_none(conn):
    assert sstore.get_scan(conn, "nope") is None
    assert sstore.get_scan_doc(conn, "nope") is None


def test_list_scans(conn):
    _store_doc(conn, "minimal.json")
    _store_doc(conn, "empty.json")
    rows = sstore.list_scans(conn)
    assert {r["id"] for r in rows} == {"scan-minimal-001", "scan-empty-001"}
    assert len(sstore.list_scans(conn, limit=1)) == 1


def test_duplicate_scan_id_rejected(conn):
    doc = _validated("minimal.json")
    sstore.insert_scan(conn, doc)
    with pytest.raises(sqlite3.IntegrityError):
        sstore.insert_scan(conn, doc)


# --- findings ---------------------------------------------------------------


def test_insert_and_list_findings(conn):
    doc = _store_doc(conn, "minimal.json")
    rows = fstore.list_findings(conn, doc["scan_id"])
    assert len(rows) == 1
    f = rows[0]
    src = doc["findings"][0]
    assert f["scan_id"] == doc["scan_id"]
    assert f["rule_id"] == src["rule_id"]
    assert f["severity"] == src["severity"]
    assert f["file"] == src["file"]
    assert f["line"] == src["line"]
    assert f["title"] == src["title"]
    assert f["confidence"] == pytest.approx(src["confidence"])


def test_multiple_findings_and_counts(conn):
    doc = _store_doc(conn, "multi.json")
    assert fstore.count_findings(conn, doc["scan_id"]) == 4
    by_sev = fstore.count_by_severity(conn, doc["scan_id"])
    assert by_sev == {"high": 1, "medium": 1, "critical": 1, "low": 1}
    assert fstore.count_findings(conn, doc["scan_id"], severity="high") == 1
    assert len(fstore.list_findings(conn, doc["scan_id"], severity="critical")) == 1


def test_empty_scan_has_no_findings(conn):
    doc = _store_doc(conn, "empty.json")
    assert fstore.list_findings(conn, doc["scan_id"]) == []
    assert fstore.count_findings(conn, doc["scan_id"]) == 0
    assert fstore.count_by_severity(conn, doc["scan_id"]) == {}


def test_findings_scoped_to_scan(conn):
    _store_doc(conn, "minimal.json")
    empty = _store_doc(conn, "empty.json")
    assert fstore.list_findings(conn, empty["scan_id"]) == []
    assert fstore.count_findings(conn, "scan-minimal-001") == 1


def test_foreign_key_rejects_orphan_finding(conn):
    with pytest.raises(sqlite3.IntegrityError):
        fstore.insert_finding(
            conn,
            "missing-scan",
            {
                "rule_id": "X",
                "severity": "low",
                "file": "a.py",
                "line": 1,
                "title": "t",
            },
        )


def test_delete_scan_cascades_findings(conn):
    doc = _store_doc(conn, "multi.json")
    assert sstore.delete_scan(conn, doc["scan_id"]) == 1
    assert sstore.get_scan(conn, doc["scan_id"]) is None
    assert fstore.list_findings(conn, doc["scan_id"]) == []


# --- raw JSON preservation --------------------------------------------------


@pytest.mark.parametrize("name", ["minimal.json", "multi.json", "empty.json"])
def test_raw_json_preserved(conn, name):
    doc = _store_doc(conn, name)
    assert sstore.get_scan_doc(conn, doc["scan_id"]) == doc
