"""Tests for the Task 4 CLI vertical slice (scan / list / show).

All tests drive ecdat.cli.main() directly and use tmp_path databases —
never the ~/.ecdat default. Exit codes: 0 ok, 1 general error,
2 target not found, 3 validation failure.
"""

import json
from pathlib import Path

from ecdat.cli import main
from ecdat.core.validate import validate
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore


def _target(tmp_path: Path, name: str = "a.py") -> Path:
    p = tmp_path / name
    p.write_text("x = 1\n")
    return p


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "t.db")


def _scan_id(capsys) -> str:
    out, _ = capsys.readouterr()
    return out.strip()


# --- scan ---------------------------------------------------------------


def test_scan_mock_stores_scan(tmp_path, capsys):
    target = _target(tmp_path)
    rc = main(["scan", str(target), "--db", _db(tmp_path)])
    assert rc == 0
    scan_id = _scan_id(capsys)
    assert scan_id == "scan-minimal-001"  # mirrors minimal.json
    conn = db.open_db(_db(tmp_path))
    try:
        row = sstore.get_scan(conn, scan_id)
        assert row is not None
        assert row["target"] == str(target)
    finally:
        conn.close()


def test_scan_stores_findings(tmp_path, capsys):
    target = _target(tmp_path)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    scan_id = _scan_id(capsys)
    conn = db.open_db(_db(tmp_path))
    try:
        assert fstore.count_findings(conn, scan_id) == 1
    finally:
        conn.close()


def test_scan_directory_stores_multi_findings(tmp_path, capsys):
    app = tmp_path / "app"
    app.mkdir()
    (app / "m.py").write_text("x = 1\n")
    assert main(["scan", str(app), "--db", _db(tmp_path)]) == 0
    scan_id = _scan_id(capsys)
    conn = db.open_db(_db(tmp_path))
    try:
        assert fstore.count_findings(conn, scan_id) == 4  # mirrors multi.json
    finally:
        conn.close()


def test_scan_output_writes_valid_canonical_json(tmp_path, capsys):
    target = _target(tmp_path)
    out = tmp_path / "out.json"
    rc = main(["scan", str(target), "--db", _db(tmp_path), "--output", str(out)])
    assert rc == 0
    _scan_id(capsys)
    doc = json.loads(out.read_text())
    validate(doc)  # must be valid canonical JSON
    assert doc["target"] == str(target)


def test_scan_target_not_found(tmp_path, capsys):
    rc = main(["scan", str(tmp_path / "nope.py"), "--db", _db(tmp_path)])
    assert rc == 2
    _, err = capsys.readouterr()
    assert "not found" in err


def test_scan_real_placeholder_is_clean(tmp_path, capsys):
    target = _target(tmp_path)
    rc = main(["scan", str(target), "--db", _db(tmp_path), "--real"])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert err.strip() != ""


def test_scan_validation_failure(tmp_path, capsys, monkeypatch):
    import ecdat.commands.scan_cmd as scan_cmd

    class BadClient:
        def scan(self, target):
            return {"not": "canonical"}

    monkeypatch.setattr(scan_cmd, "get_client", lambda mode: BadClient())
    rc = main(["scan", str(_target(tmp_path)), "--db", _db(tmp_path)])
    assert rc == 3
    _, err = capsys.readouterr()
    assert "validation failed" in err


def test_scan_duplicate_is_clean_error(tmp_path, capsys):
    target = _target(tmp_path)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    _scan_id(capsys)
    rc = main(["scan", str(target), "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "already exists" in err


# --- list ---------------------------------------------------------------


def test_list_empty_db(tmp_path, capsys):
    assert main(["list", "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert "no scans" in out


def test_list_shows_scan(tmp_path, capsys):
    target = _target(tmp_path)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    _scan_id(capsys)
    assert main(["list", "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert "scan-minimal-001" in out
    assert str(target) in out


def test_list_json(tmp_path, capsys):
    target = _target(tmp_path)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    _scan_id(capsys)
    assert main(["list", "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    rows = json.loads(out)
    assert len(rows) == 1
    assert rows[0]["id"] == "scan-minimal-001"
    assert rows[0]["finding_count"] == 1


# --- show ---------------------------------------------------------------


def test_show_human(tmp_path, capsys):
    target = _target(tmp_path)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    scan_id = _scan_id(capsys)
    assert main(["show", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert "RSA-1024" in out
    assert "high" in out
    assert str(target) in out


def test_show_json(tmp_path, capsys):
    target = _target(tmp_path)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    scan_id = _scan_id(capsys)
    assert main(["show", scan_id, "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["scan"]["id"] == scan_id
    assert len(doc["findings"]) == 1


def test_show_missing_scan(tmp_path, capsys):
    rc = main(["show", "bogus-id", "--db", _db(tmp_path)])
    assert rc == 1
    _, err = capsys.readouterr()
    assert "not found" in err
