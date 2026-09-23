"""Tests for the unified CLI vertical slice (scan / list / show).

All tests drive ecdat.cli.main() directly against the shared backend
(ScanOrchestrator via RealCoreClient) and use tmp_path databases — never
the ~/.ecdat default. Exit codes: 0 ok, 1 general error, 2 target not
found. There is no mock mode: every scan here runs the real pipeline.
"""

import json
from pathlib import Path

from ecdat.cli import main
from ecdat.core.validate import validate
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore

CRYPTO_PY = (
    "import hashlib\n"
    "h = hashlib.md5(b'ecdat-cli-test').hexdigest()\n"
)


def _target(tmp_path: Path, name: str = "a.py") -> Path:
    p = tmp_path / name
    p.write_text(CRYPTO_PY)
    return p


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "t.db")


def _scan_id(capsys) -> str:
    out, _ = capsys.readouterr()
    return out.strip()


def _stored_scan_id(tmp_path: Path, scan_id: str):
    conn = db.open_db(_db(tmp_path))
    try:
        return sstore.get_scan(conn, scan_id)
    finally:
        conn.close()


# --- scan ---------------------------------------------------------------


def test_scan_stores_scan_with_cir(tmp_path, capsys):
    target = _target(tmp_path)
    rc = main(["scan", str(target), "--db", _db(tmp_path)])
    assert rc == 0
    scan_id = _scan_id(capsys)
    assert scan_id.startswith("scan:")
    row = _stored_scan_id(tmp_path, scan_id)
    assert row is not None
    assert row["target"] == str(target)
    conn = db.open_db(_db(tmp_path))
    try:
        assert sstore.get_scan_cir(conn, scan_id) is not None
    finally:
        conn.close()


def test_scan_stores_real_findings(tmp_path, capsys):
    target = _target(tmp_path)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    scan_id = _scan_id(capsys)
    conn = db.open_db(_db(tmp_path))
    try:
        findings = fstore.list_findings(conn, scan_id)
        assert len(findings) >= 1
        assert {f["rule_id"] for f in findings} >= {"MD5"}
    finally:
        conn.close()


def test_scan_output_writes_valid_canonical_json(tmp_path, capsys):
    target = _target(tmp_path)
    out = tmp_path / "out.json"
    rc = main(["scan", str(target), "--db", _db(tmp_path), "--output", str(out)])
    assert rc == 0
    scan_id = _scan_id(capsys)
    doc = json.loads(out.read_text())
    validate(doc)  # must be valid canonical JSON
    assert doc["target"].endswith("a.py")
    assert doc["scan_id"] == scan_id


def test_scan_target_not_found(tmp_path, capsys):
    rc = main(["scan", str(tmp_path / "nope.py"), "--db", _db(tmp_path)])
    assert rc == 2
    _, err = capsys.readouterr()
    assert "not found" in err


def test_scan_invalid_scanners_fail_clean(tmp_path, capsys):
    target = _target(tmp_path)
    rc = main(["scan", str(target), "--db", _db(tmp_path),
               "--scanners", "bogus-scanner"])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert err.strip() != ""


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
    scan_id = _scan_id(capsys)
    assert main(["list", "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert scan_id in out
    assert "a.py" in out


def test_list_json(tmp_path, capsys):
    target = _target(tmp_path)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    scan_id = _scan_id(capsys)
    assert main(["list", "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    rows = json.loads(out)
    assert len(rows) == 1
    assert rows[0]["id"] == scan_id
    assert rows[0]["finding_count"] >= 1


# --- show ---------------------------------------------------------------


def test_show_human(tmp_path, capsys):
    target = _target(tmp_path)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    scan_id = _scan_id(capsys)
    assert main(["show", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert "MD5" in out
    assert "a.py" in out


def test_show_json(tmp_path, capsys):
    target = _target(tmp_path)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    scan_id = _scan_id(capsys)
    assert main(["show", scan_id, "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["scan"]["id"] == scan_id
    assert len(doc["findings"]) >= 1


def test_show_missing_scan(tmp_path, capsys):
    rc = main(["show", "bogus-id", "--db", _db(tmp_path)])
    assert rc == 1
    _, err = capsys.readouterr()
    assert "not found" in err
