"""Tests for Task 5 specialized scan commands.

Covers: scan-binary / scan-container / scan-cloud (mock-first).
All tests drive ecdat.cli.main() directly and use tmp_path databases —
never the ~/.ecdat default. Exit codes: 0 ok, 1 general error,
2 target not found / argparse rejection, 3 validation failure.
"""

import json
from pathlib import Path

import pytest

from ecdat.cli import build_parser, main
from ecdat.core.validate import validate
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "t.db")


def _scan_id(capsys) -> str:
    out, _ = capsys.readouterr()
    return out.strip()


def _binary(tmp_path: Path, name: str = "app.bin") -> Path:
    p = tmp_path / name
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00mock-binary\n")
    return p


# --- scan-binary --------------------------------------------------------


def test_scan_binary_mock_stores_scan(tmp_path, capsys):
    target = _binary(tmp_path)
    rc = main(["scan-binary", str(target), "--db", _db(tmp_path)])
    assert rc == 0
    scan_id = _scan_id(capsys)
    assert scan_id == "scan-binary-001"
    conn = db.open_db(_db(tmp_path))
    try:
        row = sstore.get_scan(conn, scan_id)
        assert row is not None
        assert row["target"] == str(target)
    finally:
        conn.close()


def test_scan_binary_stores_findings(tmp_path, capsys):
    target = _binary(tmp_path)
    assert main(["scan-binary", str(target), "--db", _db(tmp_path)]) == 0
    scan_id = _scan_id(capsys)
    conn = db.open_db(_db(tmp_path))
    try:
        assert fstore.count_findings(conn, scan_id) == 2
    finally:
        conn.close()


def test_scan_binary_deep_auto_accepted(tmp_path, capsys):
    target = _binary(tmp_path)
    rc = main(["scan-binary", str(target), "--deep", "auto", "--db", _db(tmp_path)])
    assert rc == 0
    assert _scan_id(capsys) == "scan-binary-001"


def test_scan_binary_output_writes_valid_canonical_json(tmp_path, capsys):
    target = _binary(tmp_path)
    out = tmp_path / "out.json"
    rc = main(["scan-binary", str(target), "--db", _db(tmp_path), "--output", str(out)])
    assert rc == 0
    _scan_id(capsys)
    doc = json.loads(out.read_text())
    validate(doc)
    assert doc["target"] == str(target)
    assert doc["scan_id"] == "scan-binary-001"


def test_scan_binary_missing_target(tmp_path, capsys):
    rc = main(["scan-binary", str(tmp_path / "nope.bin"), "--db", _db(tmp_path)])
    assert rc == 2
    _, err = capsys.readouterr()
    assert "not found" in err


def test_scan_binary_real_placeholder_is_clean(tmp_path, capsys):
    # Integrated real mode: --real runs the binary scanner subset.
    target = _binary(tmp_path)
    rc = main(["scan-binary", str(target), "--db", _db(tmp_path), "--real"])
    assert rc == 0
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert out.strip().startswith("scan:")


def test_scan_binary_validation_failure(tmp_path, capsys, monkeypatch):
    import ecdat.commands.scan_binary_cmd as bin_cmd

    monkeypatch.setattr(bin_cmd, "_mock_doc", lambda label: {"not": "canonical"})
    rc = main(["scan-binary", str(_binary(tmp_path)), "--db", _db(tmp_path)])
    assert rc == 3
    _, err = capsys.readouterr()
    assert "validation failed" in err


def test_scan_binary_duplicate_is_clean_error(tmp_path, capsys):
    target = _binary(tmp_path)
    assert main(["scan-binary", str(target), "--db", _db(tmp_path)]) == 0
    _scan_id(capsys)
    rc = main(["scan-binary", str(target), "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "already exists" in err


# --- scan-container -----------------------------------------------------


def test_scan_container_registry_ref(tmp_path, capsys):
    rc = main(["scan-container", "nginx:1.25", "--db", _db(tmp_path)])
    assert rc == 0
    scan_id = _scan_id(capsys)
    assert scan_id == "scan-container-001"
    conn = db.open_db(_db(tmp_path))
    try:
        row = sstore.get_scan(conn, scan_id)
        assert row is not None
        assert row["target"] == "nginx:1.25"
        assert fstore.count_findings(conn, scan_id) == 2
    finally:
        conn.close()


def test_scan_container_digest_ref(tmp_path, capsys):
    ref = "registry/org/image@sha256:abc123"
    assert main(["scan-container", ref, "--db", _db(tmp_path)]) == 0
    assert _scan_id(capsys) == "scan-container-001"


def test_scan_container_local_path(tmp_path, capsys):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "etc").mkdir()
    rc = main(["scan-container", str(rootfs), "--db", _db(tmp_path)])
    assert rc == 0
    scan_id = _scan_id(capsys)
    conn = db.open_db(_db(tmp_path))
    try:
        row = sstore.get_scan(conn, scan_id)
        assert row is not None
        assert row["target"] == str(rootfs)
    finally:
        conn.close()


def test_scan_container_output_valid(tmp_path, capsys):
    out = tmp_path / "ctr.json"
    rc = main(["scan-container", "nginx:1.25", "--db", _db(tmp_path), "--output", str(out)])
    assert rc == 0
    _scan_id(capsys)
    doc = json.loads(out.read_text())
    validate(doc)
    assert doc["target"] == "nginx:1.25"


def test_scan_container_real_clean(tmp_path, capsys):
    rc = main(["scan-container", "nginx:1.25", "--db", _db(tmp_path), "--real"])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert err.strip() != ""


def test_scan_container_validation_failure(tmp_path, capsys, monkeypatch):
    import ecdat.commands.scan_container_cmd as ctr_cmd

    monkeypatch.setattr(ctr_cmd, "_mock_doc", lambda label: {"not": "canonical"})
    rc = main(["scan-container", "nginx:1.25", "--db", _db(tmp_path)])
    assert rc == 3
    _, err = capsys.readouterr()
    assert "validation failed" in err


def test_scan_container_duplicate_is_clean_error(tmp_path, capsys):
    assert main(["scan-container", "nginx:1.25", "--db", _db(tmp_path)]) == 0
    _scan_id(capsys)
    rc = main(["scan-container", "nginx:1.25", "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "already exists" in err


# --- scan-cloud ---------------------------------------------------------


def test_scan_cloud_aws_mock_stores_scan(tmp_path, capsys):
    rc = main(
        ["scan-cloud", "aws", "--profile", "dev", "--services", "kms,acm",
         "--db", _db(tmp_path)]
    )
    assert rc == 0
    scan_id = _scan_id(capsys)
    assert scan_id == "scan-cloud-aws-001"
    conn = db.open_db(_db(tmp_path))
    try:
        row = sstore.get_scan(conn, scan_id)
        assert row is not None
        assert row["target"] == "aws:dev:services=kms,acm"
        assert fstore.count_findings(conn, scan_id) == 3
    finally:
        conn.close()


def test_scan_cloud_defaults(tmp_path, capsys):
    assert main(["scan-cloud", "aws", "--db", _db(tmp_path)]) == 0
    scan_id = _scan_id(capsys)
    conn = db.open_db(_db(tmp_path))
    try:
        row = sstore.get_scan(conn, scan_id)
        assert row is not None
        assert row["target"] == "aws:default:services=kms,acm,elb"
    finally:
        conn.close()


def test_scan_cloud_services_normalized(tmp_path, capsys):
    rc = main(
        ["scan-cloud", "aws", "--services", "kms, acm ,elb", "--db", _db(tmp_path)]
    )
    assert rc == 0
    scan_id = _scan_id(capsys)
    conn = db.open_db(_db(tmp_path))
    try:
        row = sstore.get_scan(conn, scan_id)
        assert row is not None
        assert row["target"] == "aws:default:services=kms,acm,elb"
    finally:
        conn.close()


def test_scan_cloud_output_valid(tmp_path, capsys):
    out = tmp_path / "cloud.json"
    rc = main(["scan-cloud", "aws", "--db", _db(tmp_path), "--output", str(out)])
    assert rc == 0
    _scan_id(capsys)
    doc = json.loads(out.read_text())
    validate(doc)
    assert doc["scan_id"] == "scan-cloud-aws-001"


def test_scan_cloud_empty_services_is_clean_error(tmp_path, capsys):
    rc = main(["scan-cloud", "aws", "--services", "", "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "services" in err


def test_scan_cloud_real_clean(tmp_path, capsys):
    rc = main(["scan-cloud", "aws", "--db", _db(tmp_path), "--real"])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert err.strip() != ""


def test_scan_cloud_validation_failure(tmp_path, capsys, monkeypatch):
    import ecdat.commands.scan_cloud_cmd as cloud_cmd

    monkeypatch.setattr(cloud_cmd, "_mock_doc", lambda label: {"not": "canonical"})
    rc = main(["scan-cloud", "aws", "--db", _db(tmp_path)])
    assert rc == 3
    _, err = capsys.readouterr()
    assert "validation failed" in err


def test_scan_cloud_duplicate_is_clean_error(tmp_path, capsys):
    assert main(["scan-cloud", "aws", "--db", _db(tmp_path)]) == 0
    _scan_id(capsys)
    rc = main(["scan-cloud", "aws", "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "already exists" in err


def test_scan_cloud_unknown_provider_rejected(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["scan-cloud", "gcp", "--db", _db(tmp_path)])
    assert exc.value.code == 2


# --- parser -------------------------------------------------------------


def test_parser_dispatch_new_commands():
    parser = build_parser()
    assert parser.parse_args(["scan-binary", "a.bin"]).func.__module__ == (
        "ecdat.commands.scan_binary_cmd"
    )
    assert parser.parse_args(["scan-container", "nginx:1.25"]).func.__module__ == (
        "ecdat.commands.scan_container_cmd"
    )
    assert parser.parse_args(["scan-cloud", "aws"]).func.__module__ == (
        "ecdat.commands.scan_cloud_cmd"
    )


def test_parser_defaults():
    parser = build_parser()
    a = parser.parse_args(["scan-binary", "a.bin"])
    assert a.deep == "auto" and a.real is False and a.mock is False
    b = parser.parse_args(["scan-cloud", "aws"])
    assert b.profile == "default" and b.services == "kms,acm,elb"


def test_parser_existing_commands_unchanged():
    parser = build_parser()
    assert parser.parse_args(["scan", "a.py"]).func.__module__ == "ecdat.commands.scan_cmd"
    assert parser.parse_args(["list"]).func.__module__ == "ecdat.commands.list_cmd"
    assert parser.parse_args(["show", "x"]).func.__module__ == "ecdat.commands.show_cmd"


# --- regression + coexistence -------------------------------------------


def test_existing_scan_still_works(tmp_path, capsys):
    target = tmp_path / "a.py"
    target.write_text("x = 1\n")
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    assert _scan_id(capsys) == "scan-minimal-001"


def test_mixed_scans_coexist_in_one_db(tmp_path, capsys):
    target = tmp_path / "a.py"
    target.write_text("x = 1\n")
    binary = _binary(tmp_path)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    _scan_id(capsys)
    assert main(["scan-binary", str(binary), "--db", _db(tmp_path)]) == 0
    _scan_id(capsys)
    assert main(["scan-container", "nginx:1.25", "--db", _db(tmp_path)]) == 0
    _scan_id(capsys)
    assert main(["scan-cloud", "aws", "--db", _db(tmp_path)]) == 0
    _scan_id(capsys)
    assert main(["list", "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    rows = json.loads(out)
    assert {r["id"] for r in rows} == {
        "scan-minimal-001",
        "scan-binary-001",
        "scan-container-001",
        "scan-cloud-aws-001",
    }
    assert main(["show", "scan-binary-001", "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["scan"]["id"] == "scan-binary-001"
    assert len(doc["findings"]) == 2
