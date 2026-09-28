"""Tests for specialized scan commands (unified backend).

Covers: scan-binary / scan-container / scan-cloud. Every command runs the
shared ScanOrchestrator pipeline (no mock). Tests drive ecdat.cli.main()
directly with tmp_path databases. Exit codes: 0 ok, 1 backend/general
error, 2 target not found / argparse rejection.
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
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00ecdat-binary\n")
    return p


# --- scan-binary --------------------------------------------------------


def test_scan_binary_stores_scan(tmp_path, capsys):
    target = _binary(tmp_path)
    rc = main(["scan-binary", str(target), "--db", _db(tmp_path)])
    assert rc == 0
    scan_id = _scan_id(capsys)
    assert scan_id.startswith("scan:")
    conn = db.open_db(_db(tmp_path))
    try:
        row = sstore.get_scan(conn, scan_id)
        assert row is not None
        assert row["target"] == str(target)
        assert sstore.get_scan_cir(conn, scan_id) is not None
    finally:
        conn.close()


def test_scan_binary_output_writes_valid_canonical_json(tmp_path, capsys):
    target = _binary(tmp_path)
    out = tmp_path / "out.json"
    rc = main(["scan-binary", str(target), "--db", _db(tmp_path), "--output", str(out)])
    assert rc == 0
    scan_id = _scan_id(capsys)
    doc = json.loads(out.read_text())
    validate(doc)
    assert doc["scan_id"] == scan_id


def test_scan_binary_missing_target(tmp_path, capsys):
    rc = main(["scan-binary", str(tmp_path / "nope.bin"), "--db", _db(tmp_path)])
    assert rc == 2
    _, err = capsys.readouterr()
    assert "not found" in err


def test_scan_binary_duplicate_reuses_stored_row(tmp_path, capsys):
    target = _binary(tmp_path)
    assert main(["scan-binary", str(target), "--db", _db(tmp_path)]) == 0
    first_id = _scan_id(capsys)
    rc = main(["scan-binary", str(target), "--db", _db(tmp_path)])
    assert rc == 0
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert out.strip() == first_id
    assert "reused" in err


# --- scan-container -----------------------------------------------------


def test_scan_container_local_path(tmp_path, capsys):
    rootfs = tmp_path / "rootfs"
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "etc" / "app.py").write_text("import hashlib\nh = hashlib.md5(b'x')\n")
    rc = main(["scan-container", str(rootfs), "--db", _db(tmp_path)])
    assert rc == 0
    scan_id = _scan_id(capsys)
    assert scan_id.startswith("scan:")
    conn = db.open_db(_db(tmp_path))
    try:
        row = sstore.get_scan(conn, scan_id)
        assert row is not None
    finally:
        conn.close()


def test_scan_container_registry_ref_without_pull_is_clean_error(tmp_path, capsys):
    rc = main(["scan-container", "nginx:1.25", "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "--allow-pull" in err


def test_scan_container_empty_target_is_clean_error(tmp_path, capsys):
    rc = main(["scan-container", "  ", "--db", _db(tmp_path)])
    assert rc == 2
    _, err = capsys.readouterr()
    assert "not found" in err.lower()


# --- scan-cloud ---------------------------------------------------------


def test_scan_cloud_without_credentials_fails_clean(tmp_path, capsys):
    # No AWS credentials in CI: the cloud scanner reports unavailable and
    # the shared helper fails loudly instead of returning mock data.
    rc = main(["scan-cloud", "aws", "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert err.strip() != ""


def test_scan_cloud_empty_services_is_clean_error(tmp_path, capsys):
    rc = main(["scan-cloud", "aws", "--services", "", "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "services" in err


def test_scan_cloud_unknown_provider_rejected(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["scan-cloud", "gcp", "--db", _db(tmp_path)])
    assert exc.value.code == 2


def test_scan_cloud_aws_cred_flags_accepted(tmp_path):
    # Parity with the GUI cloud-config form: explicit credential flags exist
    # and parse (values flow to ScanRequest; covered in parity tests).
    parser = build_parser()
    args = parser.parse_args(["scan-cloud", "aws", "--aws-access-key-id", "AKID",
                              "--aws-secret-access-key", "SECRET",
                              "--aws-session-token", "TOK",
                              "--aws-profile", "dev"])
    assert args.aws_access_key_id == "AKID"
    assert args.aws_secret_access_key == "SECRET"
    assert args.aws_session_token == "TOK"
    assert args.aws_profile == "dev"
    assert args.profile == "default"  # AWS profile meaning preserved


# --- parser -------------------------------------------------------------


def test_parser_dispatch_specialized_commands():
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


def test_parser_scan_cloud_defaults():
    parser = build_parser()
    args = parser.parse_args(["scan-cloud", "aws"])
    assert args.profile == "default" and args.services == "kms,acm,elb"
    assert args.region is None
    assert args.aws_access_key_id is None and args.aws_profile is None


def test_parser_existing_commands_unchanged():
    parser = build_parser()
    assert parser.parse_args(["scan", "a.py"]).func.__module__ == "ecdat.commands.scan_cmd"
    assert parser.parse_args(["list"]).func.__module__ == "ecdat.commands.list_cmd"
    assert parser.parse_args(["show", "x"]).func.__module__ == "ecdat.commands.show_cmd"


# --- regression + coexistence -------------------------------------------


def test_mixed_scans_coexist_in_one_db(tmp_path, capsys):
    target = tmp_path / "a.py"
    target.write_text("import hashlib\nh = hashlib.md5(b'x')\n")
    binary = _binary(tmp_path)
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    first = _scan_id(capsys)
    assert main(["scan-binary", str(binary), "--db", _db(tmp_path)]) == 0
    second = _scan_id(capsys)
    assert main(["scan-container", str(rootfs), "--db", _db(tmp_path)]) == 0
    third = _scan_id(capsys)
    assert len({first, second, third}) == 3
    assert main(["list", "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    rows = json.loads(out)
    assert {r["id"] for r in rows} == {first, second, third}
    assert main(["show", second, "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["scan"]["id"] == second
