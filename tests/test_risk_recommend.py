"""Tests for risk + recommend commands (unified backend).

Both commands are read-only views over stored scans: CLI -> store ->
P1 wire data (risks/recommendations embedded in the stored CIR). No
scanning here. All tests drive ecdat.cli.main() directly and use tmp_path
databases. Exit codes: 0 ok, 1 unknown scan / missing analysis record.
"""

import json
from pathlib import Path

import pytest

from ecdat.cli import build_parser, main
from ecdat.store import db
from ecdat.store import scans as sstore

CRYPTO_PY = "import hashlib\nh = hashlib.md5(b'ecdat-risk-test').hexdigest()\n"


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "t.db")


def _seed_scan_id(capsys) -> str:
    out, _ = capsys.readouterr()
    return out.strip()


def _seed_crypto(tmp_path: Path, capsys, name: str = "c.py") -> str:
    target = tmp_path / name
    target.write_text(CRYPTO_PY)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    return _seed_scan_id(capsys)


def _seed_clean(tmp_path: Path, capsys) -> str:
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n")
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    return _seed_scan_id(capsys)


# --- risk: CLI ----------------------------------------------------------


def test_risk_crypto_human(tmp_path, capsys):
    scan_id = _seed_crypto(tmp_path, capsys)
    assert main(["risk", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert scan_id in out
    assert "P1 engine" in out
    assert "findings: 1" in out
    assert "risk records: 1" in out


def test_risk_crypto_json(tmp_path, capsys):
    scan_id = _seed_crypto(tmp_path, capsys)
    assert main(["risk", scan_id, "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["scan_id"] == scan_id
    assert set(doc["risk"]) >= {"score", "level", "finding_count", "risk_count"}
    assert doc["risk"]["finding_count"] == 1
    assert doc["risk"]["risk_count"] == 1


def test_risk_clean_scan(tmp_path, capsys):
    scan_id = _seed_clean(tmp_path, capsys)
    assert main(["risk", scan_id, "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["risk"]["finding_count"] == 0
    assert doc["risk"]["risk_count"] == 0


def test_risk_unknown_scan(tmp_path, capsys):
    rc = main(["risk", "bogus-id", "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "not found" in err


# --- recommend: CLI -----------------------------------------------------


def test_recommend_crypto_json(tmp_path, capsys):
    scan_id = _seed_crypto(tmp_path, capsys)
    assert main(["recommend", scan_id, "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["scan_id"] == scan_id
    assert len(doc["recommendations"]) >= 1
    assert {r["rule_id"] for r in doc["recommendations"]} >= {"MD5"}
    first = doc["recommendations"][0]
    assert first["action"] and first["severity"] in {
        "info", "low", "medium", "high", "critical"}


def test_recommend_human(tmp_path, capsys):
    scan_id = _seed_crypto(tmp_path, capsys)
    assert main(["recommend", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert scan_id in out
    assert "MD5" in out


def test_recommend_severity_filter_cli(tmp_path, capsys):
    scan_id = _seed_crypto(tmp_path, capsys)
    rc = main(["recommend", scan_id, "--db", _db(tmp_path), "--json",
               "--severity", "medium"])
    assert rc == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["recommendations"]
    assert {r["severity"] for r in doc["recommendations"]} == {"medium"}


def test_recommend_empty_scan(tmp_path, capsys):
    scan_id = _seed_clean(tmp_path, capsys)
    assert main(["recommend", scan_id, "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    assert json.loads(out) == {"scan_id": scan_id, "recommendations": []}
    assert main(["recommend", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert "no recommendations" in out


def test_recommend_unknown_scan(tmp_path, capsys):
    rc = main(["recommend", "bogus-id", "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "not found" in err


# --- parser -------------------------------------------------------------


def test_parser_dispatch_risk_recommend():
    parser = build_parser()
    assert parser.parse_args(["risk", "x"]).func.__module__ == "ecdat.commands.risk_cmd"
    args = parser.parse_args(["recommend", "x"])
    assert args.func.__module__ == "ecdat.commands.recommend_cmd"
    assert args.severity is None


def test_parser_recommend_severity_choices():
    parser = build_parser()
    assert parser.parse_args(["recommend", "x", "--severity", "high"]).severity == "high"
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["recommend", "x", "--severity", "bogus"])
    assert exc.value.code == 2


# --- regression ---------------------------------------------------------


def test_scan_list_show_risk_recommend_same_scan(tmp_path, capsys):
    target = tmp_path / "a.py"
    target.write_text(CRYPTO_PY)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    scan_id = _seed_scan_id(capsys)
    assert main(["list", "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert scan_id in out
    assert main(["show", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert scan_id in out
    assert main(["risk", scan_id, "--db", _db(tmp_path)]) == 0
    capsys.readouterr()
    assert main(["recommend", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert "MD5" in out
