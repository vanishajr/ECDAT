"""Tests for Task 6 risk + recommend commands (mock-first).

Both commands are read-only views over stored scans: CLI -> store ->
pure helper. No CoreClient, no scanning, no persistence of results.
All tests drive ecdat.cli.main() directly (plus pure-helper unit
tests) and use tmp_path databases. Exit codes: 0 ok, 1 unknown scan,
2 argparse rejection.
"""

import json
from pathlib import Path

import pytest

from ecdat.cli import build_parser, main
from ecdat.commands import recommend_cmd, risk_cmd
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "t.db")


def _seed_scan_id(capsys) -> str:
    out, _ = capsys.readouterr()
    return out.strip()


def _seed_multi(tmp_path: Path, capsys) -> str:
    app = tmp_path / "app"
    app.mkdir(exist_ok=True)
    (app / "m.py").write_text("x = 1\n")
    assert main(["scan", str(app), "--db", _db(tmp_path)]) == 0
    return _seed_scan_id(capsys)


def _seed_empty(tmp_path: Path, capsys) -> str:
    target = tmp_path / "clean.py"
    target.write_text("x = 1\n")
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    return _seed_scan_id(capsys)


def _seed_cloud(tmp_path: Path, capsys) -> str:
    assert main(["scan-cloud", "aws", "--db", _db(tmp_path)]) == 0
    return _seed_scan_id(capsys)


def _insert_custom_rule(tmp_path: Path, scan_id: str = "scan-custom-001") -> str:
    doc = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "target": "custom/target.py",
        "started_at": "2026-09-10T16:00:00Z",
        "finished_at": "2026-09-10T16:00:01Z",
        "tool_versions": {"ecdat": "0.1.0"},
        "findings": [
            {
                "rule_id": "UNKNOWN-999",
                "title": "Something novel",
                "severity": "high",
                "file": "custom/target.py",
                "line": 3,
            }
        ],
        "stats": {"files_scanned": 1, "findings_count": 1},
    }
    conn = db.open_db(_db(tmp_path))
    try:
        sstore.insert_scan(conn, doc)
        fstore.insert_findings_for_scan(conn, doc)
    finally:
        conn.close()
    return scan_id


# --- risk: pure helper --------------------------------------------------


@pytest.mark.parametrize(
    "score,level",
    [(0, "none"), (1, "low"), (4, "low"), (5, "medium"), (9, "medium"),
     (10, "high"), (19, "high"), (20, "critical"), (100, "critical")],
)
def test_risk_thresholds(score, level):
    assert risk_cmd.level_for(score) == level


def test_risk_from_findings_minimal_shape():
    findings = [{"severity": "high"}]
    res = risk_cmd.risk_from_findings(findings)
    assert res == {"score": 5, "level": "medium",
                   "breakdown": {"high": 1}, "finding_count": 1}


def test_risk_from_findings_empty():
    res = risk_cmd.risk_from_findings([])
    assert res["score"] == 0 and res["level"] == "none"
    assert res["breakdown"] == {} and res["finding_count"] == 0


# --- risk: CLI ----------------------------------------------------------


def test_risk_minimal_human(tmp_path, capsys):
    target = tmp_path / "a.py"
    target.write_text("x = 1\n")
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    scan_id = _seed_scan_id(capsys)
    assert main(["risk", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert scan_id in out
    assert "medium" in out and "5" in out
    assert "mock" in out


def test_risk_multi_json(tmp_path, capsys):
    scan_id = _seed_multi(tmp_path, capsys)
    assert main(["risk", scan_id, "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["scan_id"] == scan_id
    assert doc["risk"] == {"score": 19, "level": "high"}
    assert doc["breakdown"] == {"critical": 1, "high": 1, "low": 1, "medium": 1}
    assert doc["finding_count"] == 4


def test_risk_empty_scan(tmp_path, capsys):
    scan_id = _seed_empty(tmp_path, capsys)
    assert main(["risk", scan_id, "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["risk"] == {"score": 0, "level": "none"}
    assert doc["finding_count"] == 0


def test_risk_unknown_scan(tmp_path, capsys):
    rc = main(["risk", "bogus-id", "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "not found" in err


# --- recommend: pure helper ---------------------------------------------


def test_recommend_known_rules_mapped():
    findings = [
        {"rule_id": "RSA-1024", "severity": "high", "title": "t"},
        {"rule_id": "AES-ECB", "severity": "critical", "title": "t"},
    ]
    recs = recommend_cmd.recommend_for_findings(findings)
    assert [r["rule_id"] for r in recs] == ["AES-ECB", "RSA-1024"]
    assert all(r["action"] and "mock" in r["action"] for r in recs)
    assert all(r["refs"] for r in recs)


def test_recommend_unknown_rule_fallback():
    recs = recommend_cmd.recommend_for_findings(
        [{"rule_id": "UNKNOWN-999", "severity": "high", "title": "t"}]
    )
    assert len(recs) == 1
    assert recs[0]["refs"] == []
    assert "mock" in recs[0]["action"]


def test_recommend_deduplicates_by_rule():
    findings = [
        {"rule_id": "RSA-1024", "severity": "high", "title": "t"},
        {"rule_id": "RSA-1024", "severity": "high", "title": "t"},
    ]
    recs = recommend_cmd.recommend_for_findings(findings)
    assert len(recs) == 1
    assert recs[0]["count"] == 2


def test_recommend_severity_filter_helper():
    findings = [
        {"rule_id": "RSA-1024", "severity": "high", "title": "t"},
        {"rule_id": "TLS-1.0", "severity": "low", "title": "t"},
    ]
    recs = recommend_cmd.recommend_for_findings(findings, severity="high")
    assert [r["rule_id"] for r in recs] == ["RSA-1024"]


# --- recommend: CLI -----------------------------------------------------


def test_recommend_multi_covers_all_scan_rules(tmp_path, capsys):
    scan_id = _seed_multi(tmp_path, capsys)
    assert main(["recommend", scan_id, "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["scan_id"] == scan_id
    assert {r["rule_id"] for r in doc["recommendations"]} == {
        "RSA-1024", "MD5-USAGE", "AES-ECB", "TLS-1.0",
    }


def test_recommend_cloud_covers_cloud_rules(tmp_path, capsys):
    scan_id = _seed_cloud(tmp_path, capsys)
    assert main(["recommend", scan_id, "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert {r["rule_id"] for r in doc["recommendations"]} == {
        "KMS-NO-ROTATION", "ACM-EXPIRY", "ELB-TLS-OLD",
    }


def test_recommend_human_labels_mock(tmp_path, capsys):
    target = tmp_path / "a.py"
    target.write_text("x = 1\n")
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    scan_id = _seed_scan_id(capsys)
    assert main(["recommend", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert "mock" in out and "RSA-1024" in out


def test_recommend_severity_filter_cli(tmp_path, capsys):
    scan_id = _seed_multi(tmp_path, capsys)
    rc = main(["recommend", scan_id, "--db", _db(tmp_path), "--json",
               "--severity", "high"])
    assert rc == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert [r["rule_id"] for r in doc["recommendations"]] == ["RSA-1024"]


def test_recommend_unknown_rule_fallback_cli(tmp_path, capsys):
    scan_id = _insert_custom_rule(tmp_path)
    assert main(["recommend", scan_id, "--db", _db(tmp_path), "--json"]) == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert len(doc["recommendations"]) == 1
    assert doc["recommendations"][0]["rule_id"] == "UNKNOWN-999"
    assert doc["recommendations"][0]["refs"] == []


def test_recommend_empty_scan(tmp_path, capsys):
    scan_id = _seed_empty(tmp_path, capsys)
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


def test_parser_existing_commands_unchanged():
    parser = build_parser()
    assert parser.parse_args(["scan", "a.py"]).func.__module__ == "ecdat.commands.scan_cmd"
    assert parser.parse_args(["list"]).func.__module__ == "ecdat.commands.list_cmd"
    assert parser.parse_args(["show", "x"]).func.__module__ == "ecdat.commands.show_cmd"
    assert parser.parse_args(["scan-binary", "a.bin"]).func.__module__ == (
        "ecdat.commands.scan_binary_cmd"
    )


# --- regression ---------------------------------------------------------


def test_existing_scan_list_show_still_work(tmp_path, capsys):
    target = tmp_path / "a.py"
    target.write_text("x = 1\n")
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    scan_id = _seed_scan_id(capsys)
    assert main(["list", "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert scan_id in out
    assert main(["show", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert scan_id in out
    # New read-only commands work on the same scan.
    assert main(["risk", scan_id, "--db", _db(tmp_path)]) == 0
    capsys.readouterr()
    assert main(["recommend", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert "RSA-1024" in out
