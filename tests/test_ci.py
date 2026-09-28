"""Tests for the CI gate (unified backend).

All tests drive ecdat.cli.main() directly (plus pure-helper unit tests)
and use tmp_path databases — never the ~/.ecdat default. CI always runs
the shared ScanOrchestrator pipeline (no mock); --fail-on gates on stored
finding severities only. Exit codes: 0 pass, 1 policy failure / scan or
store error, 2 target not found / argparse rejection.
"""

import json
from pathlib import Path

import pytest

from ecdat.cli import build_parser, main
from ecdat.commands import ci_cmd
from ecdat.commands import export_cmd
from ecdat.exports import sarif as sarif_mod
from ecdat.store import db
from ecdat.store import scans as sstore

CRYPTO_PY = "import hashlib\nh = hashlib.md5(b'ecdat-ci-test').hexdigest()\n"


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "t.db")


def _file(tmp_path: Path, name: str = "a.py") -> Path:
    p = tmp_path / name
    p.write_text("x = 1\n")
    return p


def _crypto(tmp_path: Path, name: str = "c.py") -> Path:
    p = tmp_path / name
    p.write_text(CRYPTO_PY)
    return p


# --- command exists ----------------------------------------------------


def test_ci_subcommand_registered():
    parser = build_parser()
    args = parser.parse_args(["ci", "sometarget"])
    assert args.func is ci_cmd.run
    assert args.fail_on is None
    assert args.json is False
    assert args.sarif is None
    assert args.profile == "standard"


def test_ci_repeat_run_reuses_stored_row(tmp_path, capsys):
    target = _crypto(tmp_path)
    assert main(["ci", str(target), "--db", _db(tmp_path)]) == 0
    capsys.readouterr()
    # Second run against the same DB must gate on policy, never crash on
    # the deterministic scan ID (UNIQUE constraint regression).
    rc = main(["ci", str(target), "--db", _db(tmp_path)])
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "UNIQUE" not in err
    assert "reused" in err


# --- basic execution / persistence --------------------------------------


def test_ci_basic_execution_clean(tmp_path, capsys):
    rc = main(["ci", str(_file(tmp_path)), "--db", _db(tmp_path)])
    assert rc == 0
    out, err = capsys.readouterr()
    assert "scan:" in out
    assert "PASS" in out
    assert "Traceback" not in out + err


def test_ci_stores_scan(tmp_path, capsys):
    target = _crypto(tmp_path)
    assert main(["ci", str(target), "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    scan_id = [line for line in out.splitlines() if line.startswith("scan_id:")][0].split(": ", 1)[1]
    conn = db.open_db(_db(tmp_path))
    try:
        row = sstore.get_scan(conn, scan_id)
        assert row is not None
        assert sstore.get_scan_cir(conn, scan_id) is not None
    finally:
        conn.close()


def test_ci_clean_scan_passes(tmp_path, capsys):
    rc = main(["ci", str(_file(tmp_path)), "--db", _db(tmp_path)])
    assert rc == 0
    out, _ = capsys.readouterr()
    assert "findings: 0" in out
    assert "PASS" in out


# --- --fail-on thresholds -------------------------------------------------


def test_ci_fail_on_info_trips_on_any_finding(tmp_path, capsys):
    rc = main(["ci", str(_crypto(tmp_path)), "--db", _db(tmp_path),
               "--fail-on", "info"])
    assert rc == 1
    out, _ = capsys.readouterr()
    assert "FAIL" in out


def test_ci_fail_on_critical_passes_for_clean(tmp_path, capsys):
    rc = main(["ci", str(_file(tmp_path)), "--db", _db(tmp_path),
               "--fail-on", "critical"])
    assert rc == 0
    out, _ = capsys.readouterr()
    assert "PASS" in out


def test_ci_invalid_fail_on_rejected():
    with pytest.raises(SystemExit) as exc:
        main(["ci", "x.py", "--fail-on", "bogus"])
    assert exc.value.code == 2


# --- evaluate() unit behavior ----------------------------------------------


def test_evaluate_ordering_and_triggering():
    findings = [{"severity": "high"}, {"severity": "low"}]
    assert ci_cmd.evaluate(findings, "critical")["passed"] is True
    assert ci_cmd.evaluate(findings, "high")["passed"] is False
    assert ci_cmd.evaluate(findings, "high")["triggered"] == ["high"]
    assert ci_cmd.evaluate(findings, None)["passed"] is True
    assert ci_cmd.evaluate([], "info")["passed"] is True
    assert ci_cmd.evaluate([], "info")["max_severity"] is None


def test_evaluate_counts_all_levels_deterministically():
    findings = [{"severity": "critical"}, {"severity": "critical"},
                {"severity": "medium"}]
    first = ci_cmd.evaluate(findings, "low")
    assert ci_cmd.evaluate(findings, "low") == first
    assert first["by_severity"] == {"info": 0, "low": 0, "medium": 1,
                                    "high": 0, "critical": 2}
    assert first["max_severity"] == "critical"


# --- --summary --------------------------------------------------------------


def test_ci_summary_fields(tmp_path, capsys):
    target = _crypto(tmp_path)
    rc = main(["ci", str(target), "--db", _db(tmp_path), "--summary"])
    assert rc == 0
    out, _ = capsys.readouterr()
    for needle in (str(target), "findings:", "risk:", "fail-on:", "verdict:"):
        assert needle in out


# --- --json -------------------------------------------------------------------


def test_ci_json_valid_and_shaped(tmp_path, capsys):
    rc = main(["ci", str(_crypto(tmp_path)), "--db", _db(tmp_path),
               "--json", "--fail-on", "info"])
    assert rc == 1
    out, err = capsys.readouterr()
    assert err == ""  # no stdout contamination, no stderr noise
    doc = json.loads(out)  # must be pure valid JSON
    assert doc["tool"] == "ecdat-ci"
    assert doc["finding_count"] >= 1
    assert doc["fail_on"] == "info"
    assert doc["verdict"] == "fail"
    assert set(doc["risk"]) >= {"score", "level"}
    assert doc["max_severity"] is not None
    assert "limitations" in doc


def test_ci_json_pass_verdict(tmp_path, capsys):
    rc = main(["ci", str(_file(tmp_path)), "--db", _db(tmp_path), "--json"])
    assert rc == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["verdict"] == "pass"
    assert doc["fail_on"] is None
    assert doc["finding_count"] == 0


# --- --sarif ---------------------------------------------------------------------


def test_ci_sarif_file_and_reuse(tmp_path, capsys):
    target = _crypto(tmp_path)
    sarif_path = tmp_path / "ci.sarif"
    rc = main(["ci", str(target), "--db", _db(tmp_path),
               "--sarif", str(sarif_path)])
    assert rc == 0
    capsys.readouterr()
    sarif_doc = json.loads(sarif_path.read_text())
    assert sarif_doc["version"] == "2.1.0"
    out_id = main(["ci", str(target), "--db", str(tmp_path / "other.db"),
                   "--json"])
    assert out_id == 0
    scan_id = json.loads(capsys.readouterr()[0])["scan_id"]
    conn = db.open_db(_db(tmp_path))
    try:
        stored = sstore.get_scan_doc(conn, scan_id)
    finally:
        conn.close()
    assert stored is not None
    # Byte-identical reuse of the existing exporter path.
    assert sarif_path.read_text() == export_cmd.render(stored, "sarif") + "\n"
    assert sarif_mod.to_sarif(stored) == export_cmd.render(stored, "sarif")


def test_ci_sarif_still_written_on_policy_failure(tmp_path, capsys):
    sarif_path = tmp_path / "fail.sarif"
    rc = main(["ci", str(_crypto(tmp_path)), "--db", _db(tmp_path),
               "--fail-on", "info", "--sarif", str(sarif_path),
               "--json"])
    assert rc == 1
    out, _ = capsys.readouterr()
    assert json.loads(out)["verdict"] == "fail"  # stdout stays pure JSON
    assert json.loads(sarif_path.read_text())["version"] == "2.1.0"


# --- exit codes / errors ----------------------------------------------------------


def test_ci_target_not_found(tmp_path, capsys):
    rc = main(["ci", str(tmp_path / "nope.py"), "--db", _db(tmp_path)])
    assert rc == 2
    _, err = capsys.readouterr()
    assert "not found" in err


def test_ci_invalid_scanners_fail_clean(tmp_path, capsys):
    rc = main(["ci", str(_file(tmp_path)), "--db", _db(tmp_path),
               "--scanners", "bogus-scanner"])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert err.strip() != ""


# --- determinism ----------------------------------------------------------------------


def test_ci_deterministic_scan_id_across_databases(tmp_path, capsys):
    target = _crypto(tmp_path)
    assert main(["ci", str(target), "--db", str(tmp_path / "one.db"),
                 "--json"]) == 0
    first = json.loads(capsys.readouterr()[0])["scan_id"]
    assert main(["ci", str(target), "--db", str(tmp_path / "two.db"),
                 "--json"]) == 0
    second = json.loads(capsys.readouterr()[0])["scan_id"]
    assert first == second
    assert first.startswith("scan:")
