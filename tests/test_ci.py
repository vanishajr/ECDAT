"""Tests for the Task 15 CI gate (mock-first orchestration).

All tests drive ecdat.cli.main() directly (plus pure-helper unit
tests) and use tmp_path databases — never the ~/.ecdat default.
The CI command reuses the existing pipeline (MockCoreClient scan,
validate, store, Task 6 risk, Task 7 SARIF); these tests pin the
policy behavior, output contracts, and exit codes.

Mock routing reminder: a target whose name contains "empty"/"clean"
scans clean (0 findings); an existing directory scans multi
(critical+high+medium+low); any other file scans minimal (1x high).
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


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "t.db")


def _file(tmp_path: Path, name: str = "a.py") -> Path:
    p = tmp_path / name
    p.write_text("x = 1\n")
    return p


def _app_dir(tmp_path: Path) -> Path:
    app = tmp_path / "app"
    app.mkdir(exist_ok=True)
    (app / "m.py").write_text("x = 1\n")
    return app


def _clean(tmp_path: Path) -> Path:
    return _file(tmp_path, "clean.py")


# --- command exists ----------------------------------------------------


def test_ci_subcommand_registered():
    parser = build_parser()
    args = parser.parse_args(["ci", "sometarget"])
    assert args.func is ci_cmd.run
    assert args.fail_on is None
    assert args.json is False
    assert args.sarif is None


# --- basic execution / persistence --------------------------------------


def test_ci_basic_execution_minimal(tmp_path, capsys):
    rc = main(["ci", str(_file(tmp_path)), "--db", _db(tmp_path)])
    assert rc == 0
    out, err = capsys.readouterr()
    assert "scan-minimal-001" in out
    assert "PASS" in out


def test_ci_stores_scan(tmp_path, capsys):
    target = _file(tmp_path)
    assert main(["ci", str(target), "--db", _db(tmp_path)]) == 0
    capsys.readouterr()
    conn = db.open_db(_db(tmp_path))
    try:
        row = sstore.get_scan(conn, "scan-minimal-001")
        assert row is not None
        assert row["target"] == str(target)
    finally:
        conn.close()


def test_ci_empty_scan_passes(tmp_path, capsys):
    rc = main(["ci", str(_clean(tmp_path)), "--db", _db(tmp_path)])
    assert rc == 0
    out, _ = capsys.readouterr()
    assert "scan-empty-001" in out
    assert "findings: 0" in out
    assert "PASS" in out


def test_ci_multi_reports_critical(tmp_path, capsys):
    rc = main(["ci", str(_app_dir(tmp_path)), "--db", _db(tmp_path)])
    assert rc == 0  # no --fail-on: report only, always pass
    out, _ = capsys.readouterr()
    assert "scan-multi-001" in out
    assert "critical=1" in out
    assert "PASS" in out


# --- --fail-on thresholds -------------------------------------------------


@pytest.mark.parametrize("level", ["critical", "high", "medium", "low", "info"])
def test_ci_fail_on_multi_trips_every_level(tmp_path, capsys, level):
    rc = main(["ci", str(_app_dir(tmp_path)), "--db", _db(tmp_path),
               "--fail-on", level])
    assert rc == 1
    out, _ = capsys.readouterr()
    assert "FAIL" in out


def test_ci_fail_on_critical_passes_for_high_only(tmp_path, capsys):
    rc = main(["ci", str(_file(tmp_path)), "--db", _db(tmp_path),
               "--fail-on", "critical"])
    assert rc == 0
    out, _ = capsys.readouterr()
    assert "PASS" in out


def test_ci_fail_on_high_trips_for_high_only(tmp_path, capsys):
    rc = main(["ci", str(_file(tmp_path)), "--db", _db(tmp_path),
               "--fail-on", "high"])
    assert rc == 1
    out, _ = capsys.readouterr()
    assert "FAIL" in out


def test_ci_fail_on_info_passes_on_empty(tmp_path, capsys):
    rc = main(["ci", str(_clean(tmp_path)), "--db", _db(tmp_path),
               "--fail-on", "info"])
    assert rc == 0
    out, _ = capsys.readouterr()
    assert "PASS" in out


def test_ci_fail_on_info_trips_on_any_finding(tmp_path, capsys):
    rc = main(["ci", str(_file(tmp_path)), "--db", _db(tmp_path),
               "--fail-on", "info"])
    assert rc == 1


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
    target = _app_dir(tmp_path)
    rc = main(["ci", str(target), "--db", _db(tmp_path), "--summary"])
    assert rc == 0
    out, _ = capsys.readouterr()
    for needle in (str(target), "scan-multi-001", "findings: 4",
                   "risk:", "fail-on:", "verdict:"):
        assert needle in out


# --- --json -------------------------------------------------------------------


def test_ci_json_valid_and_shaped(tmp_path, capsys):
    rc = main(["ci", str(_app_dir(tmp_path)), "--db", _db(tmp_path),
               "--json", "--fail-on", "high"])
    assert rc == 1
    out, err = capsys.readouterr()
    assert err == ""  # no stdout contamination, no stderr noise
    doc = json.loads(out)  # must be pure valid JSON
    assert doc["tool"] == "ecdat-ci"
    assert doc["mock"] is True
    assert doc["scan_id"] == "scan-multi-001"
    assert doc["finding_count"] == 4
    assert doc["by_severity"] == {"info": 0, "low": 1, "medium": 1,
                                  "high": 1, "critical": 1}
    assert doc["risk"] == {"score": 19, "level": "high"}
    assert doc["fail_on"] == "high"
    assert doc["verdict"] == "fail"
    assert doc["triggered"] == ["high", "critical"]
    assert doc["max_severity"] == "critical"


def test_ci_json_pass_verdict(tmp_path, capsys):
    rc = main(["ci", str(_clean(tmp_path)), "--db", _db(tmp_path), "--json"])
    assert rc == 0
    out, _ = capsys.readouterr()
    doc = json.loads(out)
    assert doc["verdict"] == "pass"
    assert doc["fail_on"] is None
    assert doc["finding_count"] == 0


# --- --sarif ---------------------------------------------------------------------


def test_ci_sarif_file_and_reuse(tmp_path, capsys):
    target = _app_dir(tmp_path)
    sarif_path = tmp_path / "ci.sarif"
    rc = main(["ci", str(target), "--db", _db(tmp_path),
               "--sarif", str(sarif_path)])
    assert rc == 0
    capsys.readouterr()
    sarif_doc = json.loads(sarif_path.read_text())
    assert sarif_doc["version"] == "2.1.0"
    conn = db.open_db(_db(tmp_path))
    try:
        stored = sstore.get_scan_doc(conn, "scan-multi-001")
    finally:
        conn.close()
    assert stored is not None
    # Byte-identical reuse of the existing Task 7 exporter path.
    assert sarif_path.read_text() == export_cmd.render(stored, "sarif") + "\n"
    assert sarif_mod.to_sarif(stored) == export_cmd.render(stored, "sarif")


def test_ci_sarif_still_written_on_policy_failure(tmp_path, capsys):
    sarif_path = tmp_path / "fail.sarif"
    rc = main(["ci", str(_app_dir(tmp_path)), "--db", _db(tmp_path),
               "--fail-on", "low", "--sarif", str(sarif_path),
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


def test_ci_real_placeholder_is_clean_error(tmp_path, capsys):
    rc = main(["ci", str(_file(tmp_path)), "--db", _db(tmp_path), "--real"])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert err.strip() != ""


def test_ci_validation_failure(tmp_path, capsys, monkeypatch):
    import ecdat.commands.ci_cmd as ci_mod

    class BadClient:
        def scan(self, target):
            return {"not": "canonical"}

    monkeypatch.setattr(ci_mod, "get_client", lambda mode: BadClient())
    rc = main(["ci", str(_file(tmp_path)), "--db", _db(tmp_path)])
    assert rc == 3
    _, err = capsys.readouterr()
    assert "validation failed" in err


# --- determinism ----------------------------------------------------------------------


def test_ci_deterministic_across_repeat_runs(tmp_path, capsys):
    target = _file(tmp_path)
    argv = ["ci", str(target), "--db", _db(tmp_path), "--json",
            "--fail-on", "medium"]
    assert main(argv) == 1
    first, first_err = capsys.readouterr()
    assert main(argv) == 1  # second run reuses the stored scan
    second, second_err = capsys.readouterr()
    assert json.loads(first) == json.loads(second)
    assert first_err == second_err == ""
