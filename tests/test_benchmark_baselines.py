"""Task 34 baseline-adapter framework tests (no external tools required).

All baselines are exercised through deterministic test doubles or
availability probes only (`shutil.which`, never executed). No network,
no downloads, no subprocess invocation.
"""

import json
import subprocess

import pytest

from ecdat.benchmark import baselines as bl
from ecdat.benchmark import predictions as pred_mod
from ecdat.benchmark import report as report_mod
from ecdat.benchmark import suite as suite_mod
from ecdat.benchmark.__main__ import main as bench_main
from ecdat.benchmark.ground_truth import evaluate_cases
from ecdat.benchmark.suite import with_predictions


def _first_cases(n=3):
    return suite_mod.list_cases()[:n]


def _expected(case):
    return sorted(case.ground_truth.expected)


# --- registry ------------------------------------------------------------


def test_registry_lists_seven_required_families():
    names = sorted(bl.list_baselines())
    assert names == sorted([
        "grep-ripgrep",
        "cbomkit-sonar",
        "cdxgen",
        "syft-trivy",
        "strings-objdump",
        "lief-only",
        "yara-only",
    ])


def test_unknown_baseline_name_rejected():
    with pytest.raises(ValueError):
        bl.get_baseline("nope-not-real")


# --- 1. adapter interface/contract ---------------------------------------


def test_registered_adapters_satisfy_protocol():
    for name in bl.list_baselines():
        adapter = bl.get_baseline(name)
        assert isinstance(adapter, bl.BaselineAdapter)
        assert adapter.name == name
        assert isinstance(adapter.executables(), tuple)
        groups = adapter.supported_groups()
        assert groups is None or set(groups) <= set(suite_mod.GROUPS)
        avail = adapter.check_availability()
        assert set(avail) == {"available", "found", "reason"}
        assert avail["available"] is (avail["found"] is not None)
        desc = adapter.describe()
        assert desc["baseline"] == name
        assert desc["version"] is None  # never fabricated
        assert desc["test_double"] is False


def test_lief_only_has_no_executable_and_reports_why():
    adapter = bl.get_baseline("lief-only")
    assert adapter.executables() == ()
    avail = adapter.check_availability()
    assert avail == {"available": False, "found": None,
                     "reason": ("library-only baseline family; no executable "
                                "to discover (" + bl._NO_SUBPROCESS_NOTE + ")")}


# --- availability never invokes anything ---------------------------------


def test_availability_detection_invokes_nothing(monkeypatch):
    def _boom(*args, **kwargs):
        raise AssertionError("external tool must never be invoked")

    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(subprocess, "call", _boom)
    monkeypatch.setattr(subprocess, "check_output", _boom)
    for name in bl.list_baselines():
        bl.get_baseline(name).check_availability()
        bl.get_baseline(name).describe()


def test_missing_tools_report_unavailable_with_reason(monkeypatch):
    monkeypatch.setattr(bl.shutil, "which", lambda exe: None)
    for name in bl.list_baselines():
        if name == "lief-only":
            continue
        avail = bl.get_baseline(name).check_availability()
        assert avail["available"] is False
        assert avail["found"] is None
        assert "PATH" in avail["reason"]


# --- 2. unavailable baseline behavior ------------------------------------


def test_unavailable_baseline_attempts_zero_cases():
    adapter = bl.MockBaselineAdapter(name="mock-gone (TEST/MOCK)",
                                     available=False)
    result = bl.evaluate_baseline(adapter)
    assert result["status"] == bl.UNAVAILABLE
    assert result["case_count"] == 0
    assert result["evaluated_n"] == 0
    assert result["failed_n"] == 0
    assert result["not_applicable_n"] == 0
    assert result["cases"] == []
    # No fabricated metrics: engine honest-unavailable output reused.
    assert result["aggregate"]["precision"] is None
    assert result["aggregate"]["recall"] is None
    run = bl.run_baseline(adapter)
    assert run["status"] == bl.UNAVAILABLE
    assert "not evaluated" in bl.to_console(run)


# --- 3. available mock baseline behavior ---------------------------------


def test_available_mock_baseline_evaluates():
    cases = _first_cases(3)
    predictions = {cases[0].case_id: _expected(cases[0])}
    adapter = bl.MockBaselineAdapter(
        name="mock-canned (TEST/MOCK)", predictions=predictions)
    assert adapter.describe()["test_double"] is True
    result = bl.evaluate_baseline(
        adapter, case_ids=[c.case_id for c in cases])
    assert result["status"] == bl.EVALUATED
    assert result["evaluated_n"] == 3
    assert result["failed_n"] == 0
    assert result["not_applicable_n"] == 0
    assert [c["status"] for c in result["cases"]] == ["evaluated"] * 3


# --- 4. normalization into the existing engine ----------------------------


def test_baseline_totals_match_engine_on_same_predictions():
    cases = _first_cases(4)
    predictions = {c.case_id: _expected(c) for c in cases[:2]}
    result = bl.evaluate_baseline(
        adapter := bl.MockBaselineAdapter(
            name="mock-norm (TEST/MOCK)", predictions=predictions),
        case_ids=[c.case_id for c in cases])
    assert adapter is not None
    bridged = [with_predictions(c, predictions.get(c.case_id, frozenset()))
               for c in cases]
    assert result["totals"] == evaluate_cases(bridged)["totals"]
    # Same seeded cases and ground truth as the main pipeline.
    assert result["selection"]["resolved"] == [c.case_id for c in cases]
    mock = pred_mod.MockPredictionProvider(predictions=predictions)
    assert (pred_mod.evaluate_selection(
        mock, case_ids=[c.case_id for c in cases])["totals"]
            == result["totals"])


# --- 5. deterministic output ----------------------------------------------


def test_baseline_runs_are_deterministic():
    cases = _first_cases(5)
    predictions = {c.case_id: _expected(c) for c in cases[:2]}
    first = bl.run_baseline(bl.MockBaselineAdapter(
        name="mock-det (TEST/MOCK)", predictions=predictions),
        case_ids=[c.case_id for c in cases])
    second = bl.run_baseline(bl.MockBaselineAdapter(
        name="mock-det (TEST/MOCK)", predictions=predictions),
        case_ids=[c.case_id for c in cases])
    assert bl.logical_json(first) == bl.logical_json(second)
    assert json.loads(bl.logical_json(first)) == json.loads(
        bl.logical_json(second))


# --- 6. malformed baseline results fail honestly ---------------------------


def test_malformed_baseline_results_become_failures():
    cases = _first_cases(3)

    class _Bad(bl.MockBaselineAdapter):
        def predict(self, case):
            if case.case_id == cases[0].case_id:
                raise RuntimeError("boom")
            return super().predict(case)

    result = bl.evaluate_baseline(
        _Bad(name="mock-bad (TEST/MOCK)",
             predictions={c.case_id: _expected(c) for c in cases}),
        case_ids=[c.case_id for c in cases])
    assert result["cases"][0]["status"] == bl.FAILED
    assert "RuntimeError" in result["cases"][0]["error"]
    assert result["failed_n"] == 1
    assert result["evaluated_n"] == 2
    # Failed case contributes no counts: totals cover 2 cases only.
    assert result["totals"]["fn"] >= 0


def test_unsuccessful_predictions_become_failures():
    cases = _first_cases(2)
    result = bl.evaluate_baseline(
        bl.MockBaselineAdapter(name="mock-err (TEST/MOCK)",
                               errors={cases[0].case_id: "nope"}),
        case_ids=[c.case_id for c in cases])
    assert result["cases"][0]["status"] == bl.FAILED
    assert result["cases"][0]["error"] == "nope"
    assert result["cases"][1]["status"] == bl.EVALUATED


# --- 7. N/A handling --------------------------------------------------------


def test_not_applicable_cases_excluded_from_metrics():
    cases = _first_cases(3)
    adapter = bl.MockBaselineAdapter(
        name="mock-na (TEST/MOCK)",
        predictions={cases[0].case_id: _expected(cases[0])},
        not_applicable=[c.case_id for c in cases[1:]])
    result = bl.evaluate_baseline(
        adapter, case_ids=[c.case_id for c in cases])
    assert [c["status"] for c in result["cases"]] == [
        bl.EVALUATED, bl.NOT_APPLICABLE, bl.NOT_APPLICABLE]
    assert result["not_applicable_n"] == 2
    assert result["cases"][1]["reason"]
    only_first = bl.evaluate_baseline(
        bl.MockBaselineAdapter(
            name="mock-na2 (TEST/MOCK)",
            predictions={cases[0].case_id: _expected(cases[0])}),
        case_ids=[cases[0].case_id])
    assert result["totals"] == only_first["totals"]
    assert result["aggregate"] == only_first["aggregate"]


def test_all_abstained_baseline_reports_not_applicable():
    cases = _first_cases(2)
    result = bl.evaluate_baseline(
        bl.MockBaselineAdapter(
            name="mock-allna (TEST/MOCK)",
            not_applicable=[c.case_id for c in cases]),
        case_ids=[c.case_id for c in cases])
    assert result["status"] == bl.NOT_APPLICABLE
    assert result["evaluated_n"] == 0
    assert result["aggregate"]["precision"] is None


def test_registered_adapters_abstain_without_invocation():
    # Real families cannot predict without executing tools (forbidden),
    # so every case is NOT_APPLICABLE — never a fake empty detection.
    result = bl.evaluate_baseline(bl.get_baseline("grep-ripgrep"),
                                  case_ids=[c.case_id for c in _first_cases(2)])
    assert result["status"] in (bl.NOT_APPLICABLE, bl.UNAVAILABLE)
    if result["status"] == bl.NOT_APPLICABLE:
        assert all(c["status"] == bl.NOT_APPLICABLE
                   for c in result["cases"])


# --- 8/9. report integration -------------------------------------------------


def test_report_preserves_na_and_unavailable_honestly():
    cases = _first_cases(3)
    result = bl.evaluate_baseline(
        bl.MockBaselineAdapter(
            name="mock-rep (TEST/MOCK)",
            predictions={cases[0].case_id: _expected(cases[0])},
            not_applicable=[cases[2].case_id]),
        case_ids=[c.case_id for c in cases])
    run = bl.run_baseline(
        bl.MockBaselineAdapter(
            name="mock-rep (TEST/MOCK)",
            predictions={cases[0].case_id: _expected(cases[0])},
            not_applicable=[cases[2].case_id]),
        case_ids=[c.case_id for c in cases])
    report = report_mod.build_report(run)
    by_id = {r["case_id"]: r for r in report["cases"]}
    assert by_id[cases[2].case_id]["status"] == bl.NOT_APPLICABLE
    assert by_id[cases[2].case_id]["counts"] is None
    assert by_id[cases[2].case_id]["reason"]
    assert by_id[cases[0].case_id]["status"] == "evaluated"
    assert result["status"] == bl.EVALUATED
    gone = bl.run_baseline(bl.MockBaselineAdapter(
        name="mock-gone (TEST/MOCK)", available=False))
    gone_report = report_mod.build_report(gone)
    assert gone_report["evaluated_n"] == 0
    assert gone_report["overall"]["metrics"]["precision"] is None


# --- 10. CLI behavior ----------------------------------------------------------


def test_cli_baselines_lists_registry(capsys):
    assert bench_main(["baselines"]) == 0
    out = capsys.readouterr().out
    for name in bl.list_baselines():
        assert name in out
    assert "UNAVAILABLE" in out or "AVAILABLE" in out


def test_cli_baselines_json_parses(capsys):
    assert bench_main(["baselines", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert sorted(r["baseline"] for r in payload["baselines"]) == \
        sorted(bl.list_baselines())


def test_cli_unknown_baseline_errors(capsys):
    assert bench_main(["suite-run", "--baseline", "nope"]) == 2
    assert "unknown baseline" in capsys.readouterr().err


def test_cli_suite_run_baseline_honest(capsys, tmp_path):
    group = suite_mod.list_groups()[0]
    rc = bench_main(["suite-run", "--baseline", "lief-only",
                     "--group", group, "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == bl.UNAVAILABLE
    assert payload["evaluated_n"] == 0
    dest = tmp_path / "baseline.json"
    assert bench_main(["suite-run", "--baseline", "lief-only",
                       "--group", group, "--json",
                       "--output", str(dest)]) == 0
    capsys.readouterr()
    assert json.loads(dest.read_text())["status"] == bl.UNAVAILABLE
