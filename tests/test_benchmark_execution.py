"""Tests for Task 19: reproducible benchmark execution engine.

Covers run structure, selection (full/group/ids/empty/unknown),
failure explicitness, timing/resources honesty, logical-result
reproducibility, JSON/console serialization, metadata passthrough,
Task 18 reuse, and the suite-run CLI. Stdlib only.
"""

import json

import pytest

from ecdat.benchmark import __main__ as bench_main
from ecdat.benchmark import execution as exec_mod
from ecdat.benchmark import output as output_mod
from ecdat.benchmark.predictions import MockPredictionProvider, evaluate_selection


def _empty():
    return MockPredictionProvider()


# --- run structure -----------------------------------------------------------------


def test_run_result_shape():
    run = exec_mod.run_suite(_empty())
    for key in ("run_id", "engine", "engine_version", "started_at",
                "python", "platform", "suite_id", "suite_version",
                "provider", "selection", "case_count", "evaluated_n",
                "failed_n", "elapsed_s", "resources", "totals",
                "aggregate", "cases", "synthetic", "metadata", "note"):
        assert key in run
    assert run["engine"] == "ecdat-benchmark-execution"
    assert run["suite_id"] == "ecdat-seed-suite"
    assert run["provider"] == "mock-predictions"
    assert run["case_count"] == 23
    assert run["evaluated_n"] == 23 and run["failed_n"] == 0
    assert run["synthetic"] is True
    assert run["selection"] == {"group": None, "case_ids": None,
                                "resolved": [c["case_id"] for c in run["cases"]]}
    assert "no detector accuracy" in run["note"]


def test_run_reuses_task18_evaluation():
    provider = MockPredictionProvider({"source.aes.direct": ["x"]})
    run = exec_mod.run_suite(provider)
    expected = evaluate_selection(provider)
    assert run["totals"] == expected["totals"]
    assert run["aggregate"] == expected["aggregate"]
    assert [c["case_id"] for c in run["cases"]] == [
        c["case_id"] for c in expected["cases"]]


# --- selection --------------------------------------------------------------------------


def test_group_selection():
    run = exec_mod.run_suite(_empty(), group="config")
    assert run["case_count"] == 2
    assert run["selection"]["group"] == "config"
    assert all(c["group"] == "config" for c in run["cases"])


def test_case_id_selection():
    run = exec_mod.run_suite(
        _empty(), case_ids=["risk.low.synthetic", "source.aes.direct"])
    assert [c["case_id"] for c in run["cases"]] == [
        "risk.low.synthetic", "source.aes.direct"]
    assert run["selection"]["case_ids"] == ["risk.low.synthetic",
                                            "source.aes.direct"]


def test_unknown_selection_raises():
    with pytest.raises(ValueError):
        exec_mod.run_suite(_empty(), group="nope")
    with pytest.raises(ValueError):
        exec_mod.run_suite(_empty(), case_ids=["nope"])


def test_empty_selection_is_valid():
    run = exec_mod.run_suite(_empty(), case_ids=[])
    assert run["case_count"] == 0
    assert run["cases"] == []
    assert run["totals"] == {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    assert run["aggregate"]["precision"] is None


# --- failures --------------------------------------------------------------------------------


def test_all_failed_run_stays_valid_without_fake_accuracy():
    provider = MockPredictionProvider(
        errors={c: "down" for c in
                ["source.aes.direct", "source.hash.weak"]})
    run = exec_mod.run_suite(
        provider, case_ids=["source.aes.direct", "source.hash.weak"])
    assert run["failed_n"] == 2 and run["evaluated_n"] == 0
    assert all(c["status"] == "failed" for c in run["cases"])
    assert run["totals"] == {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    assert run["aggregate"]["accuracy"] is None
    assert "accuracy" in run["aggregate"]["unavailable"]


# --- timing / resources / metadata -------------------------------------------------------------------------


def test_timing_and_resources_measured():
    run = exec_mod.run_suite(_empty(), case_ids=["source.aes.direct"])
    assert run["elapsed_s"] >= 0.0
    assert set(run["resources"]) == {"peak_rss_bytes", "cpu_s", "note"}


def test_metadata_passthrough():
    run = exec_mod.run_suite(_empty(), case_ids=[], metadata={"ci": "demo"})
    assert run["metadata"] == {"ci": "demo"}
    assert exec_mod.run_suite(_empty(), case_ids=[])["metadata"] == {}


# --- reproducibility ---------------------------------------------------------------------------------------------


def test_logical_result_reproducible_across_runs():
    first = exec_mod.logical_result(exec_mod.run_suite(_empty()))
    second = exec_mod.logical_result(exec_mod.run_suite(_empty()))
    assert first == second
    assert json.loads(json.dumps(first)) == first
    assert "run_id" not in first and "elapsed_s" not in first
    assert "started_at" not in first and "resources" not in first


# --- serialization ------------------------------------------------------------------------------------------------------


def test_json_and_console():
    run = exec_mod.run_suite(_empty(), group="binary")
    text = exec_mod.to_json(run)
    assert output_mod.from_json(text) == json.loads(text)
    assert json.loads(text)["suite_id"] == "ecdat-seed-suite"
    summary = exec_mod.to_console(run)
    assert "ecdat-seed-suite" in summary
    assert "mock-predictions" in summary
    assert "synthetic: true" in summary
    assert "no detector accuracy claimed" in summary


# --- CLI -----------------------------------------------------------------------------------------------------------------------


def test_cli_suite_run_human(capsys):
    assert bench_main.main(["suite-run", "--group", "fusion"]) == 0
    out, _ = capsys.readouterr()
    assert "ecdat-seed-suite" in out
    assert "synthetic: true" in out


def test_cli_suite_run_json_pure(tmp_path, capsys):
    dest = tmp_path / "suite-run.json"
    assert bench_main.main(["suite-run", "--json", "--output", str(dest)]) == 0
    out, err = capsys.readouterr()
    assert err == ""
    run = json.loads(out)  # pure JSON on stdout
    assert run["case_count"] == 23
    assert output_mod.from_json(dest.read_text())["provider"] == "mock-predictions"
