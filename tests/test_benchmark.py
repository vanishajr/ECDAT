"""Tests for the Person 3 benchmarking foundation (mock-only, stdlib only).

Covers deterministic datasets, result structure, success/failure
runs, metric math, JSON round-trip, DB integrity across repeated
runs, fixture immutability, and the standalone entry point. No
accuracy claims are tested because none are made.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ecdat.benchmark import __main__ as bench_main
from ecdat.benchmark import datasets, metrics, output, resources, runner
from ecdat.benchmark.targets import (
    BenchmarkTarget,
    MockPipelineTarget,
    RunContext,
    TargetResult,
)
from ecdat.core.validate import validate
from ecdat.store import db
from ecdat.store import scans as sstore

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "canonical"


def _snapshot_fixtures() -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(FIXTURE_DIR.glob("*.json"))}


# --- datasets ------------------------------------------------------------------


def test_datasets_are_deterministic():
    assert datasets.build_dataset("small") == datasets.build_dataset("small")
    assert datasets.build_dataset("large")["seed"] == 33


def test_dataset_sizes_and_validity():
    specs = {"small": (2, 4), "medium": (5, 20), "large": (10, 100)}
    for name, (docs, per_doc) in specs.items():
        ds = datasets.build_dataset(name)
        assert len(ds["docs"]) == docs
        ids = set()
        for doc in ds["docs"]:
            validate(doc)  # canonical-valid by construction
            assert len(doc["findings"]) == per_doc
            assert doc["stats"]["findings_count"] == per_doc
            assert doc["stats"]["files_scanned"] >= 1
            ids.add(doc["scan_id"])
        assert len(ids) == docs  # distinct scan ids


def test_datasets_carry_no_ground_truth():
    for name in datasets.list_datasets():
        for doc in datasets.build_dataset(name)["docs"]:
            for finding in doc["findings"]:
                assert "label" not in finding and "ground_truth" not in finding


def test_building_datasets_does_not_mutate_fixtures():
    before = _snapshot_fixtures()
    for name in datasets.list_datasets():
        datasets.build_dataset(name)
    assert _snapshot_fixtures() == before


def test_unknown_dataset_raises():
    with pytest.raises(KeyError):
        datasets.build_dataset("nope")


# --- metrics -------------------------------------------------------------------


def test_summarize_math():
    s = metrics.summarize([1.0, 2.0, 3.0])
    assert s == {"count": 3, "total_s": 6.0, "mean_s": 2.0, "min_s": 1.0, "max_s": 3.0}
    assert metrics.summarize([])["count"] == 0


def test_success_rate_and_throughput():
    runs = [{"ok": True}, {"ok": False}, {"ok": True}]
    assert metrics.success_rate(runs) == {"ok": 2, "total": 3, "rate": 2 / 3}
    assert metrics.throughput(100, 4.0)["findings_per_s"] == 25.0
    assert metrics.throughput(100, 0.0)["findings_per_s"] == 0.0


def test_accuracy_unavailable_without_ground_truth():
    status = metrics.accuracy_status()
    assert status["status"] == "unavailable"
    assert "ground-truth" in status["reason"]
    with pytest.raises(NotImplementedError):
        metrics.accuracy_status(ground_truth={"scan": ["TP"]})


def test_resources_never_faked():
    got = resources.collect(resources.cpu_times(), resources.now_wall())
    assert set(got) == {"peak_rss_bytes", "cpu_s", "note"}
    assert got["peak_rss_bytes"] is None or got["peak_rss_bytes"] >= 0
    assert got["cpu_s"] is None or got["cpu_s"] >= 0.0


# --- runner --------------------------------------------------------------------


def test_successful_run_structure(tmp_path):
    result = runner.run_benchmark("small", db_path=tmp_path / "b.db")
    assert result["result_version"] == "1"
    assert result["target"] == "mock-pipeline"
    assert result["dataset"] == {
        "name": "small", "seed": 11, "docs": 2, "findings": 8}
    assert result["success"] == {"ok": 2, "total": 2, "rate": 1.0}
    assert result["output_bytes"] > 0
    assert result["accuracy"]["status"] == "unavailable"
    assert len(result["runs"]) == 2
    for run in result["runs"]:
        assert run["ok"] is True and run["error"] is None
        assert run["elapsed_s"] >= 0.0 and run["output_bytes"] > 0
    assert "mock" in result["notes"][0].lower()


class _FailingTarget:
    name = "failing"

    def run(self, doc, ctx):
        raise RuntimeError("boom")


def test_failed_runs_are_captured_not_raised(tmp_path):
    result = runner.run_benchmark("small", target=_FailingTarget(),
                                  db_path=tmp_path / "b.db")
    assert result["success"] == {"ok": 0, "total": 2, "rate": 0.0}
    assert all(r["ok"] is False for r in result["runs"])
    assert all("RuntimeError: boom" in r["error"] for r in result["runs"])


def test_repeated_runs_do_not_corrupt_db(tmp_path):
    db_file = tmp_path / "reuse.db"
    first = runner.run_benchmark("small", db_path=db_file)
    second = runner.run_benchmark("small", db_path=db_file)
    assert first["success"]["rate"] == 1.0 == second["success"]["rate"]
    conn = db.open_db(db_file)
    try:
        assert sstore.count_scans(conn) == 2  # no duplicates
    finally:
        conn.close()


def test_running_benchmarks_does_not_mutate_fixtures():
    before = _snapshot_fixtures()
    runner.run_benchmark("medium")
    assert _snapshot_fixtures() == before


def test_target_result_contract():
    target = MockPipelineTarget()
    assert isinstance(target, BenchmarkTarget)  # satisfies the Protocol
    assert target.name == "mock-pipeline"
    doc = datasets.build_dataset("small")["docs"][0]
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        res = target.run(doc, RunContext(db_path=Path(tmp) / "t.db", run_id="r"))
    assert isinstance(res, TargetResult) and res.ok and res.output_bytes > 0


# --- output --------------------------------------------------------------------


def test_json_round_trip_and_stability(tmp_path):
    result = runner.run_benchmark("small", db_path=tmp_path / "b.db")
    text = output.to_json(result)
    assert output.from_json(text) == json.loads(text)
    assert text == output.to_json(output.from_json(text))  # stable
    lowered = text.lower()
    for claimed in ('"precision"', '"recall"', '"f1"', '"fpr"', '"fnr"'):
        assert claimed not in lowered
    assert output.from_json(text)["accuracy"]["status"] == "unavailable"


def test_console_summary_states_mock_only(tmp_path):
    result = runner.run_benchmark("small", db_path=tmp_path / "b.db")
    summary = output.to_console(result)
    assert "mock-pipeline" in summary and "small" in summary
    assert "mock engineering measurement only" in summary
    assert "unavailable" in summary


# --- entry point -----------------------------------------------------------------


def test_entry_list(capsys):
    assert bench_main.main(["list"]) == 0
    out, _ = capsys.readouterr()
    assert "small" in out and "medium" in out and "large" in out


def test_entry_run_writes_json(tmp_path, capsys):
    dest = tmp_path / "bench.json"
    assert bench_main.main(["run", "--dataset", "small", "--output", str(dest),
                            "--db", str(tmp_path / "b.db")]) == 0
    capsys.readouterr()
    assert output.from_json(dest.read_text())["dataset"]["name"] == "small"
