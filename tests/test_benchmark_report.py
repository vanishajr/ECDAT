"""Tests for Task 20: benchmark report model + result analysis.

Hand-calculated literals throughout (never the formulas under
test), including the spec's aggregation example: Case 1
TP=2/FP=1/TN=5/FN=1 plus Case 2 TP=1/FP=0/TN=4/FN=1 aggregates
to TP=3/FP=1/TN=9/FN=2 with micro-average metrics — NOT the mean
of per-case percentages. Stdlib only.
"""

import json

import pytest

from ecdat.benchmark import execution as exec_mod
from ecdat.benchmark import report as report_mod
from ecdat.benchmark.predictions import MockPredictionProvider
from ecdat.benchmark.suite import get_case


def _eval_entry(case_id="source.aes.direct", group="source",
                status="evaluated", tp=2, fp=1, tn: int | None = 5, fn=1,
                predicted=("a", "b", "c"), error=None, synthetic=True):
    from ecdat.benchmark.metrics import confusion_metrics
    if status == "failed":
        return {"case_id": case_id, "group": group, "status": "failed",
                "predicted": None, "error": error or "boom",
                "counts": None, "metrics": None, "synthetic": synthetic}
    counts = {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
              "predicted_n": len(predicted), "expected_n": tp + fn}
    return {"case_id": case_id, "group": group, "status": "evaluated",
            "predicted": sorted(predicted), "error": None,
            "counts": counts,
            "metrics": confusion_metrics(tp, fp, tn, fn),
            "synthetic": synthetic}


def _run(cases, **fields):
    base = {
        "run_id": "suite-run-test", "engine": "ecdat-benchmark-execution",
        "suite_id": "ecdat-seed-suite", "suite_version": "1",
        "provider": "mock-predictions", "synthetic": True,
        "selection": {"group": None, "case_ids": None,
                      "resolved": [c["case_id"] for c in cases]},
        "case_count": len(cases),
        "evaluated_n": sum(1 for c in cases if c["status"] == "evaluated"),
        "failed_n": sum(1 for c in cases if c["status"] == "failed"),
        "elapsed_s": 0.5,
        "resources": {"peak_rss_bytes": 123, "cpu_s": 0.1, "note": "n"},
        "totals": {"tp": 3, "fp": 1, "tn": 9, "fn": 2},
        "aggregate": None, "cases": cases, "metadata": {},
    }
    from ecdat.benchmark.metrics import confusion_metrics
    base["aggregate"] = confusion_metrics(3, 1, 9, 2)
    base.update(fields)
    return base


# --- spec aggregation example --------------------------------------------------------
# Case 1 (2/1/5/1) + Case 2 (1/0/4/1) -> totals 3/1/9/2 (15 total):
# precision 3/4, recall 3/5, F1 2/3, accuracy 12/15, FPR 1/10,
# FNR 2/5, specificity 9/10. Per-case precisions are 2/3 and 1/1,
# whose mean (5/6) must NOT equal the micro precision (3/4).


def test_group_micro_aggregation_hand_calculated():
    group = report_mod.summarize_group("source", [
        _eval_entry("a"), _eval_entry("b", tp=1, fp=0, tn=4, fn=1,
                                      predicted=("a",))])
    assert group["group"] == "source"
    assert (group["cases"], group["evaluated"], group["failed"]) == (2, 2, 0)
    assert group["counts"] == {"tp": 3, "fp": 1, "tn": 9, "fn": 2}
    m = group["metrics"]
    assert m["precision"] == pytest.approx(3 / 4)
    assert m["recall"] == pytest.approx(3 / 5)
    assert m["f1"] == pytest.approx(2 / 3)
    assert m["accuracy"] == pytest.approx(12 / 15)
    assert m["fpr"] == pytest.approx(1 / 10)
    assert m["fnr"] == pytest.approx(2 / 5)
    assert m["specificity"] == pytest.approx(9 / 10)
    assert group["unavailable"] == {}
    # Micro-average, not mean-of-percentages (per-case precisions
    # 2/3 and 1/1 average to 5/6 ~= 0.833, far from the true 3/4):
    mean_of_percentages = (2 / 3 + 1) / 2
    assert abs(m["precision"] - mean_of_percentages) > 0.05


def test_group_tn_unknown_when_any_case_lacks_universe():
    group = report_mod.summarize_group("source", [
        _eval_entry("a"), _eval_entry("b", tn=None)])
    assert group["counts"] == {"tp": 4, "fp": 2, "tn": None, "fn": 2}
    assert group["metrics"]["accuracy"] is None
    assert "accuracy" in group["unavailable"]
    assert group["metrics"]["precision"] == pytest.approx(4 / 6)


# --- report from a real run ------------------------------------------------------------------


def _source_run():
    case = get_case("source.aes.direct")
    assert case is not None
    exp = sorted(case.ground_truth.expected)
    provider = MockPredictionProvider(
        {"source.aes.direct": exp + ["NOISE@x:1"], "source.hash.weak": []})
    return exec_mod.run_suite(provider, group="source")


def test_report_structure_from_successful_run():
    report = report_mod.build_report(_source_run())
    assert report["report"] == "ecdat-benchmark-report"
    assert report["report_version"] == "1"
    assert report["suite_id"] == "ecdat-seed-suite"
    assert report["provider"] == "mock-predictions"
    assert report["provider_type"] == "mock"
    assert report["synthetic"] is True
    assert (report["case_count"], report["evaluated_n"],
            report["failed_n"]) == (3, 3, 0)
    assert [g["group"] for g in report["groups"]] == ["source"]
    assert [c["case_id"] for c in report["cases"]] == [
        "source.aes.direct", "source.hash.weak", "source.plain.no_crypto"]
    assert report["failures"] == []
    assert "no detector accuracy is claimed" in report["note"]


def test_per_case_rows_from_run():
    report = report_mod.build_report(_source_run())
    rows = {c["case_id"]: c for c in report["cases"]}
    direct = rows["source.aes.direct"]
    assert direct["title"] == "Direct AES-ECB usage"
    assert direct["status"] == "evaluated"
    assert direct["synthetic"] is True
    assert direct["predicted_n"] == 2
    assert (direct["counts"]["tp"], direct["counts"]["fp"],
            direct["counts"]["fn"]) == (1, 1, 0)
    assert direct["error"] is None
    assert direct["unavailable"] == {}


def test_overall_reuses_run_totals():
    run = _source_run()
    report = report_mod.build_report(run)
    assert report["overall"]["counts"] == run["totals"]
    assert report["overall"]["metrics"] == run["aggregate"]
    assert report["performance"]["elapsed_s"] == run["elapsed_s"]
    assert report["performance"]["cpu_s"] == run["resources"]["cpu_s"]
    assert report["performance"]["peak_rss_bytes"] == run["resources"]["peak_rss_bytes"]
    assert "cache" not in json.dumps(report).lower()
    assert "superior" not in json.dumps(report).lower()
    assert "throughput" not in json.dumps(report).lower()


def test_provider_type_gate():
    run = _source_run()
    assert report_mod.build_report(run, provider_type="unknown")["provider_type"] == "unknown"
    with pytest.raises(ValueError):
        report_mod.build_report(run, provider_type="real")


# --- evaluated-with-unavailable vs failed -----------------------------------------------------------------


def test_evaluated_unavailable_metric_is_not_failed():
    from ecdat.benchmark.metrics import confusion_metrics
    counts = {"tp": 1, "fp": 0, "tn": None, "fn": 0,
              "predicted_n": 1, "expected_n": 1}
    entry = {"case_id": "u", "group": "source", "status": "evaluated",
             "predicted": ["a"], "error": None, "counts": counts,
             "metrics": confusion_metrics(1, 0, None, 0), "synthetic": True}
    report = report_mod.build_report(_run([entry], evaluated_n=1,
                                          totals={"tp": 1, "fp": 0, "tn": None, "fn": 0},
                                          aggregate=confusion_metrics(1, 0, None, 0)))
    row = report["cases"][0]
    assert row["status"] == "evaluated"
    assert row["metrics"]["accuracy"] is None
    assert "accuracy" in row["unavailable"]
    assert report["failures"] == []
    assert report["failed_n"] == 0
    assert report["unavailable"]["overall"]["accuracy"]


def test_failed_case_separate_no_fabricated_counts():
    report = report_mod.build_report(_run(
        [_eval_entry("a"), _eval_entry("bad", status="failed")],
        evaluated_n=1, failed_n=1,
        totals={"tp": 2, "fp": 1, "tn": 5, "fn": 1},
        aggregate=__import__("ecdat.benchmark.metrics", fromlist=["confusion_metrics"]).confusion_metrics(2, 1, 5, 1)))
    bad = [c for c in report["cases"] if c["case_id"] == "bad"][0]
    assert bad["status"] == "failed"
    assert bad["counts"] is None and bad["metrics"] is None
    assert bad["predicted_n"] is None
    assert report["failures"] == [{"case_id": "bad", "group": "source",
                                   "error": "boom"}]
    group = report["groups"][0]
    assert group["failed"] == 1 and group["failed_case_ids"] == ["bad"]
    assert group["counts"] == {"tp": 2, "fp": 1, "tn": 5, "fn": 1}


# --- serialization / determinism -------------------------------------------------------------------------------


def test_json_valid_and_deterministic():
    case = get_case("source.aes.direct")
    assert case is not None
    expected_keys: list[str] = sorted(case.ground_truth.expected)
    predictions: dict[str, list[str]] = {
        "source.aes.direct": expected_keys + ["NOISE@x:1"],
        "source.hash.weak": []}
    run = _source_run()
    first = json.loads(report_mod.to_json(report_mod.build_report(run)))
    assert first["suite_id"] == "ecdat-seed-suite"
    second_run = exec_mod.run_suite(MockPredictionProvider(predictions),
                                    group="source")
    second = json.loads(report_mod.to_json(
        report_mod.build_report(second_run)))
    # Volatile run metadata varies; logical report content must not.
    for doc in (first, second):
        del doc["run_id"]
        del doc["performance"]
    assert first == second
