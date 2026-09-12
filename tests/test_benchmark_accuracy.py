"""Tests for Task 16: ground-truth model + confusion-matrix metrics.

All expectations are HAND-CALCULATED literals (never the formulas
under test). Covers pairing, the seven standard metrics, zero-
denominator and unknown-universe honesty (explicit None + reason,
never fake zeros), invalid input, deterministic synthetic cases,
micro-average aggregation, and regression of the engineering-
dataset gate (still unavailable, still no accuracy keys in its
JSON). Stdlib only.
"""

import pytest

from ecdat.benchmark import ground_truth as gt
from ecdat.benchmark import metrics


def _case(expected, predicted, universe=None, synthetic=False):
    return gt.BenchmarkCase(
        case_id="t",
        group="source",
        ground_truth=gt.GroundTruth(
            expected=frozenset(expected),
            universe=None if universe is None else frozenset(universe),
            synthetic=synthetic,
        ),
        predicted=frozenset(predicted),
    )


# --- pairing -----------------------------------------------------------------


def test_pair_counts():
    counts = gt.pair(_case({"a", "b", "c"}, {"b", "c", "d"}, {"a", "b", "c", "d", "e", "f", "g", "h", "i"}))
    assert counts == {"tp": 2, "fp": 1, "fn": 1, "tn": 5,
                      "predicted_n": 3, "expected_n": 3}


def test_pair_without_universe_leaves_tn_unknown():
    counts = gt.pair(_case({"a"}, {"a", "b"}))
    assert counts["tn"] is None
    assert (counts["tp"], counts["fp"], counts["fn"]) == (1, 1, 0)


def test_pair_collapses_duplicate_predictions():
    case = _case({"a"}, ["a", "a", "a"], {"a", "b"})
    assert gt.pair(case)["tp"] == 1
    assert gt.pair(case)["predicted_n"] == 1


def test_finding_key_format():
    assert gt.finding_key("RSA-1024", "a.py", 12) == "RSA-1024@a.py:12"


# --- hand-calculated metrics: TP=2 FP=1 TN=5 FN=1 -------------------------------
# precision 2/3, recall 2/3, F1 2/3, accuracy 7/9,
# FPR 1/6, FNR 1/3, specificity 5/6.


def test_confusion_metrics_hand_calculated():
    got = metrics.confusion_metrics(2, 1, 5, 1)
    assert got["tp"] == 2 and got["fp"] == 1
    assert got["tn"] == 5 and got["fn"] == 1
    assert got["precision"] == pytest.approx(2 / 3)
    assert got["recall"] == pytest.approx(2 / 3)
    assert got["f1"] == pytest.approx(2 / 3)
    assert got["accuracy"] == pytest.approx(7 / 9)
    assert got["fpr"] == pytest.approx(1 / 6)
    assert got["fnr"] == pytest.approx(1 / 3)
    assert got["specificity"] == pytest.approx(5 / 6)
    assert got["unavailable"] == {}


def test_perfect_classification():
    got = metrics.confusion_metrics(3, 0, 4, 0)
    assert got["precision"] == 1.0 and got["recall"] == 1.0
    assert got["f1"] == 1.0 and got["accuracy"] == 1.0
    assert got["fpr"] == 0.0 and got["fnr"] == 0.0
    assert got["specificity"] == 1.0
    assert got["unavailable"] == {}


# --- zero-denominator honesty ------------------------------------------------------


def test_empty_confusion_reports_unavailable_not_zero():
    got = metrics.confusion_metrics(0, 0, 0, 0)
    assert got["precision"] is None
    assert got["recall"] is None
    assert got["f1"] is None
    assert got["accuracy"] is None
    assert got["fpr"] is None
    assert got["fnr"] is None
    assert got["specificity"] is None
    assert set(got["unavailable"]) == {"precision", "recall", "f1",
                                       "accuracy", "fpr", "fnr", "specificity"}


def test_unknown_universe_keeps_precision_recall_but_not_tn_metrics():
    got = metrics.confusion_metrics(2, 1, None, 1)
    assert got["precision"] == pytest.approx(2 / 3)
    assert got["recall"] == pytest.approx(2 / 3)
    assert got["f1"] == pytest.approx(2 / 3)
    assert got["fnr"] == pytest.approx(1 / 3)
    assert got["accuracy"] is None and got["fpr"] is None
    assert got["specificity"] is None
    assert set(got["unavailable"]) == {"accuracy", "fpr", "specificity"}


def test_no_expected_positives():
    got = metrics.confusion_metrics(0, 2, 5, 0)
    assert got["precision"] == pytest.approx(0.0)
    assert got["recall"] is None
    assert got["f1"] is None
    assert got["fnr"] is None
    assert got["accuracy"] == pytest.approx(5 / 7)


def test_invalid_counts_rejected():
    for bad in [(-1, 0, 0, 0), (0, -2, 0, 0), (0, 0, -1, 0), (0, 0, 0, -3),
                (1.5, 0, 0, 0), (0, 0, "5", 0)]:
        with pytest.raises(ValueError):
            metrics.confusion_metrics(*bad)


# --- end-to-end pairing -> metrics ---------------------------------------------------


def test_pair_then_metrics_end_to_end():
    counts = gt.pair(_case({"a", "b", "c"}, {"b", "c", "d"},
                            {"a", "b", "c", "d", "e", "f", "g", "h", "i"}))
    got = metrics.confusion_metrics(counts["tp"], counts["fp"],
                                    counts["tn"], counts["fn"])
    assert got["precision"] == pytest.approx(2 / 3)
    assert got["accuracy"] == pytest.approx(7 / 9)


# --- synthetic cases ---------------------------------------------------------------------


def test_synthetic_cases_are_deterministic_and_flagged():
    first = gt.synthetic_cases()
    assert gt.synthetic_cases() == first
    assert len(first) == 6  # 3 groups x 2
    assert {c.group for c in first} == {"source", "binary", "container"}
    assert all(c.ground_truth.synthetic for c in first)
    assert all("synthetic" in c.ground_truth.note.lower() for c in first)
    assert all(c.ground_truth.universe is not None for c in first)


def test_synthetic_cases_evaluate_without_unavailable():
    result = gt.evaluate_cases(gt.synthetic_cases())
    assert result["case_count"] == 6
    assert result["synthetic"] is True
    assert result["totals"]["tn"] is not None
    assert result["aggregate"]["unavailable"] == {}
    assert result["aggregate"]["precision"] is not None


# --- aggregation ------------------------------------------------------------------------------


def test_evaluate_cases_micro_average_hand_calculated():
    cases = [
        _case({"a", "b"}, {"a", "x"}, {"a", "b", "x", "y"}),
        _case({"c"}, {"c"}, {"c", "z"}),
    ]
    result = gt.evaluate_cases(cases)
    assert result["case_count"] == 2
    assert [c["case_id"] for c in result["cases"]] == ["t", "t"]
    # Totals: TP=2 (a,c), FP=1 (x), FN=1 (b), TN=2 (y,z).
    assert result["totals"] == {"tp": 2, "fp": 1, "tn": 2, "fn": 1}
    assert result["aggregate"]["precision"] == pytest.approx(2 / 3)
    assert result["aggregate"]["accuracy"] == pytest.approx(4 / 6)
    assert result["synthetic"] is False


def test_evaluate_cases_without_universe_marks_tn_metrics_unavailable():
    result = gt.evaluate_cases([_case({"a"}, {"a"})])
    assert result["totals"]["tn"] is None
    assert result["aggregate"]["precision"] == pytest.approx(1.0)
    assert result["aggregate"]["accuracy"] is None
    assert "accuracy" in result["aggregate"]["unavailable"]


def test_evaluate_empty_case_list():
    result = gt.evaluate_cases([])
    assert result["case_count"] == 0
    assert result["totals"] == {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    assert result["aggregate"]["precision"] is None


# --- engineering-gate regression ------------------------------------------------------------------


def test_engineering_gate_still_unavailable():
    status = metrics.accuracy_status()
    assert status["status"] == "unavailable"
    with pytest.raises(NotImplementedError):
        metrics.accuracy_status(ground_truth={"anything": True})
