"""Tests for Task 18: prediction adapter layer.

Covers the PredictionProvider interface, the explicit-only mock,
hand-calculated TP/FP/FN outcomes (expected {a,b} / predicted {a,c}
-> 1/1/1), failure capture, selection filtering, deterministic
ordering, Task 16 reuse, and unavailable preservation. Stdlib only.
"""

import json

import pytest

from ecdat.benchmark import metrics as metrics_mod
from ecdat.benchmark import predictions as pred_mod
from ecdat.benchmark import suite as suite_mod
from ecdat.benchmark.ground_truth import GroundTruth, evaluate_cases, pair
from ecdat.benchmark.suite import SuiteCase, with_predictions


def _suite_case(case_id="t", group="source", expected=("a", "b"),
                universe=("a", "b", "c", "d")):
    return SuiteCase(
        case_id=case_id,
        group=group,
        title="t",
        description="d",
        input_ref="seed/t",
        ground_truth=GroundTruth(expected=frozenset(expected),
                                 universe=frozenset(universe),
                                 synthetic=True),
    )


def _eval(predictions=None, errors=None, **kwargs):
    provider = pred_mod.MockPredictionProvider(predictions=predictions,
                                               errors=errors)
    if "cases" in kwargs:
        return pred_mod.evaluate_suite(kwargs["cases"], provider), provider
    return pred_mod.evaluate_selection(provider, **kwargs), provider


# --- interface + mock ---------------------------------------------------------------


def test_provider_interface():
    provider = pred_mod.MockPredictionProvider()
    assert isinstance(provider, pred_mod.PredictionProvider)
    assert provider.name == "mock-predictions"


def test_mock_returns_explicitly_configured_predictions():
    case = _suite_case()
    provider = pred_mod.MockPredictionProvider({"t": ["x", "y"]})
    got = provider.predict(case)
    assert got.ok is True and got.error is None
    assert set(got.keys) == {"x", "y"}


def test_mock_never_derives_from_ground_truth():
    case = _suite_case()  # expected {a, b}
    provider = pred_mod.MockPredictionProvider()
    assert set(provider.predict(case).keys) == set()
    counts = pair(with_predictions(case, provider.predict(case).keys))
    assert (counts["tp"], counts["fp"], counts["fn"]) == (0, 0, 2)


# --- hand-calculated outcomes ------------------------------------------------------------
# expected {a,b} / predicted {a,c} over universe {a,b,c,d} -> TP=1 FP=1 FN=1 TN=1.


def test_mixed_prediction_counts():
    result, _ = _eval({"t": ["a", "c"]}, cases=[_suite_case()])
    entry = result["cases"][0]
    assert entry["status"] == "evaluated"
    assert entry["counts"] == {"tp": 1, "fp": 1, "fn": 1, "tn": 1,
                               "predicted_n": 2, "expected_n": 2}
    assert entry["predicted"] == ["a", "c"]  # sorted, deterministic
    assert entry["metrics"]["precision"] == pytest.approx(1 / 2)
    assert entry["metrics"]["recall"] == pytest.approx(1 / 2)


def test_perfect_prediction():
    result, _ = _eval({"t": ["a", "b"]}, cases=[_suite_case()])
    counts = result["cases"][0]["counts"]
    assert (counts["tp"], counts["fp"], counts["fn"], counts["tn"]) == (2, 0, 0, 2)
    assert result["aggregate"]["accuracy"] == pytest.approx(1.0)


def test_false_negative_only():
    result, _ = _eval({"t": ["a"]}, cases=[_suite_case()])
    counts = result["cases"][0]["counts"]
    assert (counts["tp"], counts["fp"], counts["fn"], counts["tn"]) == (1, 0, 1, 2)


def test_empty_prediction():
    result, _ = _eval(cases=[_suite_case()])
    counts = result["cases"][0]["counts"]
    assert (counts["tp"], counts["fp"], counts["fn"], counts["tn"]) == (0, 0, 2, 2)


def test_negative_only_case():
    neg = _suite_case(case_id="n", expected=(), universe=("z",))
    result, _ = _eval(cases=[neg])
    assert result["cases"][0]["counts"]["tn"] == 1
    result, _ = _eval({"n": ["z"]}, cases=[neg])
    assert result["cases"][0]["counts"]["fp"] == 1


# --- failures -------------------------------------------------------------------------------


def test_provider_failure_is_explicit():
    result, _ = _eval(errors={"t": "detector blew up"}, cases=[_suite_case()])
    entry = result["cases"][0]
    assert entry["status"] == "failed"
    assert entry["error"] == "detector blew up"
    assert entry["predicted"] is None
    assert entry["counts"] is None and entry["metrics"] is None
    assert result["failed_n"] == 1 and result["evaluated_n"] == 0


def test_failed_case_contributes_no_counts():
    cases = [_suite_case("ok", expected=("a",), universe=("a", "b")),
             _suite_case("bad", expected=("a",), universe=("a", "b"))]
    result, _ = _eval({"ok": ["a"], "bad": ["a"]}, errors={"bad": "boom"},
                      cases=cases)
    assert result["totals"] == {"tp": 1, "fp": 0, "tn": 1, "fn": 0}
    assert result["aggregate"]["accuracy"] == pytest.approx(1.0)
    statuses = {c["case_id"]: c["status"] for c in result["cases"]}
    assert statuses == {"ok": "evaluated", "bad": "failed"}


def test_raising_provider_is_captured_not_raised():
    class _Boom:
        name = "boom"

        def predict(self, case):
            raise RuntimeError("kaput")

    result = pred_mod.evaluate_suite([_suite_case()], _Boom())
    assert result["cases"][0]["status"] == "failed"
    assert "RuntimeError: kaput" in result["cases"][0]["error"]
    assert result["totals"] == {"tp": 0, "fp": 0, "tn": 0, "fn": 0}


# --- selection -------------------------------------------------------------------------------


def test_full_suite_evaluation():
    result, _ = _eval()
    assert result["suite_id"] == "ecdat-seed-suite"
    assert result["version"] == "1"
    assert result["provider"] == "mock-predictions"
    assert result["case_count"] == 23
    assert result["evaluated_n"] == 23 and result["failed_n"] == 0
    assert [c["case_id"] for c in result["cases"]] == [
        c.case_id for c in suite_mod.list_cases()]


def test_group_filtering():
    result, _ = _eval(group="risk")
    assert result["case_count"] == 2
    assert all(c["group"] == "risk" for c in result["cases"])


def test_case_subset_filtering_preserves_given_order():
    result, _ = _eval(case_ids=["risk.low.synthetic", "source.aes.direct"])
    assert [c["case_id"] for c in result["cases"]] == [
        "risk.low.synthetic", "source.aes.direct"]
    with pytest.raises(ValueError):
        _eval(case_ids=["nope"])


def test_deterministic_result_ordering():
    first, _ = _eval(group="source")
    second, _ = _eval(group="source")
    assert first == second
    assert json.loads(json.dumps(first)) == first  # serializable


# --- Task 16 reuse ---------------------------------------------------------------------------------


def test_adapter_reaches_task16_pairing():
    case = _suite_case()
    predicted = ["a", "c"]
    direct = pair(with_predictions(case, predicted))
    result, _ = _eval({"t": predicted}, cases=[case])
    assert result["cases"][0]["counts"] == direct


def test_aggregate_reuses_task16_formulas():
    cases = [_suite_case("one", expected=("a",), universe=("a", "b")),
             _suite_case("two", expected=("c",), universe=("c", "d"))]
    result, _ = _eval({"one": ["a"], "two": ["x"]}, cases=cases)
    totals = result["totals"]
    assert totals == {"tp": 1, "fp": 1, "tn": 2, "fn": 1}
    assert result["aggregate"] == metrics_mod.confusion_metrics(1, 1, 2, 1)
    bridged = [with_predictions(c, {"one": ["a"], "two": ["x"]}[c.case_id])
               for c in cases]
    assert result["aggregate"] == evaluate_cases(bridged)["aggregate"]


def test_unavailable_metrics_preserved():
    no_universe = SuiteCase(
        case_id="u", group="source", title="t", description="d",
        input_ref="seed/u",
        ground_truth=GroundTruth(expected=frozenset({"a"}), universe=None,
                                 synthetic=True))
    result, _ = _eval({"u": ["a"]}, cases=[no_universe])
    assert result["aggregate"]["accuracy"] is None
    assert "accuracy" in result["aggregate"]["unavailable"]
    assert result["aggregate"]["precision"] == pytest.approx(1.0)
    per_case = result["cases"][0]
    assert per_case["counts"]["tn"] is None
    assert per_case["metrics"]["accuracy"] is None
    assert "accuracy" in per_case["metrics"]["unavailable"]
