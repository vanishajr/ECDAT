"""Tests for Task 17: benchmark suite + case registry.

Covers the required groups, id stability/uniqueness/ordering,
ground-truth validity, synthetic marking, lookup/filtering, suite
determinism, truth-vs-prediction independence, and the `cases` CLI
(human + JSON). Hand-checkable literals throughout; stdlib only.
"""

import dataclasses
import json

import pytest

from ecdat.benchmark import __main__ as bench_main
from ecdat.benchmark import output as output_mod
from ecdat.benchmark import suite as suite_mod
from ecdat.benchmark.ground_truth import BenchmarkCase, GroundTruth, pair

REQUIRED_GROUPS = [
    "source", "binary", "dependency", "container", "config",
    "certificate_key", "runtime_tls", "cloud_kms", "fusion",
    "risk", "pqc_recommendation",
]


# --- groups --------------------------------------------------------------------


def test_all_required_groups_exist_in_canonical_order():
    assert suite_mod.list_groups() == REQUIRED_GROUPS
    for group in REQUIRED_GROUPS:
        assert isinstance(suite_mod.group_description(group), str)
        assert suite_mod.group_description(group).strip() != ""


def test_unknown_group_description_raises():
    with pytest.raises(KeyError):
        suite_mod.group_description("nope")


# --- ids: unique, deterministic, ordered --------------------------------------------


def test_case_ids_unique_stable_ordered():
    first = [c.case_id for c in suite_mod.list_cases()]
    assert len(first) == len(set(first)) >= len(REQUIRED_GROUPS)
    assert [c.case_id for c in suite_mod.list_cases()] == first
    assert first[0] == "source.aes.direct"
    assert "source.plain.no_crypto" in first
    assert "pqc_recommendation.plain.non_pqc" in first


def test_every_case_in_valid_group_with_valid_ground_truth():
    for case in suite_mod.list_cases():
        assert case.group in REQUIRED_GROUPS
        assert isinstance(case.ground_truth, GroundTruth)
        assert isinstance(case.title, str) and case.title.strip()
        assert isinstance(case.description, str) and case.description.strip()
        assert isinstance(case.input_ref, str) and case.input_ref.strip()
        universe = case.ground_truth.universe
        assert universe is not None
        assert set(case.ground_truth.expected) <= set(universe)


def test_synthetic_marking_explicit():
    for case in suite_mod.list_cases():
        assert case.ground_truth.synthetic is True
        assert "synthetic" in case.tags
        assert "synthetic" in case.note.lower()
        assert "synthetic" in case.ground_truth.note.lower()


def test_suite_case_has_no_prediction_field():
    field_names = {f.name for f in dataclasses.fields(suite_mod.SuiteCase)}
    assert "predicted" not in field_names
    assert {"case_id", "group", "title", "description", "input_ref",
            "ground_truth", "tags", "note"} <= field_names


def test_invalid_suite_case_rejected():
    good = suite_mod.get_case("source.aes.direct")
    assert good is not None
    with pytest.raises(ValueError):
        suite_mod.SuiteCase(case_id="x", group="nope", title="t",
                            description="d", input_ref="i",
                            ground_truth=good.ground_truth)
    with pytest.raises(ValueError):
        suite_mod.SuiteCase(case_id="", group="source", title="t",
                            description="d", input_ref="i",
                            ground_truth=good.ground_truth)


# --- lookup / filtering -----------------------------------------------------------------


def test_lookup_hit_and_miss():
    case = suite_mod.get_case("config.tls.weak")
    assert case is not None
    assert case.group == "config"
    assert case.title == "Weak TLS configuration"
    assert suite_mod.get_case("does.not.exist") is None


def test_group_filtering():
    source = suite_mod.list_cases("source")
    assert {c.case_id for c in source} == {"source.aes.direct",
                                           "source.hash.weak",
                                           "source.plain.no_crypto"}
    assert all(c.group == "source" for c in source)
    assert len(suite_mod.list_cases("risk")) == 2
    with pytest.raises(ValueError):
        suite_mod.list_cases("nope")


# --- suite envelope -----------------------------------------------------------------------------


def test_default_suite_deterministic():
    first = suite_mod.get_default_suite()
    assert suite_mod.get_default_suite() == first
    assert first["suite_id"] == "ecdat-seed-suite"
    assert first["version"] == "1"
    assert first["groups"] == REQUIRED_GROUPS
    assert first["case_count"] == len(first["cases"]) == len(suite_mod.list_cases())
    assert first["synthetic"] is True
    assert "no detector" in first["note"].lower()
    text = output_mod.to_json(first)
    assert output_mod.from_json(text) == json.loads(text)


# --- truth independence -----------------------------------------------------------------------------


def test_ground_truth_independent_of_predictions():
    # Empty predictions against every positive case: truth must stand
    # (FN == expected_n proves expected was NOT copied from predictions).
    positives = [c for c in suite_mod.list_cases()
                 if "positive" in c.tags]
    assert positives
    for case in positives:
        assert len(case.ground_truth.expected) >= 1
        counts = pair(suite_mod.with_predictions(case, []))
        assert counts["tp"] == 0 and counts["fp"] == 0
        assert counts["fn"] == counts["expected_n"] >= 1


def test_with_predictions_bridges_to_task16_model():
    case = suite_mod.get_case("source.aes.direct")
    assert case is not None
    expected = next(iter(case.ground_truth.expected))
    bridged = suite_mod.with_predictions(case, [expected, "NOISE@x:1"])
    assert isinstance(bridged, BenchmarkCase)
    assert bridged.case_id == case.case_id and bridged.group == case.group
    assert bridged.ground_truth is case.ground_truth
    counts = pair(bridged)
    assert (counts["tp"], counts["fp"], counts["fn"]) == (1, 1, 0)


def test_negative_case_scores_tn_with_empty_predictions():
    case = suite_mod.get_case("source.plain.no_crypto")
    assert case is not None
    counts = pair(suite_mod.with_predictions(case, []))
    assert counts["tp"] == 0 and counts["fp"] == 0 and counts["fn"] == 0
    assert counts["tn"] == 2  # two absent-by-construction decoys


# --- CLI -----------------------------------------------------------------------------


def test_cli_cases_human_lists_all(capsys):
    assert bench_main.main(["cases"]) == 0
    out, _ = capsys.readouterr()
    assert "source.aes.direct" in out
    assert "pqc_recommendation.plain.non_pqc" in out
    assert "synthetic=true" in out
    assert "no detector evaluated" in out


def test_cli_cases_group_filter(capsys):
    assert bench_main.main(["cases", "--group", "binary"]) == 0
    out, _ = capsys.readouterr()
    assert "binary.crypto.symbol" in out
    assert "source.aes.direct" not in out


def test_cli_cases_json_pure(capsys):
    assert bench_main.main(["cases", "--group", "config", "--json"]) == 0
    out, err = capsys.readouterr()
    assert err == ""
    suite = json.loads(out)  # pure JSON, no human lines
    assert suite["case_count"] == 2
    assert all(c["group"] == "config" for c in suite["cases"])
    assert all(c["synthetic"] is True for c in suite["cases"])
    assert suite["cases"][0]["case_id"] == "config.tls.weak"


def test_cli_cases_invalid_group_rejected():
    with pytest.raises(SystemExit) as exc:
        bench_main.main(["cases", "--group", "nope"])
    assert exc.value.code == 2
