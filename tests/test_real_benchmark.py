"""Characterization benchmark tests (no accuracy claims).

Verifies the honest-measurement providers run and stay labeled as
characterization. Asserts structure and labeling — never threshold
values, superiority, or production precision/recall.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.skipif(
    __import__("importlib").util.find_spec("pydantic") is None,
    reason="real benchmark providers need pydantic",
)

from ecdat.benchmark import providers_real as real


def test_ground_truth_loads():
    fixtures = real.load_p2_ground_truth()
    assert len(fixtures) == 17
    assert all("fixture_path" in f and "expected_findings" in f
               for f in fixtures)


def test_expected_keys_use_shared_rule_vocabulary():
    fixtures = real.load_p2_ground_truth()
    keys, window = real.expected_keys_for_fixture(fixtures[0])
    assert keys and window >= 0
    assert all("@" in k for k in keys)


def test_cases_are_labeled_not_production():
    cases = real.p2_ground_truth_cases(limit=2)
    assert len(cases) == 2
    for case in cases:
        assert case.ground_truth.synthetic is False
        assert "not production accuracy" in case.note.lower()


def test_provider_predicts_on_real_fixtures():
    provider = real.RealDetectorProvider()
    cases = real.p2_ground_truth_cases(limit=2)
    for case in cases:
        prediction = provider.predict(case)
        assert prediction.ok, prediction.error
        assert isinstance(prediction.keys, frozenset)


def test_provider_total_on_missing_target():
    from ecdat.benchmark.suite import SuiteCase
    from ecdat.benchmark.ground_truth import GroundTruth

    provider = real.RealDetectorProvider()
    case = SuiteCase(case_id="missing", group="source", title="t",
                     description="d", input_ref="no/such/file.py",
                     ground_truth=GroundTruth(expected=frozenset()))
    prediction = provider.predict(case)
    assert prediction.ok is False
    assert prediction.error


def test_characterize_detector_labels_results():
    result = real.characterize_detector(real.p2_ground_truth_cases(limit=2))
    assert "aggregate" in result or "per_case" in result
    assert result["characterization"]["dataset"] == real.DATASET_ID
    assert "not production" in result["characterization"]["warning"].lower()


def test_measure_performance_returns_raw_rows(tmp_path):
    target = tmp_path / "a.py"
    target.write_text("import hashlib\nh = hashlib.md5(b'x').hexdigest()\n")
    rows = real.measure_performance([str(target)])
    assert len(rows) == 1
    row = rows[0]
    assert row["target"] == str(target)
    assert isinstance(row["elapsed_s"], float) and row["elapsed_s"] >= 0
    assert row["findings"] >= 1
    assert "error" not in row


def test_measure_performance_records_errors():
    rows = real.measure_performance(["/nonexistent/xyz"])
    assert len(rows) == 1 and "error" in rows[0]
