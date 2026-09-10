"""Tests for provisional canonical v1 validation + models.

Covers: all valid fixtures accepted, malformed docs rejected,
models round-trip without business logic.
"""

from pathlib import Path

import jsonschema
import pytest

from ecdat.core.models import Scan
from ecdat.core.validate import load_json, validate

FIXTURES = Path(__file__).parent / "fixtures" / "canonical"


@pytest.mark.parametrize(
    "name", ["minimal.json", "multi.json", "empty.json"]
)
def test_valid_fixtures_pass(name):
    doc = load_json(FIXTURES / name)
    assert validate(doc) == doc


def test_stats_count_matches_findings():
    # Contract guard: stats.findings_count must equal len(findings).
    for name in ["minimal.json", "multi.json", "empty.json"]:
        doc = load_json(FIXTURES / name)
        validate(doc)
        assert doc["stats"]["findings_count"] == len(doc["findings"])


def test_models_roundtrip_minimal():
    doc = load_json(FIXTURES / "minimal.json")
    scan = Scan.from_dict(validate(doc))
    assert scan.scan_id == "scan-minimal-001"
    assert len(scan.findings) == 1
    assert scan.to_dict() == doc


def test_models_roundtrip_multi_and_empty():
    for name in ["multi.json", "empty.json"]:
        doc = load_json(FIXTURES / name)
        scan = Scan.from_dict(validate(doc))
        assert scan.to_dict() == doc


def test_reject_missing_findings():
    doc = load_json(FIXTURES / "minimal.json")
    del doc["findings"]
    with pytest.raises(jsonschema.ValidationError):
        validate(doc)


def test_reject_bad_severity():
    doc = load_json(FIXTURES / "minimal.json")
    doc["findings"][0]["severity"] = "urgent"
    with pytest.raises(jsonschema.ValidationError):
        validate(doc)


def test_reject_line_as_string():
    doc = load_json(FIXTURES / "minimal.json")
    doc["findings"][0]["line"] = "12"
    with pytest.raises(jsonschema.ValidationError):
        validate(doc)


def test_reject_negative_files_scanned():
    doc = load_json(FIXTURES / "minimal.json")
    doc["stats"]["files_scanned"] = -1
    with pytest.raises(jsonschema.ValidationError):
        validate(doc)


def test_reject_wrong_schema_version():
    doc = load_json(FIXTURES / "minimal.json")
    doc["schema_version"] = "2.0"
    with pytest.raises(jsonschema.ValidationError):
        validate(doc)


def test_reject_extra_top_level_field():
    doc = load_json(FIXTURES / "minimal.json")
    doc["invented_field"] = "should-fail"
    with pytest.raises(jsonschema.ValidationError):
        validate(doc)
