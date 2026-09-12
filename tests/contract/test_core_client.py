"""Contract tests for CoreClient (Task 2).

Same assertions must pass against MockCoreClient now and RealCoreClient
later. Real-client conformance = passes these tests. No CLI/DB/exports
here — canonical conformance only.
"""

from pathlib import Path

import pytest

from ecdat.core.client import (
    CoreClient,
    MockCoreClient,
    RealCoreClient,
    get_client,
)
from ecdat.core.validate import validate

REQUIRED_TOP_KEYS = {
    "schema_version",
    "scan_id",
    "target",
    "started_at",
    "finished_at",
    "tool_versions",
    "findings",
    "stats",
}
REQUIRED_FINDING_KEYS = {"rule_id", "title", "severity", "file", "line"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}


def assert_canonical(doc: dict) -> None:
    """Shared contract: valid canonical v1 shape. Reused for real client later."""
    assert REQUIRED_TOP_KEYS <= set(doc), f"missing keys: {REQUIRED_TOP_KEYS - set(doc)}"
    assert doc["schema_version"] == "1.0"
    assert isinstance(doc["findings"], list)
    for f in doc["findings"]:
        assert REQUIRED_FINDING_KEYS <= set(f), f"finding missing keys: {f}"
        assert f["severity"] in SEVERITIES, f"bad severity: {f['severity']}"
        assert isinstance(f["line"], int) and f["line"] >= 0
    assert doc["stats"]["findings_count"] == len(doc["findings"])
    assert doc["stats"]["files_scanned"] >= 0
    validate(doc)  # must pass jsonschema


def test_mock_conforms_to_canonical(tmp_path):
    client = MockCoreClient()
    doc = client.scan(tmp_path / "rsa_small.py")
    assert_canonical(doc)


def test_mock_routing_empty(tmp_path):
    client = MockCoreClient()
    doc = client.scan(tmp_path / "clean.py")
    assert_canonical(doc)
    assert doc["findings"] == []
    assert doc["stats"]["findings_count"] == 0


def test_mock_routing_multi_for_directories(tmp_path):
    client = MockCoreClient()
    target = tmp_path / "app"
    target.mkdir()
    doc = client.scan(target)
    assert_canonical(doc)
    assert len(doc["findings"]) > 1


def test_mock_default_is_minimal(tmp_path):
    client = MockCoreClient()
    doc = client.scan(tmp_path / "something.py")
    assert_canonical(doc)
    assert len(doc["findings"]) == 1  # mirrors minimal.json


def test_mock_echoes_requested_target(tmp_path):
    client = MockCoreClient()
    target = tmp_path / "my_target.py"
    doc = client.scan(target)
    assert doc["target"] == str(target)


def test_mock_is_deterministic(tmp_path):
    client = MockCoreClient()
    target = tmp_path / "rsa_small.py"
    assert client.scan(target) == client.scan(target)


def test_mock_results_are_isolated(tmp_path):
    client = MockCoreClient()
    target = tmp_path / "rsa_small.py"
    first = client.scan(target)
    first["findings"].append({"bogus": True})
    second = client.scan(target)
    assert_canonical(second)
    assert len(second["findings"]) == 1


def test_mock_implements_protocol():
    assert isinstance(MockCoreClient(), CoreClient)
    assert isinstance(RealCoreClient(), CoreClient)


def test_factory_modes():
    assert isinstance(get_client("mock"), MockCoreClient)
    assert isinstance(get_client(), MockCoreClient)  # default is mock
    assert isinstance(get_client("real"), RealCoreClient)
    with pytest.raises(ValueError):
        get_client("bogus")


def test_real_placeholder_raises(tmp_path):
    with pytest.raises(NotImplementedError):
        get_client("real").scan(Path(tmp_path) / "x.py")
