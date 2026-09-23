"""Contract tests for the integrated client (unified backend).

The single production client is RealCoreClient: thin facade over
ScanOrchestrator. No mock client exists. No CLI/DB/exports here —
canonical conformance + request forwarding only.
"""

import pytest

from ecdat.core.client import CoreClient, RealCoreClient, get_client
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
    """Shared contract: valid canonical v1 shape."""
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


def _crypto(tmp_path, name="real_app.py"):
    target = tmp_path / name
    target.write_text(
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        "h = hashlib.md5(b'x').hexdigest()\n"
    )
    return target


def test_real_conforms_to_canonical(tmp_path):
    doc = RealCoreClient().scan(_crypto(tmp_path))
    assert_canonical(doc)
    # Deterministic rerun: same target -> same scan_id, no uuid4.
    again = RealCoreClient().scan(_crypto(tmp_path))
    assert again["scan_id"] == doc["scan_id"]
    assert doc["scan_id"].startswith("scan:")
    assert doc["target"].endswith("real_app.py")


def test_real_scan_with_cir_returns_tuple(tmp_path):
    cir, doc = RealCoreClient().scan_with_cir(_crypto(tmp_path))
    assert_canonical(doc)
    assert isinstance(cir, dict)
    assert cir["scan_id"] == doc["scan_id"]
    assert cir.get("risks") is not None


def test_real_rejects_unknown_scanners(tmp_path):
    pytest.importorskip("pydantic")
    from ecdat.adapters.pipeline import RealScanError

    target = tmp_path / "x.py"
    target.write_text("x = 1\n")
    with pytest.raises(RealScanError):
        RealCoreClient(scanners=["bogus-scanner"]).scan(target)


def test_real_rejects_unknown_options():
    with pytest.raises(ValueError):
        RealCoreClient(bogus_option=True)


def test_real_implements_protocol():
    assert isinstance(RealCoreClient(), CoreClient)


def test_factory_returns_integrated_client():
    assert isinstance(get_client(), RealCoreClient)


def test_cloud_credentials_reach_request():
    """Unification parity: GUI cloud-config fields exist on the CLI client."""
    import ecdat.core.orchestrator as orch

    seen = {}
    original = orch.ScanOrchestrator.scan

    def spy(self, request, progress=None):
        seen.update(
            access_key_id=request.cloud_aws_access_key_id,
            secret=request.cloud_aws_secret_access_key,
            token=request.cloud_aws_session_token,
            profile=request.cloud_aws_profile,
        )
        raise RuntimeError("stop here")

    orch.ScanOrchestrator.scan = spy
    try:
        with pytest.raises(RuntimeError, match="stop here"):
            RealCoreClient(
                scanners=["cloud"],
                cloud_aws_access_key_id="AKID",
                cloud_aws_secret_access_key="SECRET",
                cloud_aws_session_token="TOK",
                cloud_aws_profile="dev",
            ).scan_result("aws:dev:services=kms")
    finally:
        orch.ScanOrchestrator.scan = original
    assert seen == {"access_key_id": "AKID", "secret": "SECRET",
                    "token": "TOK", "profile": "dev"}
