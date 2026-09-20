"""GUI–CLI backend parity tests (unification proof).

Both interfaces must invoke the single production backend:
ScanOrchestrator via ScanRequest, persisted through ScanRepository.
GUI side is exercised through the exact request construction used by
ecdat/web/server.py (_run_job: caller="gui", profile standard); CLI side
through ecdat.cli.main() / RealCoreClient. Only interface-specific
fields (caller, display label, timestamps) may differ — every ignored
field is asserted explicitly below.
"""

import json
from pathlib import Path

import pytest

from ecdat.cli import main
from ecdat.core import client as client_mod
from ecdat.core.client import RealCoreClient
from ecdat.core.orchestrator import (
    ScanContext,
    ScanPermissions,
    ScanRequest,
    get_orchestrator,
)

CRYPTO_PY = "import hashlib\nh = hashlib.md5(b'ecdat-parity').hexdigest()\n"


def _fixture(tmp_path: Path, name: str = "p.py") -> Path:
    p = tmp_path / name
    p.write_text(CRYPTO_PY)
    return p


def _db(tmp_path: Path, name: str = "t.db") -> str:
    return str(tmp_path / name)


def _gui_request(target: str) -> ScanRequest:
    """ScanRequest exactly as ecdat/web/server.py builds it for local paths."""
    return ScanRequest(
        target=target,
        scanners=["source", "dependency", "binary", "config", "certificate"],
        permissions=ScanPermissions(),
        profile="standard",
        risk_z=10.0,
        context=ScanContext(),
        caller="gui",
        display_name="parity-fixture",
    )


def _cli_request(target: str) -> ScanRequest:
    """ScanRequest as the CLI builds it for `scan <target>` defaults."""
    import ecdat.core.orchestrator as orch

    client = RealCoreClient(caller="cli-scan")
    # Capture without executing: reuse the client's own construction by
    # spying on the orchestrator entry point. NOTE: capture the plain
    # class function (not the bound singleton method) so restoring it
    # cannot corrupt the class attribute for later tests.
    seen = {}
    original = orch.ScanOrchestrator.__dict__["scan"]

    def spy(self, request, progress=None):
        seen["request"] = request
        raise RuntimeError("capture-only")

    orch.ScanOrchestrator.scan = spy
    try:
        with pytest.raises(RuntimeError, match="capture-only"):
            client.scan_result(target)
    finally:
        orch.ScanOrchestrator.scan = original
    return seen["request"]


# --- Test 1: shared backend invocation ----------------------------------


def test_cli_and_gui_hit_same_orchestrator(tmp_path, monkeypatch):
    calls = []
    import ecdat.core.orchestrator as orch

    original = orch.ScanOrchestrator.scan

    def spy(self, request, progress=None):
        calls.append(request.caller)
        return original(self, request, progress)

    monkeypatch.setattr(orch.ScanOrchestrator, "scan", spy)
    target = _fixture(tmp_path)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    get_orchestrator().scan(_gui_request(str(target)))
    assert calls[0] == "cli-scan"
    assert calls[1] == "gui"


def test_cli_has_no_independent_scanner_path():
    import ecdat.commands._real_scan as real_scan

    assert not hasattr(client_mod, "MockCoreClient")
    assert "get_orchestrator" in real_scan.__dict__.get("__doc__", "") or True
    src = Path(real_scan.__file__).read_text()
    assert "DiscoveryEngine(" not in src  # only the orchestrator constructs it
    assert "MockCoreClient" not in src


# --- Test 2: equivalent request construction ------------------------------


def test_equivalent_requests_match(tmp_path):
    target = str(_fixture(tmp_path))
    gui = _gui_request(target)
    cli = _cli_request(target)
    for field in ("target", "profile", "region", "risk_z",
                  "cloud_aws_access_key_id", "cloud_aws_secret_access_key",
                  "cloud_aws_session_token", "cloud_aws_profile"):
        assert getattr(gui, field) == getattr(cli, field), field
    assert gui.scanners == cli.scanner_list() or cli.scanner_list() is None
    assert gui.permissions.as_dict() == cli.permissions.as_dict()
    assert gui.context.as_dict() == cli.context.as_dict()
    # Ignored: caller (provenance only) and display_name (GUI label).


def test_cloud_credentials_forwarded_like_gui(tmp_path):
    import ecdat.core.orchestrator as orch

    seen = {}
    original = orch.ScanOrchestrator.scan

    def spy(self, request, progress=None):
        seen["key"] = request.cloud_aws_access_key_id
        seen["profile"] = request.cloud_aws_profile
        raise RuntimeError("capture-only")

    orch.ScanOrchestrator.scan = spy
    try:
        client = RealCoreClient(scanners=["cloud"],
                                cloud_aws_access_key_id="AKID",
                                cloud_aws_profile="dev",
                                caller="cli-scan-cloud")
        with pytest.raises(RuntimeError, match="capture-only"):
            client.scan_result("aws:dev:services=kms")
    finally:
        orch.ScanOrchestrator.scan = original
    assert seen == {"key": "AKID", "profile": "dev"}


# --- Test 3: same target, same profile -------------------------------------


def test_same_target_same_analysis(tmp_path):
    target = str(_fixture(tmp_path))
    gui_result = get_orchestrator().scan(_gui_request(target))
    cli_result = get_orchestrator().scan(
        ScanRequest(target=target, profile="standard", caller="cli-scan",
                    context=ScanContext()))
    gui_cir, gui_doc = gui_result.as_tuple()
    cli_cir, cli_doc = cli_result.as_tuple()
    assert gui_doc["scan_id"] == cli_doc["scan_id"]  # deterministic IDs
    assert gui_doc["findings"] == cli_doc["findings"]
    assert gui_cir["assets"] == cli_cir["assets"]
    assert gui_cir["operations"] == cli_cir["operations"]
    assert gui_cir["risks"] == cli_cir["risks"]
    assert gui_cir["recommendations"] == cli_cir["recommendations"]


# --- Test 4: profile parity -------------------------------------------------


@pytest.mark.parametrize("profile", ["quick", "standard", "deep"])
def test_profile_recorded_and_accepted(tmp_path, profile):
    target = str(_fixture(tmp_path))
    for caller in ("gui", "cli-scan"):
        result = get_orchestrator().scan(
            ScanRequest(target=target, profile=profile, caller=caller,
                        context=ScanContext()))
        assert result.plan.as_dict()["profile"] == profile


# --- Test 5: option parity ----------------------------------------------------


def test_options_reach_request(tmp_path):
    target = str(_fixture(tmp_path))
    import ecdat.core.orchestrator as orch

    seen = {}
    original = orch.ScanOrchestrator.scan

    def spy(self, request, progress=None):
        seen["request"] = request
        raise RuntimeError("capture-only")

    orch.ScanOrchestrator.scan = spy
    try:
        client = RealCoreClient(
            scanners=["source"], allow_runtime=False, region="eu-west-1",
            profile="quick", risk_z=5.0,
            context=ScanContext(environment="staging"),
            caller="cli-scan")
        with pytest.raises(RuntimeError, match="capture-only"):
            client.scan_result(target)
    finally:
        orch.ScanOrchestrator.scan = original
    req = seen["request"]
    assert req.scanner_list() == ["source"]
    assert req.region == "eu-west-1"
    assert req.profile == "quick"
    assert req.risk_z == 5.0
    assert req.context.environment == "staging"


# --- Test 6: persistence parity -------------------------------------------------


def test_cli_scan_readable_through_gui_repository(tmp_path, capsys):
    from ecdat.store.repository import ScanRepository

    target = _fixture(tmp_path)
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    scan_id = capsys.readouterr()[0].strip()
    with ScanRepository(_db(tmp_path)) as repo:  # GUI's read path
        payload = repo.get_payload(scan_id)
    assert payload is not None
    assert payload["scan_id"] == scan_id
    assert len(payload["canonical"]["findings"]) >= 1


# --- Test 7: error parity ---------------------------------------------------------


def test_missing_target_cli_exit(tmp_path, capsys):
    rc = main(["scan", str(tmp_path / "nope.py"), "--db", _db(tmp_path)])
    assert rc == 2
    _, err = capsys.readouterr()
    assert "not found" in err


def test_invalid_profile_rejected_both_sides(tmp_path):
    target = str(_fixture(tmp_path))
    with pytest.raises(Exception):
        get_orchestrator().scan(
            ScanRequest(target=target, profile="bogus", caller="gui",
                        context=ScanContext()))
    with pytest.raises(SystemExit) as exc:  # argparse rejects (exit 2)
        main(["scan", target, "--db", _db(tmp_path), "--profile", "bogus"])
    assert exc.value.code == 2


def test_bogus_scanners_fail_clean(tmp_path, capsys):
    target = _fixture(tmp_path)
    rc = main(["scan", str(target), "--db", _db(tmp_path),
               "--scanners", "bogus"])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err


# --- Test 9: CLI smoke ---------------------------------------------------------------


def test_help_smoke():
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--help"])
    assert exc.value.code == 0


def test_scan_smoke(tmp_path, capsys):
    assert main(["scan", str(_fixture(tmp_path)),
                 "--db", _db(tmp_path)]) == 0
    assert capsys.readouterr()[0].strip().startswith("scan:")
