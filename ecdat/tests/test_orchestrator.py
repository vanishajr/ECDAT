"""Phase 1 regression: CLI / GUI / CI converge on ScanOrchestrator.

Proves the acceptance criterion::

    CLI -->                     .
    GUI -->  ScanOrchestrator -> shared analysis stages
    CI  -->                     .

No active production surface keeps an independent scan implementation;
DiscoveryEngine remains the scanner-execution utility owned by the
orchestrator.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest


def _sample(tmp_path: Path) -> Path:
    p = tmp_path / "sample.py"
    p.write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "x = AESGCM.generate_key(bit_length=256)\n"
    )
    return p


# --- models exist ------------------------------------------------------


def test_orchestrator_models_exist():
    from ecdat.core import orchestrator as orch

    for name in (
        "ScanRequest",
        "ScanPermissions",
        "ScanProgressEvent",
        "ScanPlan",
        "ScanResult",
        "ScanOrchestrator",
        "RealScanError",
        "get_orchestrator",
    ):
        assert hasattr(orch, name), f"missing {name}"
    assert hasattr(orch.ScanOrchestrator, "plan")
    assert hasattr(orch.ScanOrchestrator, "scan")
    assert hasattr(orch.ScanOrchestrator, "scan_with_cir")


def test_request_defaults_and_profile_validation(tmp_path):
    from ecdat.core.orchestrator import RealScanError, ScanRequest

    req = ScanRequest(target=str(tmp_path))
    assert req.normalized_profile() == "standard"
    assert ScanRequest(target="x", profile="deep").normalized_profile() == "deep"
    assert ScanRequest(target="x", profile="QUICK").normalized_profile() == "quick"
    with pytest.raises(RealScanError):
        ScanRequest(target="x", profile="bogus").normalized_profile()


def test_empty_target_raises(tmp_path):
    from ecdat.core.orchestrator import RealScanError, ScanRequest, get_orchestrator

    with pytest.raises(RealScanError):
        get_orchestrator().plan(ScanRequest(target="   "))
    with pytest.raises(RealScanError):
        get_orchestrator().scan(ScanRequest(target=""))


# --- plan --------------------------------------------------------------


def test_plan_shape(tmp_path):
    from ecdat.core.orchestrator import ScanPermissions, ScanRequest, get_orchestrator

    target = _sample(tmp_path)
    plan = get_orchestrator().plan(
        ScanRequest(target=str(target), profile="standard", caller="test")
    )
    assert plan.job_id.startswith("job-")
    assert plan.target == str(target)
    assert plan.profile == "standard"
    assert plan.caller == "test"
    assert isinstance(plan.scanners, tuple) and len(plan.scanners) >= 4
    assert "source" in plan.scanners
    assert isinstance(plan.stages, tuple) and len(plan.stages) >= 1
    assert isinstance(plan.permissions, dict)
    d = plan.as_dict()
    assert d["job_id"] == plan.job_id
    assert d["scanners"] == list(plan.scanners)


def test_plan_is_deterministic(tmp_path):
    from ecdat.core.orchestrator import ScanRequest, get_orchestrator

    target = _sample(tmp_path)
    a = get_orchestrator().plan(ScanRequest(target=str(target)))
    b = get_orchestrator().plan(ScanRequest(target=str(target)))
    assert a.job_id == b.job_id
    assert a.scanners == b.scanners
    assert a.stages == b.stages


# --- scan --------------------------------------------------------------


def test_scan_produces_validated_pair_and_events(tmp_path):
    from ecdat.core.orchestrator import ScanRequest, get_orchestrator

    target = _sample(tmp_path)
    events: list = []
    result = get_orchestrator().scan(
        ScanRequest(target=str(target), caller="test"), progress=events.append
    )
    assert result.scan_id.startswith("scan:")
    assert result.cir["scan_id"] == result.canonical["scan_id"] == result.scan_id
    assert result.target == str(target)
    assert result.plan.target == str(target)
    assert result.diagnostics["caller"] == "test"

    from ecdat.core import cir_validate as _cv
    from ecdat.core.validate import validate as _validate_canonical

    _cv.validate_cir(result.cir)
    _validate_canonical(result.canonical)

    stages = [e.stage for e in events]
    assert stages, "expected progress events"
    assert stages[0] == "normalize"
    assert stages[-1] == "complete"
    assert "discovery" in stages
    progresses = [int(e.progress) for e in events]
    assert progresses == sorted(progresses), "progress must be non-decreasing"
    assert progresses[-1] == 100


def test_scan_unknown_scanner_fails_clean(tmp_path):
    from ecdat.core.orchestrator import RealScanError, ScanRequest, get_orchestrator

    with pytest.raises(RealScanError):
        get_orchestrator().scan(
            ScanRequest(target=str(_sample(tmp_path)), scanners=["bogus-scanner"])
        )


# --- wrappers delegate (no second pipeline) ----------------------------


def test_pipeline_wrapper_delegates(tmp_path, monkeypatch):
    from ecdat.adapters import pipeline as _pipe
    from ecdat.core import orchestrator as orch

    target = _sample(tmp_path)
    calls: list = []
    real = orch.ScanOrchestrator.scan

    def _spy(self, request, progress=None):
        calls.append(request)
        return real(self, request, progress=progress)

    monkeypatch.setattr(orch.ScanOrchestrator, "scan", _spy)
    cir, canonical = _pipe.run_real_scan(str(target))
    assert len(calls) == 1
    assert calls[0].target == str(target)
    assert cir["scan_id"] == canonical["scan_id"]


def test_client_delegates_to_orchestrator(tmp_path, monkeypatch):
    from ecdat.core import orchestrator as orch
    from ecdat.core.client import RealCoreClient

    target = _sample(tmp_path)
    calls: list = []
    real = orch.ScanOrchestrator.scan

    def _spy(self, request, progress=None):
        calls.append(request)
        return real(self, request, progress=progress)

    monkeypatch.setattr(orch.ScanOrchestrator, "scan", _spy)
    cir, canonical = RealCoreClient(caller="test-client").scan_with_cir(str(target))
    assert len(calls) == 1
    assert calls[0].caller == "test-client"
    assert cir["scan_id"] == canonical["scan_id"]


def test_pipeline_reexports_single_error_type():
    from ecdat.adapters import pipeline as _pipe
    from ecdat.core import orchestrator as orch

    assert _pipe.RealScanError is orch.RealScanError
    assert _pipe._is_cloud_label is orch._is_cloud_label
    assert _pipe._is_image_reference is orch._is_image_reference
    assert _pipe._is_runtime_endpoint is orch._is_runtime_endpoint


# --- CLI / CI reach the orchestrator -----------------------------------


def test_cli_scan_reaches_orchestrator(tmp_path, monkeypatch, capsys):
    from ecdat.cli import main
    from ecdat.core import orchestrator as orch

    target = _sample(tmp_path)
    db = str(tmp_path / "t.db")
    calls: list = []
    real = orch.ScanOrchestrator.scan

    def _spy(self, request, progress=None):
        calls.append(request)
        return real(self, request, progress=progress)

    monkeypatch.setattr(orch.ScanOrchestrator, "scan", _spy)
    rc = main(["scan", str(target), "--db", db])
    assert rc == 0
    capsys.readouterr()
    assert len(calls) == 1
    assert calls[0].caller == "cli-scan"


def test_ci_reaches_orchestrator(tmp_path, monkeypatch, capsys):
    from ecdat.cli import main
    from ecdat.core import orchestrator as orch

    target = _sample(tmp_path)
    db = str(tmp_path / "t.db")
    calls: list = []
    real = orch.ScanOrchestrator.scan

    def _spy(self, request, progress=None):
        calls.append(request)
        return real(self, request, progress=progress)

    monkeypatch.setattr(orch.ScanOrchestrator, "scan", _spy)
    rc = main(["ci", str(target), "--db", db])
    assert rc in (0, 1)  # gating may fail; scan itself must run
    capsys.readouterr()
    assert len(calls) == 1
    assert calls[0].caller == "ci"


def test_specialized_commands_share_pipeline_but_hint(tmp_path, monkeypatch):
    import ecdat.commands.scan_binary_cmd as _bin
    import ecdat.commands.scan_cloud_cmd as _cloud
    import ecdat.commands.scan_container_cmd as _ctr
    from ecdat.core import orchestrator as orch

    # All specialized commands must resolve through the same orchestrator
    # module (import convergence), while passing target hints.
    for mod in (_bin, _ctr, _cloud):
        src = inspect.getsource(mod)
        assert "run_real_and_store" in src
        assert "orchestrator" in src.lower() or "caller=" in src

    captured: dict = {}

    def _fake_run(args, target, scanners=None, caller="cli-scan"):
        captured["scanners"] = scanners
        captured["caller"] = caller
        captured["target"] = str(target)
        # Prove the hint would still resolve via the orchestrator plan path.
        plan = orch.get_orchestrator().plan(
            orch.ScanRequest(target=".", scanners=scanners, caller=caller)
        )
        assert plan.scanners == tuple(scanners or [])
        return 0

    import argparse

    monkeypatch.setattr(
        "ecdat.commands.scan_binary_cmd.run_real_and_store", _fake_run
    )
    fake_bin = tmp_path / "app.exe"
    fake_bin.write_bytes(b"MZ" + b"\x00" * 64)
    rc = _bin.run(argparse.Namespace(binary=str(fake_bin)))
    assert rc == 0
    assert captured["scanners"] == ["binary"]
    assert captured["caller"] == "cli-scan-binary"

    monkeypatch.setattr(
        "ecdat.commands.scan_container_cmd.run_real_and_store", _fake_run
    )
    rc = _ctr.run(argparse.Namespace(image_or_path="nginx:1.25"))
    assert rc == 0
    assert "container" in captured["scanners"]
    assert captured["caller"] == "cli-scan-container"

    monkeypatch.setattr(
        "ecdat.commands.scan_cloud_cmd.run_real_and_store", _fake_run
    )
    rc = _cloud.run(
        argparse.Namespace(profile="default", services="kms,acm")
    )
    assert rc == 0
    assert captured["scanners"] == ["cloud"]
    assert captured["caller"] == "cli-scan-cloud"


# --- GUI reaches the orchestrator --------------------------------------


def test_gui_module_uses_orchestrator():
    import ecdat.web.server as _srv

    src = inspect.getsource(_srv._run_job)
    assert "get_orchestrator" in src or "ScanOrchestrator" in src
    assert "run_real_scan" not in src, "GUI must not bypass the orchestrator"
    assert "ScanRequest" in src
    assert "progress" in src.lower()


def test_gui_run_job_end_to_end(tmp_path):
    import ecdat.web.server as _srv

    target = _sample(tmp_path)
    # Fake an inspected input + queued job, then run synchronously.
    record = _srv.STATE.new_input()
    record["target"] = target
    record["label"] = "sample"
    job_id = "test-job-phase1"
    with _srv.STATE.lock:
        _srv.STATE.jobs[job_id] = {
            "job_id": job_id,
            "input_id": record["input_id"],
            "status": "queued",
            "progress": 5,
            "stage": "Preparing input",
            "scanners": ["source", "dependency", "config", "certificate"],
            "profile": "standard",
            "created_at": _srv._now(),
        }
    _srv._run_job(job_id)
    with _srv.STATE.lock:
        job = dict(_srv.STATE.jobs[job_id])
    assert job["status"] == "completed", job.get("error")
    assert job["scan_id"] in _srv.STATE.results
    payload = _srv.STATE.results[job["scan_id"]]
    assert payload["canonical"]["scan_id"] == job["scan_id"]
    assert payload["cir"]["scan_id"] == job["scan_id"]


# --- DiscoveryEngine is an execution utility, not the owner -------------


def test_discovery_engine_still_available_as_utility():
    from ecdat.scanners.discovery import DiscoveryEngine

    engine = DiscoveryEngine(enabled_scanners=["source"])
    assert "source" in engine.get_enabled_scanners()
    assert isinstance(engine.availability(), dict)


def test_scheduler_registry_are_runtime_components(tmp_path):
    from ecdat.core.scheduler import AdaptiveScheduler, InputRegistry

    job = InputRegistry().normalize(str(_sample(tmp_path)))
    assert job.job_id.startswith("job-")
    route = AdaptiveScheduler().route(job)
    assert route["job_id"] == job.job_id
    assert len(route["stages"]) >= 1
