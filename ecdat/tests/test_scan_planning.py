"""Phase 3 regression: real routing, profiles, cache, permissions, planning.

Proves AdaptiveScheduler.triage() routes centrally, quick/standard/deep
produce observably different plans, the generic ScanCache serves repeat
scans, permissions_required names real gaps, scanner outcomes are
structured, should_escalate has a production caller, and the GUI exposes
automatic discovery + a scan-plan preview.
"""

from __future__ import annotations

from pathlib import Path

from ecdat.core.orchestrator import ScanRequest, get_orchestrator


def _mixed_dir(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n")
    (root / "requirements.txt").write_text("cryptography>=42.0\n")
    (root / "nginx.conf").write_text("server { listen 443 ssl; }\n")
    (root / "tool").write_bytes(b"\x7fELF" + b"\x00" * 64)
    return root


def test_triage_artifact_prefers_content():
    from ecdat.core.inventory import ArtifactRecord
    from ecdat.core.scheduler import AdaptiveScheduler

    scheduler = AdaptiveScheduler()
    binary = ArtifactRecord(
        relative_path="data.txt", abs_path="/tmp/data.txt", size=68,
        content_hash="abc", extension=".txt", mime="text/plain",
        magic="7f454c46", executable_format="elf", language=None,
        category="binary")
    assert scheduler.triage_artifact(binary) == "binary"
    # Archives/unknowns fall back to path triage (tar -> container).
    archive = ArtifactRecord(
        relative_path="img.tar", abs_path="/tmp/img.tar", size=10,
        content_hash="def", extension=".tar", mime=None, magic="",
        executable_format=None, language=None, category="archive")
    assert scheduler.triage_artifact(archive) == "container"
    # Plain path triage is untouched.
    assert scheduler.triage("app.py") == "source"


def test_plan_carries_inventory_and_surfaces(tmp_path):
    target = _mixed_dir(tmp_path / "repo")
    plan = get_orchestrator().plan(ScanRequest(target=str(target)))
    assert plan.artifacts_total >= 4
    assert plan.artifact_counts.get("source", 0) >= 1
    assert plan.artifact_counts.get("binary", 0) >= 1
    assert plan.artifact_counts.get("config", 0) >= 1
    assert plan.artifact_counts.get("dependency", 0) >= 1
    for surface in ("source", "binary", "config", "dependency"):
        assert surface in plan.surfaces
    assert plan.display_target == str(target)
    payload = plan.as_dict()
    assert payload["artifacts_total"] == plan.artifacts_total
    assert payload["surfaces"] == list(plan.surfaces)
    assert payload["display_target"] == str(target)


def test_profiles_produce_observably_different_plans(tmp_path):
    target = tmp_path / "a.py"
    target.write_text("x = 1\n")
    orch = get_orchestrator()
    quick = orch.plan(ScanRequest(target=str(target), profile="quick"))
    standard = orch.plan(ScanRequest(target=str(target), profile="standard"))
    deep = orch.plan(ScanRequest(target=str(target), profile="deep"))
    assert quick.escalation_allowed is False
    assert standard.escalation_allowed is True
    assert deep.escalation_allowed is True
    assert quick.effort["archive_depth"] < deep.effort["archive_depth"]
    assert quick.effort["expensive_backends"] == []
    assert deep.effort["expensive_backends"] != []
    assert quick.effort != standard.effort != deep.effort


def test_display_name_is_primary_identity(tmp_path):
    target = tmp_path / "a.py"
    target.write_text("x = 1\n")
    plan = get_orchestrator().plan(
        ScanRequest(target=str(target), display_name="my-repo"))
    assert plan.display_target == "my-repo"
    assert plan.as_dict()["display_target"] == "my-repo"


def test_permissions_required_names_real_gaps(tmp_path):
    target = _mixed_dir(tmp_path / "repo")
    plan = get_orchestrator().plan(
        ScanRequest(target=str(target), scanners=["source"]))
    assert plan.permissions_required, "expected uncovered-surface notes"
    joined = " ".join(plan.permissions_required)
    assert "binary" in joined


def test_repeat_scan_serves_cache(tmp_path):
    target = tmp_path / "cached.py"
    target.write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n")
    orch = get_orchestrator()
    request = ScanRequest(target=str(target), caller="cache-test")
    first = orch.scan(request)
    assert first.diagnostics["cache_hit"] is False
    second = orch.scan(request)
    assert second.diagnostics["cache_hit"] is True
    assert second.scan_id == first.scan_id
    assert second.canonical == first.canonical
    # A different profile is a different cache entry (miss).
    third = orch.scan(ScanRequest(target=str(target), caller="cache-test",
                                  profile="deep"))
    assert third.diagnostics["cache_hit"] is False


def test_scan_diagnostics_carry_status_and_escalation(tmp_path):
    target = tmp_path / "diag.py"
    target.write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n")
    result = get_orchestrator().scan(
        ScanRequest(target=str(target), caller="diag-test"))
    status = result.diagnostics["scanner_status"]
    assert status.get("source") == "success"
    escalation = result.diagnostics["escalation"]
    assert escalation["evaluated"] >= 0
    assert escalation["escalated"] == 0
    assert isinstance(escalation["candidates"], list)
    assert result.diagnostics["surfaces"]
    assert result.diagnostics["artifacts_total"] >= 1


def test_gui_defaults_auto_enable_local_discovery():
    import ecdat.web.server as _srv

    for profile in ("quick", "standard", "deep"):
        selected = _srv._profile_scanners(profile, None)
        for family in ("source", "dependency", "binary", "config",
                       "certificate"):
            assert family in selected, f"{profile} must auto-enable {family}"
    # Explicit Advanced override still honored; unknown still rejected.
    assert _srv._profile_scanners("standard", ["source"]) == ["source"]
    try:
        _srv._profile_scanners("standard", ["bogus"])
    except ValueError:
        pass
    else:
        raise AssertionError("unknown scanner must raise")


def test_inspect_returns_real_inventory(tmp_path):
    import ecdat.web.server as _srv

    root = _mixed_dir(tmp_path / "repo")
    payload = _srv._inspect(root, "demo-label")
    # Legacy keys preserved.
    assert payload["name"] == "demo-label"
    assert payload["file_count"] >= 4
    assert payload["total_bytes"] > 0
    assert payload["languages"]
    # Real inventory added.
    assert payload["display_name"] == "demo-label"
    assert payload["artifact_counts"].get("binary", 0) >= 1
    assert payload["surfaces"].get("source", 0) >= 1
    assert isinstance(payload["archives"], list)


def test_scan_plan_preview_shape(tmp_path):
    import ecdat.web.server as _srv

    root = tmp_path / "inputs" / "x"
    root.mkdir(parents=True)
    (root / "app.py").write_text("x = 1\n")
    record = _srv.STATE.new_input()
    record["target"] = root
    record["label"] = "preview-label"
    plan = get_orchestrator().plan(ScanRequest(
        target=str(root), profile="quick", caller="gui-plan",
        display_name="preview-label")).as_dict()
    assert plan["profile"] == "quick"
    assert plan["display_target"] == "preview-label"
    assert plan["artifacts_total"] >= 1
    assert plan["escalation_allowed"] is False
