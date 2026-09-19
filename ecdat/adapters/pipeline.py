"""ONE logical real scan (Person 3 platform layer).

Phase 1: thin compatibility wrapper over ScanOrchestrator (the single
production pipeline owner).  P2 scans exactly once; P1 analyzes the
resulting CIR without re-scanning (``api.scan`` is never called - it
performs its own discovery and would scan the target twice).

Flow (owned by ecdat.core.orchestrator.ScanOrchestrator):
    InputRegistry.normalize
    -> scanner_policy resolution
    -> AdaptiveScheduler routing (plan)
    -> P2 DiscoveryEngine (explicit scanner subset, execution utility)
    -> model_dump(mode="json", exclude_none=True)
    -> P3 normalize_cir (deterministic ID, timestamps, stats)
    -> P1 validate_cir (raises)
    -> P1 enrich_cir (risk + recommendations on the SAME document)
    -> P1 to_canonical
    -> P3 canonical normalize (scan_id, files_scanned, asset-only findings)
    -> P3 validate (raises)

Any failure raises RealScanError with an actionable message.
"""

from __future__ import annotations

from pathlib import Path

# Single source of truth lives in ecdat.core.orchestrator.  Re-exported
# here so existing ``from ecdat.adapters.pipeline import RealScanError``
# imports keep working without a second implementation.
from ecdat.core.orchestrator import (
    RealScanError,
    ScanPermissions,
    ScanRequest,
    _is_cloud_label,
    _is_image_reference,
    _is_runtime_endpoint,
    _parse_cloud_services,
    _target_requires_existing_path,
    get_orchestrator,
)

__all__ = [
    "RealScanError",
    "run_real_scan",
    "_is_cloud_label",
    "_is_image_reference",
    "_is_runtime_endpoint",
    "_parse_cloud_services",
    "_target_requires_existing_path",
]


def run_real_scan(
    target: str | Path,
    scanners: list[str] | tuple[str, ...] | None = None,
    allow_container: bool = False,
    allow_cloud: bool = False,
    allow_runtime: bool = False,
    risk_z: float = 10.0,
    region: str | None = None,
    profile: str = "standard",
    caller: str = "pipeline-compat",
    progress=None,
) -> tuple[dict, dict]:
    """Execute the integrated real pipeline via ScanOrchestrator.

    Thin compatibility wrapper: builds a :class:`ScanRequest` and
    delegates to the shared orchestrator.  Returns ``(cir, canonical)``.
    ``profile``/``caller``/``progress`` are Phase 1 additions; all prior
    positional/keyword arguments keep their meaning.
    """
    request = ScanRequest(
        target=str(target) if target is not None else "",
        scanners=list(scanners) if scanners is not None else None,
        permissions=ScanPermissions(
            allow_container=bool(allow_container),
            allow_cloud=bool(allow_cloud),
            allow_runtime=bool(allow_runtime),
        ),
        profile=str(profile or "standard"),
        region=str(region).strip() if region else None,
        risk_z=float(risk_z),
        caller=str(caller or "pipeline-compat"),
    )
    result = get_orchestrator().scan(request, progress=progress)
    return result.as_tuple()
