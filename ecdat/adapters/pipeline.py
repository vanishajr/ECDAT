"""ONE logical real scan (Person 3 platform layer).

P3 RealCoreClient orchestrates; P2 scans exactly once; P1 analyzes the
resulting CIR without re-scanning (``api.scan`` is never called — it
performs its own discovery and would scan the target twice).

Flow:
    P2 DiscoveryEngine (explicit scanner subset)
    -> model_dump(mode="json", exclude_none=True)
    -> P3 normalize_cir (deterministic ID, timestamps, stats)
    -> P1 validate_cir (raises)
    -> P1 enrich_cir (risk + recommendations on the SAME document)
    -> P1 to_canonical
    -> P3 canonical normalize (scan_id, files_scanned, asset-only findings)
    -> P3 validate (raises)

Any failure raises RealScanError with an actionable message. There is
no fallback to mock data on any path.
"""

from __future__ import annotations

import sys
from pathlib import Path

from ecdat.adapters import normalize as _norm
from ecdat.adapters import scanner_policy as _policy


class RealScanError(RuntimeError):
    """A real scan failed. Never silently replaced with mock results."""


def run_real_scan(
    target: str | Path,
    scanners: list[str] | tuple[str, ...] | None = None,
    allow_container: bool = False,
    allow_cloud: bool = False,
    allow_runtime: bool = False,
    risk_z: float = 10.0,
) -> tuple[dict, dict]:
    """Execute the integrated real pipeline.

    Returns ``(cir_dict, canonical_doc)`` — the enriched CIR (with wire
    risks/recommendations) and the validated canonical v1 document.
    Both share the deterministic scan ID.
    """
    cleaned = str(target or "").strip()
    if not cleaned:
        raise RealScanError("target must be a non-empty string")
    if not Path(cleaned).exists():
        raise RealScanError(f"scan target does not exist: {cleaned}")
    try:
        selected = _policy.resolve_scanners(
            scanners,
            allow_container=allow_container,
            allow_cloud=allow_cloud,
            allow_runtime=allow_runtime,
        )
    except ValueError as exc:
        raise RealScanError(str(exc))

    try:
        from ecdat.scanners.discovery import DiscoveryEngine
    except ImportError as exc:
        raise RealScanError(
            "real scan requires the discovery dependencies "
            f"(pydantic, pyyaml, cryptography): {exc}"
        )
    try:
        engine = DiscoveryEngine(enabled_scanners=selected)
        cir_doc = engine.scan_and_emit_cir(cleaned, target_name=cleaned)
    except Exception as exc:
        raise RealScanError(
            f"discovery failed for target {cleaned!r} "
            f"({ _policy.describe_selection(selected)}): {exc}"
        )
    try:
        unavailable = sorted(
            n for n, ok in engine.availability().items() if not ok)
    except Exception:
        unavailable = []
    if unavailable:
        print(
            "warning: requested scanner(s) unavailable and skipped: "
            + ", ".join(unavailable)
            + " (missing tool, daemon, or credentials)",
            file=sys.stderr,
        )
    try:
        cir = cir_doc.model_dump(mode="json", exclude_none=True)
    except Exception as exc:
        raise RealScanError(f"could not serialize CIR for {cleaned!r}: {exc}")

    try:
        cir = _norm.normalize_cir(cir, cleaned)
    except ValueError as exc:
        raise RealScanError(f"CIR normalization failed: {exc}")

    try:
        from ecdat.core import cir_validate as _cir_validate
    except ImportError as exc:
        raise RealScanError(
            f"real scan requires CIR validation support (jsonschema): {exc}"
        )
    try:
        _cir_validate.validate_cir(cir)
    except Exception as exc:
        raise RealScanError(f"CIR validation failed for {cleaned!r}: {exc}")

    try:
        from ecdat.core import api as _api
    except ImportError as exc:
        raise RealScanError(
            f"real scan requires the core analysis modules: {exc}"
        )
    try:
        enriched = _api.enrich_cir(cir, Z=float(risk_z))
        canonical = _api.to_canonical(enriched)
    except Exception as exc:
        raise RealScanError(f"core analysis failed for {cleaned!r}: {exc}")

    # P3 canonical normalization (P1 hardcodes files_scanned=0 and is
    # operation-oriented; both fixed here without touching P1).
    canonical["scan_id"] = enriched.get("scan_id", canonical.get("scan_id"))
    canonical["target"] = cleaned
    canonical["started_at"] = enriched.get(
        "started_at", canonical.get("started_at"))
    canonical["finished_at"] = enriched.get(
        "finished_at", canonical.get("finished_at"))
    canonical.setdefault("stats", {})["files_scanned"] = len(
        _norm.files_from_cir(enriched))
    extra = _norm.synthesize_asset_only_findings(enriched)
    if extra:
        canonical.setdefault("findings", []).extend(extra)
        canonical["stats"]["findings_count"] = len(canonical["findings"])

    try:
        from ecdat.core.validate import validate as _validate_canonical
    except ImportError as exc:
        raise RealScanError(
            f"real scan requires canonical validation support: {exc}"
        )
    try:
        _validate_canonical(canonical)
    except Exception as exc:
        raise RealScanError(
            f"canonical validation failed for {cleaned!r}: {exc}")
    # Re-validate the enriched CIR post-normalization (IDs/timestamps
    # were rewritten after the first validation pass).
    try:
        _cir_validate.validate_cir(enriched)
    except Exception as exc:
        raise RealScanError(
            f"enriched CIR validation failed for {cleaned!r}: {exc}")
    return enriched, canonical
