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


def _is_cloud_label(target: str) -> bool:
    """Cloud targets are logical labels (``aws:<profile>:services=...``), not paths."""
    text = str(target or "").strip().lower()
    return text.startswith("aws:") or text.startswith("azure:") or text.startswith("gcp:")


def _is_image_reference(target: str) -> bool:
    """Container image refs (``nginx:1.25``, ``registry/org/img@sha256:...``).

    Local paths that exist are handled as paths; anything else containing
    an image separator is treated as a registry reference so
    ``scan-container`` works without a local file.
    """
    from pathlib import Path as _Path

    text = str(target or "").strip()
    if not text or _Path(text).exists():
        return False
    if text.startswith(("docker://", "oci://")):
        return True
    # Bare refs: name:tag, registry/org/image, digest refs.
    return (":" in text) or ("/" in text) or ("@" in text)


def _is_runtime_endpoint(target: str) -> bool:
    """Runtime targets are ``host:port`` endpoints, not filesystem paths."""
    text = str(target or "").strip()
    if not text or _is_cloud_label(text):
        return False
    from pathlib import Path as _Path

    if _Path(text).exists():
        return False
    # host:port with numeric port.
    if ":" in text and "@" not in text and "/" not in text:
        host, _, port = text.rpartition(":")
        return bool(host.strip()) and port.strip().isdigit()
    return False


def _parse_cloud_services(target: str) -> list[str]:
    """Extract ``services=`` from a cloud label (``aws:prof:services=kms,acm``)."""
    text = str(target or "")
    marker = "services="
    if marker not in text.lower():
        return []
    raw = text[text.lower().index(marker) + len(marker):]
    # Label ends at whitespace; services are comma-separated.
    raw = raw.strip().split()[0] if raw.strip().split() else ""
    return [s.strip().lower() for s in raw.split(",") if s.strip()]


def _target_requires_existing_path(target: str, selected: list[str]) -> bool:
    """Only filesystem scanner selections require an existing local path.

    Cloud labels, container image references, and runtime endpoints are
    valid non-path targets when their scanner family is selected.
    """
    if _is_cloud_label(target):
        return "cloud" not in [s.lower() for s in selected]
    if _is_image_reference(target):
        return "container" not in [s.lower() for s in selected]
    if _is_runtime_endpoint(target):
        return "runtime" not in [s.lower() for s in selected]
    return True


def run_real_scan(
    target: str | Path,
    scanners: list[str] | tuple[str, ...] | None = None,
    allow_container: bool = False,
    allow_cloud: bool = False,
    allow_runtime: bool = False,
    risk_z: float = 10.0,
    region: str | None = None,
) -> tuple[dict, dict]:
    """Execute the integrated real pipeline.

    Returns ``(cir_dict, canonical_doc)`` — the enriched CIR (with wire
    risks/recommendations) and the validated canonical v1 document.
    Both share the deterministic scan ID.
    """
    cleaned = str(target or "").strip()
    if not cleaned:
        raise RealScanError("target must be a non-empty string")
    try:
        selected = _policy.resolve_scanners(
            scanners,
            allow_container=allow_container,
            allow_cloud=allow_cloud,
            allow_runtime=allow_runtime,
        )
    except ValueError as exc:
        raise RealScanError(str(exc))
    if _target_requires_existing_path(cleaned, selected):
        if not Path(cleaned).exists():
            raise RealScanError(f"scan target does not exist: {cleaned}")

    try:
        from ecdat.scanners.discovery import DiscoveryEngine
    except ImportError as exc:
        raise RealScanError(
            "real scan requires the discovery dependencies "
            f"(pydantic, pyyaml, cryptography): {exc}"
        )
    try:
        engine = DiscoveryEngine(enabled_scanners=selected)
    except Exception as exc:
        raise RealScanError(
            f"discovery failed for target {cleaned!r} "
            f"({ _policy.describe_selection(selected)}): {exc}"
        )
    # Honest unavailable handling: warn for partially unavailable
    # selections, but fail loudly when NOTHING could run — otherwise an
    # empty scan would masquerade unavailable tools as zero findings.
    try:
        availability = dict(engine.availability())
    except Exception:
        availability = {}
    if availability:
        unavailable = sorted(n for n, ok in availability.items() if not ok)
        available = sorted(n for n, ok in availability.items() if ok)
        if unavailable:
            print(
                "warning: requested scanner(s) unavailable and skipped: "
                + ", ".join(unavailable)
                + " (missing tool, daemon, or credentials)",
                file=sys.stderr,
            )
        if not available:
            raise RealScanError(
                f"no requested scanner available for target {cleaned!r} "
                f"({', '.join(unavailable)} unavailable; "
                "install the tool, start the daemon, or provide credentials)")
        # Non-path targets need their primary family: an image ref without
        # container support, or a cloud label without cloud support, cannot
        # yield findings from filesystem scanners — fail loudly instead of
        # storing an empty scan that hides the missing capability.
        if _is_cloud_label(cleaned) and availability.get("cloud") is False:
            raise RealScanError(
                f"cloud scanner unavailable for target {cleaned!r} "
                "(missing SDK or credentials; cannot scan cloud label)")
        if _is_image_reference(cleaned) and availability.get("container") is False:
            raise RealScanError(
                f"container scanner unavailable for target {cleaned!r} "
                "(missing docker/syft; cannot scan image reference)")
    try:
        scan_kwargs: dict = {}
        # Forward cloud label parts (``aws:<profile>:services=kms,acm``) so
        # the AWS scanner filters to the requested services instead of
        # unconditionally enumerating KMS/ACM/ELB/ALB.
        if _is_cloud_label(cleaned):
            services = _parse_cloud_services(cleaned)
            if services:
                scan_kwargs["services"] = services
            if region:
                scan_kwargs["region"] = str(region).strip()
        elif region:
            scan_kwargs["region"] = str(region).strip()
        cir_doc = engine.scan_and_emit_cir(
            cleaned, target_name=cleaned, **scan_kwargs)
    except RealScanError:
        raise
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
        # Post-scan repeat of the pre-scan warning is intentionally
        # omitted: the pre-scan probe already reported it. Kept as a
        # no-op guard for engines whose availability changes mid-scan.
        pass
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
