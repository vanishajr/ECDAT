"""Single production scan orchestration layer (Phase 1).

Architecture-convergence target::

    CLI / GUI / CI
        -> ScanOrchestrator
        -> InputRegistry.normalize()
        -> AdaptiveScheduler routing (plan)
        -> staged scanner execution (DiscoveryEngine as execution utility)
        -> CIR / canonical validation
        -> risk + recommendations (via core.api)
        -> canonical result + persistent storage (callers)

This module OWNS the integrated pipeline.  Everything else is a thin
compatibility surface:

- ``ecdat.adapters.pipeline.run_real_scan`` delegates here (same signature,
  same errors, same ``(cir, canonical)`` return).
- ``ecdat.core.client.RealCoreClient`` delegates here.
- CLI scan commands delegate here via ``RealCoreClient``.
- CI delegates here via ``RealCoreClient``.
- GUI ``_run_job`` calls :class:`ScanOrchestrator` directly with a progress
  callback.

``DiscoveryEngine`` remains the scanner-execution utility; it no longer owns
the architecture.  ``InputRegistry`` / ``AdaptiveScheduler`` / ``ScanCache``
from :mod:`ecdat.core.scheduler` are real runtime components of every scan
(plan stage), not dead design code.

Stdlib + existing ECDAT modules only.  No new dependencies.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal

__all__ = [
    "RealScanError",
    "ScanProfile",
    "PROFILES",
    "PROFILE_EFFORT",
    "SURFACE_OWNER",
    "normalize_profile",
    "ScanPermissions",
    "ScanRequest",
    "ScanProgressEvent",
    "ProgressCallback",
    "ScanPlan",
    "ScanResult",
    "ScanOrchestrator",
    "get_orchestrator",
    "plan_scan",
    "run_scan",
    # Target-kind helpers (single source of truth; pipeline re-exports).
    "_is_cloud_label",
    "_is_image_reference",
    "_is_runtime_endpoint",
    "_parse_cloud_services",
    "_target_requires_existing_path",
]


class RealScanError(RuntimeError):
    """An integrated scan failed before producing valid output."""


# ---------------------------------------------------------------------------
# Target-kind helpers (moved here from adapters.pipeline so there is exactly
# one implementation; pipeline re-exports them for backwards compatibility).
# ---------------------------------------------------------------------------

def _is_cloud_label(target: str) -> bool:
    """Cloud targets are logical labels (``aws:<profile>:services=...``)."""
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


# ---------------------------------------------------------------------------
# Request / permissions / profile models
# ---------------------------------------------------------------------------

ScanProfile = Literal["quick", "standard", "deep"]
PROFILES: tuple[str, ...] = ("quick", "standard", "deep")

#: Phase 3 profile semantics. Depth changes ANALYSIS EFFORT, never whether
#: ECDAT knows an artifact exists: every profile inventories everything.
#: quick = cheap/high-yield only, no escalation; standard = normal fusion
#: plus escalation candidates recorded; deep = escalation allowed, deeper
#: archive exploration, expensive backends flagged expected.
PROFILE_EFFORT: dict[str, dict[str, Any]] = {
    "quick": {
        "escalation_allowed": False,
        "archive_depth": 2,
        "expensive_backends": [],
        "candidate_reasoning": "minimal",
    },
    "standard": {
        "escalation_allowed": True,
        "archive_depth": 3,
        "expensive_backends": ["capa", "floss-selective"],
        "candidate_reasoning": "normal",
    },
    "deep": {
        "escalation_allowed": True,
        "archive_depth": 5,
        "expensive_backends": ["capa", "floss", "ghidra-optional"],
        "candidate_reasoning": "extended",
    },
}

#: Scanner family that owns each detected surface (for skip/permission notes).
SURFACE_OWNER = {
    "source": "source",
    "dependency": "dependency",
    "binary": "binary",
    "container": "container",
    "config": "config",
    "cert": "certificate",
}


def normalize_profile(value: str | None) -> str:
    """Validate a scan profile name (default ``standard``)."""
    text = str(value or "standard").strip().lower()
    if text not in PROFILES:
        raise RealScanError(
            f"unknown scan profile: {value!r} (known: {', '.join(PROFILES)})"
        )
    return text


@dataclass(frozen=True)
class ScanPermissions:
    """Explicit opt-ins for external / privileged scan surfaces.

    Local/static analysis (source, dependencies, binaries, configs,
    certs/keys, supplied local container artifacts) never requires these.
    Anything touching the network, credentials, daemons, or builds does.
    """

    allow_container: bool = False
    allow_cloud: bool = False
    allow_runtime: bool = False
    # Reserved for Phase 3/7 permission model (pull/build); accepted now so
    # callers can forward them without a second request shape later.
    allow_pull: bool = False
    allow_build: bool = False

    def as_dict(self) -> dict[str, bool]:
        return {
            "allow_container": bool(self.allow_container),
            "allow_cloud": bool(self.allow_cloud),
            "allow_runtime": bool(self.allow_runtime),
            "allow_pull": bool(self.allow_pull),
            "allow_build": bool(self.allow_build),
        }


@dataclass(frozen=True)
class ScanContext:
    """Optional user-supplied risk context (Phase 10).

    All fields are user assertions, visibly tagged ``user-supplied`` in
    risk provenance. Unknown stays unknown: unset fields never inject
    high-risk defaults (the risk engine records its own explicit
    assumptions for those). Environment/owner do not change scores;
    they travel in context notes for reports/graph linkage.
    """

    environment: str | None = None
    owner: str | None = None
    exposure: str | None = None
    business_criticality: str | None = None
    data_lifetime_years: float | None = None
    migration_years: float | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "environment": self.environment,
            "owner": self.owner,
            "exposure": self.exposure,
            "business_criticality": self.business_criticality,
            "data_lifetime_years": self.data_lifetime_years,
            "migration_years": self.migration_years,
        }

    def cache_seed(self) -> str:
        parts = []
        for key in ("environment", "owner", "exposure",
                    "business_criticality", "data_lifetime_years",
                    "migration_years"):
            parts.append(f"{key}={getattr(self, key)}")
        return ";".join(parts)


def context_from_args(args) -> "ScanContext":
    """Build a ScanContext from CLI/GUI argument namespaces (never raises).

    Accepts argparse Namespaces or plain dicts; missing attributes stay
    None (unknown). Numeric Mosca inputs that fail parsing stay None.
    """
    _ALIASES = {
        "environment": ("environment",),
        "owner": ("owner",),
        "exposure": ("exposure",),
        "business_criticality": ("business_criticality",
                                 "businessCriticality", "criticality"),
        "data_lifetime_years": ("data_lifetime_years", "dataLifetimeYears",
                                "data_lifetime", "dataLifetime"),
        "migration_years": ("migration_years", "migrationYears",
                            "migration_time", "migrationTime"),
    }

    def _get(key: str):
        try:
            names = _ALIASES.get(key, (key,))
            for name in names:
                if isinstance(args, dict):
                    if name in args and args[name] not in (None, ""):
                        return args[name]
                else:
                    value = getattr(args, name, None)
                    if value not in (None, ""):
                        return value
            return None
        except Exception:
            return None

    def _num(key: str):
        raw = _get(key)
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            return None
        try:
            return float(raw)
        except (TypeError, ValueError):
            return None

    def _str(key: str):
        raw = _get(key)
        if raw is None:
            return None
        text = str(raw).strip()
        return text or None

    return ScanContext(
        environment=_str("environment"),
        owner=_str("owner"),
        exposure=_str("exposure"),
        business_criticality=_str("business_criticality"),
        data_lifetime_years=_num("data_lifetime_years"),
        migration_years=_num("migration_years"),
    )


def risk_z_from_args(args, default: float = 10.0) -> float:
    """Mosca Z from CLI/GUI arguments (caller default when absent)."""
    try:
        if isinstance(args, dict):
            raw = args.get("risk_z", args.get("riskZ"))
        else:
            raw = getattr(args, "risk_z", None)
    except Exception:
        raw = None
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return float(default)
    try:
        return float(raw)
    except (TypeError, ValueError):
        return float(default)


@dataclass(frozen=True)
class ScanRequest:
    """Everything the orchestrator needs for one scan."""

    target: str
    scanners: tuple[str, ...] | list[str] | None = None
    permissions: ScanPermissions = field(default_factory=ScanPermissions)
    profile: str = "standard"
    region: str | None = None
    risk_z: float = 10.0
    context: ScanContext = field(default_factory=ScanContext)
    # Provenance only (which surface asked): cli-scan, cli-scan-binary,
    # cli-scan-container, cli-scan-cloud, ci, gui, pipeline-compat, ...
    caller: str = "unknown"
    # Phase 2 user-facing identity (e.g. GUI input label or repo name).
    # Never the temp upload path: display_target() prefers this, while
    # target stays the exact scan input (deterministic IDs preserved).
    display_name: str | None = None
    # Optional override for archive exploration depth (default per profile).
    max_archive_depth: int | None = None

    def normalized_profile(self) -> str:
        return normalize_profile(self.profile)

    def scanner_list(self) -> list[str] | None:
        if self.scanners is None:
            return None
        return [str(s).strip().lower() for s in self.scanners if str(s).strip()]

    def cleaned_target(self) -> str:
        return str(self.target or "").strip()

    def cleaned_region(self) -> str | None:
        region = str(self.region).strip() if self.region else ""
        return region or None

    def display_target(self) -> str:
        """Primary user-facing identity (Phase 2: never a temp path)."""
        label = str(self.display_name or "").strip()
        return label or self.cleaned_target()

    def archive_depth(self) -> int:
        """Exploration depth: explicit override, else profile default."""
        if self.max_archive_depth is not None:
            try:
                return max(0, min(8, int(self.max_archive_depth)))
            except (TypeError, ValueError):
                pass
        return int(PROFILE_EFFORT[self.normalized_profile()]["archive_depth"])


@dataclass(frozen=True)
class ScanProgressEvent:
    """Structured progress emitted by ScanOrchestrator.scan().

    Stages are stable strings so CLI/GUI/CI can render them without
    coupling to scanner internals.  ``progress`` is 0-100.
    """

    stage: str
    progress: int
    message: str = ""
    detail: dict[str, Any] = field(default_factory=dict)


ProgressCallback = Callable[[ScanProgressEvent], None]


@dataclass(frozen=True)
class ScanPlan:
    """What the orchestrator WILL do for a ScanRequest (no scanning).

    Phase 2 adds the inventory summary (artifact counts, detected
    surfaces, skip reasons); Phase 3 adds effort/permission/cache state.
    All new fields default so Phase 1 callers keep working.
    """

    job_id: str
    kind: str
    label: str
    content_hash: str
    target: str
    profile: str
    permissions: dict[str, bool]
    scanners: tuple[str, ...]
    stages: tuple[str, ...]
    escalate: bool = False
    unavailable: tuple[str, ...] = ()
    caller: str = "unknown"
    # Phase 2: user-facing identity + inventory summary.
    display_target: str = ""
    artifacts_total: int = 0
    artifact_counts: dict[str, int] = field(default_factory=dict)
    surfaces: tuple[str, ...] = ()
    skipped: tuple[dict[str, str], ...] = ()
    warnings: tuple[str, ...] = ()
    # Phase 3: effort, permissions, cache.
    effort: dict[str, Any] = field(default_factory=dict)
    escalation_allowed: bool = False
    permissions_required: tuple[str, ...] = ()
    cache_hit: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "kind": self.kind,
            "label": self.label,
            "content_hash": self.content_hash,
            "target": self.target,
            "display_target": self.display_target or self.target,
            "profile": self.profile,
            "permissions": dict(self.permissions),
            "scanners": list(self.scanners),
            "stages": list(self.stages),
            "escalate": bool(self.escalate),
            "unavailable": list(self.unavailable),
            "caller": self.caller,
            "artifacts_total": int(self.artifacts_total),
            "artifact_counts": dict(self.artifact_counts),
            "surfaces": list(self.surfaces),
            "skipped": [dict(s) for s in self.skipped],
            "warnings": list(self.warnings),
            "effort": dict(self.effort),
            "escalation_allowed": bool(self.escalation_allowed),
            "permissions_required": list(self.permissions_required),
            "cache_hit": bool(self.cache_hit),
        }


@dataclass(frozen=True)
class ScanResult:
    """Completed scan: validated CIR + canonical plus plan/provenance."""

    scan_id: str
    target: str
    cir: dict[str, Any]
    canonical: dict[str, Any]
    plan: ScanPlan
    job_id: str
    kind: str
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def as_tuple(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """Backwards-compatible ``(cir, canonical)`` view."""
        return (self.cir, self.canonical)


def _registry_version() -> str:
    """Signature-registry version for cache keys (never raises)."""
    try:
        from ecdat.core.registry import REGISTRY_VERSION as _v
        return str(_v)
    except Exception:
        return "unknown"


def _inventory_for_request(
    request: ScanRequest, cleaned: str
) -> tuple[list, Any, tuple[str, ...]]:
    """Run Phase 2 inventory for filesystem targets (never raises).

    Returns ``(records, summary_or_None, warnings)``. Non-filesystem
    targets (cloud labels, image refs, endpoints) and inventory errors
    yield empty records plus a warning - the plan/scan degrades to the
    Phase 1 job-level route instead of failing.
    """
    if _is_cloud_label(cleaned) or _is_image_reference(cleaned) \
            or _is_runtime_endpoint(cleaned):
        return [], None, ()
    try:
        if not Path(cleaned).exists():
            return [], None, ()
    except Exception:
        return [], None, ()
    try:
        from ecdat.core.inventory import inventory_target
        records, summary = inventory_target(
            cleaned, max_depth=request.archive_depth())
        return list(records), summary, ()
    except Exception as exc:
        return [], None, (f"inventory-degraded: {exc}",)


def _surfaces_for(records: list) -> tuple[dict[str, int], tuple[str, ...]]:
    """Triage every record centrally; return (counts, detected surfaces)."""
    from ecdat.core.scheduler import AdaptiveScheduler

    scheduler = AdaptiveScheduler()
    counts: dict[str, int] = {}
    for record in records:
        try:
            surface = scheduler.triage_artifact(record)
        except Exception:
            surface = "skip"
        counts[surface] = counts.get(surface, 0) + 1
    detected = tuple(sorted(s for s in counts if s != "skip"))
    return counts, detected


def _permissions_required_for(
    surface_counts: dict[str, int], selected: list[str]
) -> tuple[str, ...]:
    """Detected-but-unselected surfaces (real skip reasons, Phase 3)."""
    notes: list[str] = []
    owned = set(selected)
    for surface, count in sorted(surface_counts.items()):
        if surface == "skip" or count <= 0:
            continue
        owner = SURFACE_OWNER.get(surface)
        if owner and owner not in owned:
            notes.append(
                f"{surface}: {count} artifact(s) detected but "
                f"'{owner}' scanner not selected")
    return tuple(notes)


def _cache_key_for(request: ScanRequest, cleaned: str,
                   selected: list[str], job_content_hash: str) -> str:
    """Generic ScanCache key (Phase 3).

    content hash + signature-registry version + scanner set + profile +
    caller. Tool-binary changes do NOT invalidate this key (versions are
    only observable post-scan); that gap is recorded in the report as a
    known limitation, not hidden.
    """
    import hashlib as _hl

    try:
        context_seed = request.context.cache_seed()
    except Exception:
        context_seed = ""
    try:
        risk_seed = str(float(request.risk_z))
    except (TypeError, ValueError):
        risk_seed = "10.0"
    seed = "|".join([
        job_content_hash,
        _registry_version(),
        ",".join(sorted(selected)),
        request.normalized_profile(),
        str(request.caller or "unknown"),
        cleaned if _is_cloud_label(cleaned) or _is_image_reference(cleaned)
        or _is_runtime_endpoint(cleaned) else "",
        context_seed,
        risk_seed,
    ])
    return "scan:" + _hl.blake2s(seed.encode("utf-8"), digest_size=16).hexdigest()


_BINARY_TOOL_HINTS = ("binary", "lief", "yara", "capa", "floss", "ghidra")


def _apply_scan_context(cir: dict[str, Any], context) -> None:
    """Stamp user-supplied Phase 10 context onto CIR operation dicts.

    Appends ``user:<key>=<value>`` pairs to each operation's
    ``context.notes`` so the risk engine (``user:``-aware) scores them
    as user-supplied provenance. Mutates ``cir`` in place; never raises.
    Unset fields leave no trace (unknown stays unknown).
    """
    try:
        values: dict[str, str] = {}
        for key in ("environment", "owner", "exposure",
                    "business_criticality", "data_lifetime_years",
                    "migration_years"):
            try:
                raw = getattr(context, key, None)
            except Exception:
                raw = None
            if raw is None or (isinstance(raw, str) and not raw.strip()):
                continue
            values[key] = str(raw).strip()
    except Exception:
        return
    if not values:
        return
    addition = "; ".join(f"user:{key}={val}" for key, val in values.items())
    for op in (cir.get("operations", []) or []):
        if not isinstance(op, dict):
            continue
        try:
            ctx = op.get("context")
            if not isinstance(ctx, dict):
                ctx = {}
                op["context"] = ctx
            notes = str(ctx.get("notes", "") or "")
            ctx["notes"] = f"{notes}; {addition}" if notes else addition
        except Exception:
            continue


def _escalation_for(cir: dict[str, Any]) -> dict[str, Any]:
    """Evaluate cheap-pass operations through should_escalate (Phase 3).

    A REAL production caller: every reconstructed operation with binary
    surface evidence and confidence below the scheduler threshold becomes
    a recorded escalation candidate. Expensive backends themselves land
    in Phase 6, so ``escalated`` stays 0 with an explicit note.
    """
    from ecdat.core.scheduler import AdaptiveScheduler

    scheduler = AdaptiveScheduler()
    candidates: list[dict[str, Any]] = []
    operations = cir.get("operations", []) or []
    evaluated = 0
    for op in operations:
        if not isinstance(op, dict):
            continue
        evaluated += 1
        try:
            confidence = float(op.get("confidence", 1.0))
        except (TypeError, ValueError):
            confidence = 0.0
        evidence = op.get("evidence", []) or []
        binary_linked = any(
            isinstance(item, dict) and any(
                hint in str(item.get("tool", "")).lower()
                for hint in _BINARY_TOOL_HINTS)
            for item in evidence)
        if not binary_linked or confidence >= 0.65:
            continue
        signals = {"has_hit": True, "confidence": confidence,
                   "surface": "binary"}
        if scheduler.should_escalate(signals):
            candidates.append({
                "operation_id": str(op.get("operation_id", "")),
                "confidence": confidence,
                "reason": "weak-confidence-binary-evidence",
            })
    candidates.sort(key=lambda c: (c["confidence"], c["operation_id"]))
    return {
        "evaluated": evaluated,
        "candidates": candidates,
        # Binary-level execution counts live in diagnostics["escalation"]
        # via the staged binary report (Phase 6); this stays the CIR-level
        # candidate record.
        "escalated": 0,
        "note": "CIR-level candidates; per-binary execution is recorded "
                "under diagnostics binary_stages",
    }


def _emit(
    callback: ProgressCallback | None,
    stage: str,
    progress: int,
    message: str = "",
    detail: dict[str, Any] | None = None,
) -> None:
    if callback is None:
        return
    try:
        callback(
            ScanProgressEvent(
                stage=stage,
                progress=max(0, min(100, int(progress))),
                message=message,
                detail=dict(detail or {}),
            )
        )
    except Exception:
        # Progress must never break a scan.
        pass


class ScanOrchestrator:
    """The single production orchestration layer (Phases 1-3).

    Owns: input normalization (InputRegistry) -> full inventory with
    safe recursive archive discovery -> central triage
    (AdaptiveScheduler over ArtifactRecords) -> scanner resolution
    (scanner_policy) -> execution (DiscoveryEngine) with structured
    per-scanner outcomes -> CIR/canonical normalization + validation
    -> P1 enrichment (risk + recommendations) -> generic content-hash
    cache. Escalation candidates are evaluated through
    should_escalate and recorded (expensive backends land in Phase 6).

    Later phases deepen fusion/operations/graph inside this class
    without changing its callers.
    """

    def __init__(self) -> None:
        # Shared content-hash cache for future phases (Phase 3 activates
        # generic ScanCache semantics; created here so plan/scan share it).
        from ecdat.core.scheduler import ScanCache

        self._cache = ScanCache()

    @property
    def cache(self):  # type: ignore[no-untyped-def]
        return self._cache

    # -- planning ------------------------------------------------------

    def plan(self, request: ScanRequest) -> ScanPlan:
        """Return what WOULD run for ``request`` without scanning.

        Phase 2/3: normalizes the target, runs the real inventory
        (safe recursive archive discovery), triages every record
        centrally, and reports scanners, effort, permissions, and
        cache state. No scanner executes.
        """
        from ecdat.adapters import scanner_policy as _policy
        from ecdat.core.scheduler import AdaptiveScheduler, InputRegistry

        cleaned = request.cleaned_target()
        if not cleaned:
            raise RealScanError("target must be a non-empty string")
        profile = request.normalized_profile()
        permissions = request.permissions or ScanPermissions()
        try:
            selected = _policy.resolve_scanners(
                request.scanner_list(),
                allow_container=permissions.allow_container,
                allow_cloud=permissions.allow_cloud,
                allow_runtime=permissions.allow_runtime,
            )
        except ValueError as exc:
            raise RealScanError(str(exc))

        job = InputRegistry().normalize(cleaned)
        scheduler = AdaptiveScheduler()
        route = scheduler.route(job)
        stages = tuple(str(s) for s in (route.get("stages") or ()))
        escalate = bool(route.get("escalate", False))

        records, summary, warnings = _inventory_for_request(request, cleaned)
        surface_counts, detected = _surfaces_for(records)
        permissions_required = _permissions_required_for(
            surface_counts, list(selected))
        effort = dict(PROFILE_EFFORT[profile])
        escalation_allowed = bool(effort["escalation_allowed"])

        unavailable: tuple[str, ...] = ()
        try:
            from ecdat.scanners.discovery import DiscoveryEngine

            engine = DiscoveryEngine(enabled_scanners=list(selected))
            availability = dict(engine.availability())
            unavailable = tuple(sorted(n for n, ok in availability.items() if not ok))
        except Exception:
            unavailable = ()

        cache_hit = self._cache.get(
            _cache_key_for(request, cleaned, list(selected),
                           job.content_hash)) is not None
        artifact_counts = dict(summary.by_category) if summary else {}
        skipped = tuple(summary.skipped) if summary else ()

        return ScanPlan(
            job_id=job.job_id,
            kind=job.kind,
            label=job.label,
            content_hash=job.content_hash,
            target=cleaned,
            profile=profile,
            permissions=permissions.as_dict(),
            scanners=tuple(selected),
            stages=stages,
            escalate=escalate,
            unavailable=unavailable,
            caller=str(request.caller or "unknown"),
            display_target=request.display_target(),
            artifacts_total=int(summary.total) if summary else 0,
            artifact_counts=artifact_counts,
            surfaces=detected,
            skipped=skipped,
            warnings=tuple(warnings),
            effort=effort,
            escalation_allowed=escalation_allowed,
            permissions_required=permissions_required,
            cache_hit=bool(cache_hit),
        )

    # -- scanning ------------------------------------------------------

    def scan(
        self,
        request: ScanRequest,
        progress: ProgressCallback | None = None,
    ) -> ScanResult:
        """Execute the full integrated pipeline for ``request``."""
        from ecdat.adapters import normalize as _norm
        from ecdat.adapters import scanner_policy as _policy
        from ecdat.core.scheduler import AdaptiveScheduler, InputRegistry

        t0 = time.monotonic()
        cleaned = request.cleaned_target()
        if not cleaned:
            raise RealScanError("target must be a non-empty string")
        profile = request.normalized_profile()
        permissions = request.permissions or ScanPermissions()
        region = request.cleaned_region()
        try:
            risk_z = float(request.risk_z)
        except (TypeError, ValueError):
            raise RealScanError(f"invalid risk_z: {request.risk_z!r}")

        _emit(progress, "normalize", 5, f"Normalizing target {cleaned!r}")
        try:
            selected = _policy.resolve_scanners(
                request.scanner_list(),
                allow_container=permissions.allow_container,
                allow_cloud=permissions.allow_cloud,
                allow_runtime=permissions.allow_runtime,
            )
        except ValueError as exc:
            raise RealScanError(str(exc))

        if _target_requires_existing_path(cleaned, selected):
            if not Path(cleaned).exists():
                raise RealScanError(f"scan target does not exist: {cleaned}")

        # Phase 7 permission model: pulling a remote image is an explicit
        # network action. Supplied local images/tars/rootfs analyze
        # automatically; refs require allow_pull (CLI --allow-pull, GUI
        # external-discovery opt-in, or explicit scan-container intent).
        if _is_image_reference(cleaned) and not _is_cloud_label(cleaned) \
                and not _is_runtime_endpoint(cleaned) \
                and not permissions.allow_pull:
            raise RealScanError(
                f"refusing to pull image {cleaned!r} without explicit "
                "permission (pass --allow-pull or enable image-pull "
                "discovery; local tars/rootfs scan without it)")
        if _is_image_reference(cleaned) and not _is_cloud_label(cleaned) \
                and not _is_runtime_endpoint(cleaned) \
                and permissions.allow_pull:
            try:
                from ecdat.scanners.container.scanner import (
                    container_backend_status)
                backends = container_backend_status()
            except Exception:
                backends = {}
            if backends and not any(
                    v == "available" for v in backends.values()):
                raise RealScanError(
                    f"container backends unavailable for {cleaned!r} "
                    "(no docker daemon, syft, or trivy; cannot pull or "
                    "inspect the image)")

        job = InputRegistry().normalize(cleaned)
        route = AdaptiveScheduler().route(job)
        stages = [str(s) for s in (route.get("stages") or ())]
        escalate = bool(route.get("escalate", False))
        effort = dict(PROFILE_EFFORT[profile])
        escalation_allowed = bool(effort["escalation_allowed"])

        _emit(
            progress, "plan", 10,
            f"Planned {len(selected)} scanner(s) for {job.kind}",
            {"job_id": job.job_id, "kind": job.kind,
             "scanners": list(selected), "stages": stages,
             "profile": profile, "caller": str(request.caller or "unknown")},
        )

        # Phase 2: real inventory before any scanner runs.
        _emit(progress, "inventory", 18, "Inventorying artifacts")
        records, summary, inv_warnings = _inventory_for_request(
            request, cleaned)
        surface_counts, detected = _surfaces_for(records)
        permissions_required = _permissions_required_for(
            surface_counts, list(selected))
        for warning in inv_warnings:
            print(f"warning: {warning}", file=sys.stderr)
        _emit(progress, "triage", 24,
              f"Triaged {len(records)} artifact(s) into "
              f"{len(detected)} surface(s)",
              {"artifacts": len(records), "surfaces": list(detected)})

        # Phase 3: generic content-hash cache. A repeat of the same
        # target + registry + scanners + profile + caller returns the
        # stored result instead of re-scanning.
        cache_key = _cache_key_for(request, cleaned, list(selected),
                                   job.content_hash)
        cached = self._cache.get(cache_key)
        if isinstance(cached, ScanResult):
            import dataclasses as _dc

            _emit(progress, "complete", 100, "Scan complete (cache hit)",
                  {"scan_id": cached.scan_id, "cache_hit": True})
            return _dc.replace(
                cached,
                plan=_dc.replace(cached.plan, cache_hit=True),
                diagnostics={**cached.diagnostics, "cache_hit": True},
            )

        try:
            from ecdat.scanners.discovery import DiscoveryEngine
        except ImportError as exc:
            raise RealScanError(
                "real scan requires the discovery dependencies "
                f"(pydantic, pyyaml, cryptography): {exc}"
            )
        try:
            engine = DiscoveryEngine(enabled_scanners=list(selected))
        except Exception as exc:
            raise RealScanError(
                f"discovery failed for target {cleaned!r} "
                f"({_policy.describe_selection(list(selected))}): {exc}"
            )

        # Honest unavailable handling: warn for partially unavailable
        # selections, but fail loudly when NOTHING could run - otherwise an
        # empty scan would masquerade unavailable tools as zero findings.
        _emit(progress, "availability", 30, "Probing scanner availability")
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
            # yield findings from filesystem scanners - fail loudly instead of
            # storing an empty scan that hides the missing capability.
            if _is_cloud_label(cleaned) and availability.get("cloud") is False:
                raise RealScanError(
                    f"cloud scanner unavailable for target {cleaned!r} "
                    "(missing SDK or credentials; cannot scan cloud label)")
            if _is_image_reference(cleaned) and availability.get("container") is False:
                raise RealScanError(
                    f"container scanner unavailable for target {cleaned!r} "
                    "(missing docker/syft; cannot scan image reference)")
        else:
            unavailable = []

        _emit(progress, "discovery", 40,
              f"Running discovery ({_policy.describe_selection(list(selected))})")
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
            # Phase 4: route only inventory-confirmed source artifacts into
            # the source scanner (scanners without artifact support ignore
            # the kwarg; empty inventory falls back to own traversal).
            if records:
                scan_kwargs["artifacts"] = [
                    {"abs_path": r.abs_path,
                     "relative_path": r.relative_path,
                     "category": r.category} for r in records]
            # Phase 6: staged binary analysis follows the profile effort
            # (quick never escalates; deep may expect heavy backends).
            scan_kwargs["escalation_allowed"] = bool(
                PROFILE_EFFORT[profile]["escalation_allowed"])
            scan_kwargs["expensive_backends"] = tuple(
                PROFILE_EFFORT[profile]["expensive_backends"])
            # Phase 7: pull/build permissions reach the container family.
            scan_kwargs["allow_pull"] = bool(permissions.allow_pull)
            scan_kwargs["allow_build"] = bool(permissions.allow_build)
            cir_doc = engine.scan_and_emit_cir(
                cleaned, target_name=cleaned, **scan_kwargs)
        except RealScanError:
            raise
        except Exception as exc:
            raise RealScanError(
                f"discovery failed for target {cleaned!r} "
                f"({_policy.describe_selection(list(selected))}): {exc}"
            )

        _emit(progress, "normalize_cir", 60, "Normalizing CIR")
        try:
            cir = cir_doc.model_dump(mode="json", exclude_none=True)
        except Exception as exc:
            raise RealScanError(f"could not serialize CIR for {cleaned!r}: {exc}")

        try:
            try:
                context_seed = request.context.cache_seed()
            except Exception:
                context_seed = ""
            cir = _norm.normalize_cir(cir, cleaned, context_seed)
        except ValueError as exc:
            raise RealScanError(f"CIR normalization failed: {exc}")

        _emit(progress, "validate_cir", 68, "Validating CIR")
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

        _emit(progress, "enrich", 78, "Scoring risk and recommendations")
        try:
            from ecdat.core import api as _api
        except ImportError as exc:
            raise RealScanError(
                f"real scan requires the core analysis modules: {exc}"
            )
        try:
            _apply_scan_context(cir, request.context)
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

        _emit(progress, "validate_canonical", 90, "Validating canonical result")
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

        plan = ScanPlan(
            job_id=job.job_id,
            kind=job.kind,
            label=job.label,
            content_hash=job.content_hash,
            target=cleaned,
            profile=profile,
            permissions=permissions.as_dict(),
            scanners=tuple(selected),
            stages=tuple(stages),
            escalate=escalate,
            unavailable=tuple(sorted(unavailable)),
            caller=str(request.caller or "unknown"),
            display_target=request.display_target(),
            artifacts_total=len(records),
            artifact_counts=dict(summary.by_category) if summary else {},
            surfaces=detected,
            skipped=tuple(summary.skipped) if summary else (),
            warnings=tuple(inv_warnings),
            effort=effort,
            escalation_allowed=escalation_allowed,
            permissions_required=permissions_required,
            cache_hit=False,
        )
        elapsed = time.monotonic() - t0
        try:
            tool_versions = dict(canonical.get("tool_versions", {}) or {})
        except Exception:
            tool_versions = {}
        # Phase 3: structured per-scanner outcomes (success / unavailable /
        # failed); skipped-by-policy/irrelevant come from the plan's
        # permissions_required + zero-finding scanners are reported as
        # success with no findings (never silently "nothing found": the
        # unavailable gate above already failed loudly when nothing ran).
        try:
            scanner_status = dict(engine.last_status())
        except Exception:
            scanner_status = {}
        escalation = _escalation_for(enriched)
        # Phase 6: staged binary record (cheap pass always, expensive
        # candidate-only). Empty when the binary family did not run.
        try:
            binary_stages = dict(engine.binary_stage_report())
        except Exception:
            binary_stages = {}
        try:
            stage_summary = dict(binary_stages.get("summary", {}))
        except Exception:
            stage_summary = {}
        if stage_summary:
            escalation = {**escalation,
                          "binaries_evaluated": stage_summary.get("binaries", 0),
                          "binaries_with_findings": stage_summary.get(
                              "with_findings", 0),
                          "binary_candidates": stage_summary.get(
                              "cheap_pass_candidates", 0),
                          "binaries_escalated": stage_summary.get(
                              "escalated_binaries", 0),
                          "expensive_analysis_rate": stage_summary.get(
                              "expensive_analysis_rate", 0.0),
                          "binary_stage_times": stage_summary.get(
                              "stage_times", {})}
        diagnostics: dict[str, Any] = {
            "job_id": job.job_id,
            "kind": job.kind,
            "content_hash": job.content_hash,
            "profile": profile,
            "caller": str(request.caller or "unknown"),
            "display_target": request.display_target(),
            "scanners": list(selected),
            "stages": list(stages),
            "escalate": escalate,
            "escalation_allowed": escalation_allowed,
            "escalation": escalation,
            "unavailable": sorted(unavailable),
            "scanner_status": scanner_status,
            "binary_stages": binary_stages.get("summary", {}),
            "binary_tools": binary_stages.get("tools", {}),
            "permissions_required": list(permissions_required),
            "artifacts_total": len(records),
            "artifact_counts": dict(summary.by_category) if summary else {},
            "surfaces": list(detected),
            "cache_hit": False,
            "cache_key": cache_key,
            "registry_version": _registry_version(),
            "tool_versions": tool_versions,
            "elapsed_sec": round(float(elapsed), 3),
        }
        scan_id = str(
            canonical.get("scan_id") or enriched.get("scan_id") or job.job_id
        )
        _emit(progress, "complete", 100, "Scan complete",
              {"scan_id": scan_id, "elapsed_sec": diagnostics["elapsed_sec"]})
        result = ScanResult(
            scan_id=scan_id,
            target=cleaned,
            cir=enriched,
            canonical=canonical,
            plan=plan,
            job_id=job.job_id,
            kind=job.kind,
            diagnostics=diagnostics,
        )
        self._cache.set(cache_key, result)
        return result

    def scan_with_cir(
        self,
        request: ScanRequest,
        progress: ProgressCallback | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Convenience ``(cir, canonical)`` view over :meth:`scan`."""
        result = self.scan(request, progress=progress)
        return result.as_tuple()


_orchestrator: ScanOrchestrator | None = None


def get_orchestrator() -> ScanOrchestrator:
    """Process-wide shared orchestrator (stateless apart from cache)."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = ScanOrchestrator()
    return _orchestrator


def plan_scan(request: ScanRequest) -> ScanPlan:
    """Plan via the shared orchestrator (convenience for API/GUI preview)."""
    return get_orchestrator().plan(request)


def run_scan(
    request: ScanRequest,
    progress: ProgressCallback | None = None,
) -> ScanResult:
    """Scan via the shared orchestrator (convenience for callers)."""
    return get_orchestrator().scan(request, progress=progress)
