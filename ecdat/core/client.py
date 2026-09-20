"""Client boundary for the integrated ECDAT scan pipeline.

Phase 1: thin facade over ScanOrchestrator (the single production
pipeline owner).  All CLI/CI callers go through this client, which
delegates to the shared orchestrator - never a separate pipeline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

__all__ = ["CoreClient", "RealCoreClient", "get_client"]


@runtime_checkable
class CoreClient(Protocol):
    """Boundary between callers and the integrated discovery pipeline."""

    def scan(self, target: Path) -> dict:
        """Scan a target and return a validated canonical v1 document."""
        ...


class RealCoreClient:
    """Run one integrated discovery, analysis, and canonicalization pass.

    Thin facade: builds a ScanRequest and delegates to the shared
    ScanOrchestrator.  ``profile``/``caller`` are Phase 1 additions
    (default ``standard``/``client``); all prior arguments keep their
    meaning.
    """

    def __init__(
        self,
        scanners: list[str] | tuple[str, ...] | None = None,
        allow_container: bool = False,
        allow_cloud: bool = False,
        allow_runtime: bool = False,
        allow_pull: bool = False,
        allow_build: bool = False,
        risk_z: float = 10.0,
        region: str | None = None,
        profile: str = "standard",
        caller: str = "client",
        context=None,
        cloud_aws_access_key_id: str | None = None,
        cloud_aws_secret_access_key: str | None = None,
        cloud_aws_session_token: str | None = None,
        cloud_aws_profile: str | None = None,
        display_name: str | None = None,
        **kwargs,
    ) -> None:
        if kwargs:
            raise ValueError(f"unknown RealCoreClient option(s): {sorted(kwargs)}")
        def _opt(value: str | None) -> str | None:
            text = str(value).strip() if value else ""
            return text or None

        self.cloud_aws_access_key_id = _opt(cloud_aws_access_key_id)
        self.cloud_aws_secret_access_key = _opt(cloud_aws_secret_access_key)
        self.cloud_aws_session_token = _opt(cloud_aws_session_token)
        self.cloud_aws_profile = _opt(cloud_aws_profile)
        self.display_name = str(display_name).strip() or None
        self.scanners = list(scanners) if scanners is not None else None
        self.allow_container = bool(allow_container)
        self.allow_cloud = bool(allow_cloud)
        self.allow_runtime = bool(allow_runtime)
        self.allow_pull = bool(allow_pull)
        self.allow_build = bool(allow_build)
        self.risk_z = float(risk_z)
        self.region = str(region).strip() if region else None
        self.profile = str(profile or "standard")
        self.caller = str(caller or "client")
        if context is None:
            from ecdat.core.orchestrator import ScanContext as _Ctx
            context = _Ctx()
        self.context = context

    def scan(self, target: Path) -> dict:
        return self.scan_with_cir(target)[1]

    def scan_result(self, target: Path | str):
        """Full ScanResult (CIR + canonical + plan + diagnostics)."""
        from ecdat.core.orchestrator import (
            ScanContext,
            ScanPermissions,
            ScanRequest,
            get_orchestrator,
        )

        context = self.context
        if not isinstance(context, ScanContext):
            try:
                context = ScanContext(**dict(context or {}))
            except Exception:
                context = ScanContext()
        request = ScanRequest(
            target=str(target),
            scanners=list(self.scanners) if self.scanners is not None else None,
            permissions=ScanPermissions(
                allow_container=self.allow_container,
                allow_cloud=self.allow_cloud,
                allow_runtime=self.allow_runtime,
                allow_pull=self.allow_pull,
                allow_build=self.allow_build,
            ),
            profile=self.profile,
            region=self.region,
            risk_z=self.risk_z,
            context=context,
            caller=self.caller,
            display_name=self.display_name,
            cloud_aws_access_key_id=self.cloud_aws_access_key_id,
            cloud_aws_secret_access_key=self.cloud_aws_secret_access_key,
            cloud_aws_session_token=self.cloud_aws_session_token,
            cloud_aws_profile=self.cloud_aws_profile,
        )
        return get_orchestrator().scan(request)

    def scan_with_cir(self, target: Path | str) -> tuple[dict, dict]:
        from ecdat.core.orchestrator import (
            ScanContext,
            ScanPermissions,
            ScanRequest,
            get_orchestrator,
        )

        context = self.context
        if not isinstance(context, ScanContext):
            try:
                context = ScanContext(**dict(context or {}))
            except Exception:
                context = ScanContext()
        request = ScanRequest(
            target=str(target),
            scanners=list(self.scanners) if self.scanners is not None else None,
            permissions=ScanPermissions(
                allow_container=self.allow_container,
                allow_cloud=self.allow_cloud,
                allow_runtime=self.allow_runtime,
                allow_pull=self.allow_pull,
                allow_build=self.allow_build,
            ),
            profile=self.profile,
            region=self.region,
            risk_z=self.risk_z,
            context=context,
            caller=self.caller,
            display_name=self.display_name,
            cloud_aws_access_key_id=self.cloud_aws_access_key_id,
            cloud_aws_secret_access_key=self.cloud_aws_secret_access_key,
            cloud_aws_session_token=self.cloud_aws_session_token,
            cloud_aws_profile=self.cloud_aws_profile,
        )
        return get_orchestrator().scan(request).as_tuple()


def get_client(**kwargs) -> CoreClient:
    """Return the integrated client used by every application surface."""
    return RealCoreClient(**kwargs)
