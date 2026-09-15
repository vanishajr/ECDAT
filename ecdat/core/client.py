"""CoreClient interface + mock/real implementations (Person 3 platform layer).

Person 1 (Core Intelligence) owns real analysis and Person 2
(Discovery) owns real detection. This module defines the
decoupling contract Person 3 codes against:

    CoreClient.scan(target: Path) -> dict   # canonical v1 JSON dict

- MockCoreClient: deterministic, fixture-backed, no real scanning.
  Output is validated with ecdat.core.validate.validate() before return.
- RealCoreClient: integrated adapter. scan() runs the single logical
  real scan (P2 DiscoveryEngine -> CIR v0.1 -> P1 validate/enrich/convert
  -> P3 normalization -> validated canonical). Failures raise
  RealScanError; there is no mock fallback.
- get_client(mode): factory for "mock" / "real".
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Protocol, runtime_checkable

from ecdat.core.validate import load_json, validate

__all__ = [
    "CoreClient",
    "MockCoreClient",
    "RealCoreClient",
    "get_client",
]

# Fixture dir default: <repo>/tests/fixtures/canonical resolved from this file.
# ecdat/core/client.py -> parents[2] == repo root when running from source.
_DEFAULT_FIXTURES_DIR = (
    Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "canonical"
)


@runtime_checkable
class CoreClient(Protocol):
    """Decoupling contract for Person 1's Core API."""

    def scan(self, target: Path) -> dict:
        """Scan target and return a canonical v1 JSON dict (validated)."""
        ...


class MockCoreClient:
    """Deterministic fixture-backed mock. No real scanning.

    Routing (by target name, case-insensitive):
      - name contains "empty" or "clean" -> empty.json (0 findings)
      - target is an existing directory, or name contains
        "multi" / "app" / "bulk" -> multi.json
      - otherwise -> minimal.json (1 finding)

    The fixture is deep-copied, its "target" field is overwritten with
    str(target) for realism, then validated with validate() before return.
    Finding-level "file" fields stay as in the fixture (mock limitation).
    """

    def __init__(self, fixtures_dir: Path | str | None = None) -> None:
        self.fixtures_dir = (
            Path(fixtures_dir) if fixtures_dir is not None else _DEFAULT_FIXTURES_DIR
        )

    def _fixture_for(self, target: Path) -> Path:
        name = target.name.lower()
        if "empty" in name or "clean" in name:
            return self.fixtures_dir / "empty.json"
        if target.is_dir() or "multi" in name or "app" in name or "bulk" in name:
            return self.fixtures_dir / "multi.json"
        return self.fixtures_dir / "minimal.json"

    def scan(self, target: Path) -> dict:
        target = Path(target)
        doc = copy.deepcopy(load_json(self._fixture_for(target)))
        doc["target"] = str(target)
        return validate(doc)


class RealCoreClient:
    """Integrated real adapter: ONE logical scan, no mock fallback.

    scan() runs the P3-owned pipeline (``ecdat.adapters.pipeline``):
    P2 DiscoveryEngine scans the target exactly once into CIR v0.1,
    P1 validates/scores/recommends/converts that CIR, P3 normalizes
    (deterministic scan ID, RFC3339 timestamps, real files_scanned,
    asset-only findings) and validates the canonical document.

    P1's ``api.scan()`` is deliberately never called — it performs its
    own discovery and would scan the target a second time. P2's naive
    ``_cir_to_canonical`` is likewise unused; conversion is P1's
    ``to_canonical``.

    Constructor options (all optional): ``scanners`` (explicit list —
    the default safe subset applies when omitted), ``allow_container``,
    ``allow_cloud``, ``allow_runtime`` (opt-in families), ``risk_z``.
    Every failure raises ``RealScanError`` (never mock data).
    """

    def __init__(
        self,
        scanners: list[str] | tuple[str, ...] | None = None,
        allow_container: bool = False,
        allow_cloud: bool = False,
        allow_runtime: bool = False,
        risk_z: float = 10.0,
        **kwargs,
    ) -> None:
        if kwargs:
            raise ValueError(
                f"unknown RealCoreClient option(s): {sorted(kwargs)}"
            )
        self.scanners = list(scanners) if scanners is not None else None
        self.allow_container = bool(allow_container)
        self.allow_cloud = bool(allow_cloud)
        self.allow_runtime = bool(allow_runtime)
        self.risk_z = float(risk_z)

    def scan(self, target: Path) -> dict:
        from ecdat.adapters.pipeline import RealScanError  # noqa: F401
        from ecdat.adapters.pipeline import run_real_scan

        _enriched, canonical = run_real_scan(
            target,
            scanners=self.scanners,
            allow_container=self.allow_container,
            allow_cloud=self.allow_cloud,
            allow_runtime=self.allow_runtime,
            risk_z=self.risk_z,
        )
        return canonical

    def scan_with_cir(self, target: Path) -> tuple[dict, dict]:
        """Scan and return ``(cir_dict, canonical_doc)``.

        The CIR sidecar is what the platform persists next to the
        canonical document (risk, recommendations, graph). Same
        single-scan semantics and failure behavior as ``scan``.
        """
        from ecdat.adapters.pipeline import run_real_scan

        return run_real_scan(
            target,
            scanners=self.scanners,
            allow_container=self.allow_container,
            allow_cloud=self.allow_cloud,
            allow_runtime=self.allow_runtime,
            risk_z=self.risk_z,
        )


def get_client(mode: str = "mock", **kwargs) -> CoreClient:
    """Factory: get_client("mock") -> MockCoreClient, ("real") -> RealCoreClient."""
    if mode == "mock":
        return MockCoreClient(**kwargs)
    if mode == "real":
        return RealCoreClient(**kwargs)
    raise ValueError(f"unknown client mode: {mode!r} (expected 'mock' or 'real')")
