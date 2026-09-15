"""CoreClient interface + mock/real implementations (Person 3 platform layer).

Person 1 (Core Intelligence) owns real detection. This module defines the
decoupling contract Person 3 codes against:

    CoreClient.scan(target: Path) -> dict   # canonical v1 JSON dict

- MockCoreClient: deterministic, fixture-backed, no real scanning. Used
  until Person 1's entry point is finalized. Output is validated with
  ecdat.core.validate.validate() before return.
- RealCoreClient: thin placeholder adapter. scan() raises
  NotImplementedError until Person 1's import path + function signature
  are agreed. Only this class changes at integration time.
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
    """Real adapter: uses DiscoveryEngine to scan and emit CIR v0.1,
    then converts to canonical v1 dict for Person 3 platform layer."""

    def __init__(self, scanners: list[str] | None = None) -> None:
        self.scanners = scanners

    def scan(self, target: Path) -> dict:
        target = Path(target)
        from ecdat import create_discovery_engine
        from ecdat.core.validate import validate

        engine = create_discovery_engine(self.scanners)
        cir = engine.scan_and_emit_cir(target, target_name=str(target))

        # Convert CIR v0.1 to canonical v1 format
        canonical = self._cir_to_canonical(cir, str(target))
        
        # Validate against canonical v1 schema
        return validate(canonical)

    def _cir_to_canonical(self, cir, target: str) -> dict:
        """Convert CIRDocument to canonical v1 format."""
        findings = []
        
        # Convert assets to findings
        for asset in cir.assets:
            finding = {
                "rule_id": f"CRYPTO-ASSET-{asset.canonical.replace('-', '-').upper()}",
                "title": f"Cryptographic asset detected: {asset.canonical}",
                "severity": "info",
                "file": asset.location.file if asset.location and asset.location.file else target,
                "line": asset.location.line if asset.location and asset.location.line else 0,
                "snippet": asset.evidence[0].snippet if asset.evidence else "",
                "confidence": asset.confidence,
                "metadata": {
                    "asset_id": asset.asset_id,
                    "canonical_name": asset.canonical,
                    "key_size": asset.key_size,
                    "mode": asset.mode,
                    "library": asset.library,
                    "usage_state": asset.usage_state.value if asset.usage_state else None,
                }
            }
            findings.append(finding)
        
        # Convert operations to findings
        for op in cir.operations:
            finding = {
                "rule_id": f"CRYPTO-OP-{op.operation_type.value.upper()}",
                "title": f"Cryptographic operation detected: {op.operation_type.value}",
                "severity": "info",
                "file": op.location.file if op.location and op.location.file else target,
                "line": op.location.line if op.location and op.location.line else 0,
                "snippet": op.evidence[0].snippet if op.evidence else "",
                "confidence": op.confidence,
                "metadata": {
                    "operation_id": op.operation_id,
                    "operation_type": op.operation_type.value,
                    "asset_id": op.asset_id,
                    "function": op.function,
                }
            }
            findings.append(finding)

        return {
            "schema_version": "1.0",
            "scan_id": cir.scan_id,
            "target": target,
            "started_at": cir.started_at.isoformat() + "Z",
            "finished_at": cir.finished_at.isoformat() + "Z",
            "tool_versions": cir.tool_versions,
            "findings": findings,
            "stats": {
                "files_scanned": 1,
                "findings_count": len(findings)
            }
        }


def get_client(mode: str = "mock", **kwargs) -> CoreClient:
    """Factory: get_client("mock") -> MockCoreClient, ("real") -> RealCoreClient."""
    if mode == "mock":
        return MockCoreClient(**kwargs)
    if mode == "real":
        if kwargs:
            raise ValueError("RealCoreClient takes no constructor arguments yet.")
        return RealCoreClient()
    raise ValueError(f"unknown client mode: {mode!r} (expected 'mock' or 'real')")
