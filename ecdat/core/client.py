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
    """Thin placeholder for Person 1's real Core API.

    DO NOT implement detection here. At integration time, this class
    becomes a small adapter that imports Person 1's finalized entry
    point, calls it, and returns its canonical dict (validated).
    Until then, scan() raises NotImplementedError.
    """

    def scan(self, target: Path) -> dict:  # noqa: ARG002
        raise NotImplementedError(
            "Person 1 Core entry point not finalized. "
            "Use get_client('mock') until the real adapter is agreed."
        )


def get_client(mode: str = "mock", **kwargs) -> CoreClient:
    """Factory: get_client("mock") -> MockCoreClient, ("real") -> RealCoreClient."""
    if mode == "mock":
        return MockCoreClient(**kwargs)
    if mode == "real":
        if kwargs:
            raise ValueError("RealCoreClient takes no constructor arguments yet.")
        return RealCoreClient()
    raise ValueError(f"unknown client mode: {mode!r} (expected 'mock' or 'real')")
