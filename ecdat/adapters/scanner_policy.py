"""Scanner selection policy (Person 3 platform layer).

P3-owned safety boundary: the default real scan runs a fixed,
explicit, network-free scanner subset. Opt-in families (container,
cloud, runtime) require explicit caller action. The engine is NEVER
constructed with ``enabled_scanners=None`` (which would auto-enable
everything available, including the AWS STS identity call and the
runtime socket probers).

Availability results are cached per process so repeated scans do not
re-probe tool binaries (or the network, for gated families).
"""

from __future__ import annotations

from functools import lru_cache

#: Default real scanners: local-filesystem only, no network, no creds.
DEFAULT_SCANNERS: tuple[str, ...] = (
    "source",
    "dependency",
    "binary",
    "config",
    "certificate",
)

#: Opt-in families and what they may touch (documented for operators).
OPT_IN_SCANNERS: dict[str, str] = {
    "container": "runs local docker/syft subprocesses when present",
    "cloud": "may call cloud APIs with ambient credentials (e.g. AWS STS)",
    "runtime": "opens real TLS/SSH sockets to host:port targets",
}

_ALL_KNOWN = DEFAULT_SCANNERS + tuple(OPT_IN_SCANNERS)


def resolve_scanners(
    scanners: list[str] | tuple[str, ...] | None = None,
    allow_container: bool = False,
    allow_cloud: bool = False,
    allow_runtime: bool = False,
) -> list[str]:
    """Resolve the explicit scanner allowlist for one real scan.

    Returns a concrete list (never None). Unknown names raise ValueError.
    Opt-in families are included only with their explicit flag — or when
    named in ``scanners`` explicitly (explicit naming IS the opt-in).
    """
    if scanners is not None:
        requested = [str(s).strip().lower() for s in scanners if str(s).strip()]
        unknown = [s for s in requested if s not in _ALL_KNOWN]
        if unknown:
            raise ValueError(
                f"unknown scanner(s): {', '.join(unknown)} "
                f"(known: {', '.join(_ALL_KNOWN)})"
            )
        if not requested:
            raise ValueError("scanner list must not be empty")
        return requested
    selected = list(DEFAULT_SCANNERS)
    if allow_container:
        selected.append("container")
    if allow_cloud:
        selected.append("cloud")
    if allow_runtime:
        selected.append("runtime")
    return selected


@lru_cache(maxsize=1)
def cached_availability() -> dict[str, bool]:
    """Per-process scanner availability snapshot (no repeated probing)."""
    from ecdat.scanners.discovery import DiscoveryEngine

    engine = DiscoveryEngine(enabled_scanners=list(DEFAULT_SCANNERS))
    available = set(engine.get_enabled_scanners())
    return {name: (name in available) for name in _ALL_KNOWN}


def describe_selection(selected: list[str]) -> str:
    """One-line human description of a resolved selection (CLI/GUI notes)."""
    bits = []
    for name in selected:
        note = OPT_IN_SCANNERS.get(name)
        bits.append(f"{name} (opt-in: {note})" if note else name)
    return "scanners: " + ", ".join(bits)
