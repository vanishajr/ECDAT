"""Best-effort resource measurement via stdlib only (Person 3 platform layer).

- CPU time: `os.times()` user+sys delta — cross-platform, always
  available.
- Peak RSS: `resource.getrusage(RUSAGE_SELF).ru_maxrss` on Unix
  (Linux reports KiB, macOS bytes). Unavailable on platforms without
  `resource` (e.g. Windows) and never faked: callers get None plus an
  explanatory note, and the interface accepts richer collectors later
  (e.g. psutil-backed) without changing result structure.
"""

from __future__ import annotations

import os
import sys
import time


def cpu_times() -> tuple[float, float] | None:
    """(user_s, sys_s) for this process, or None if unsupported."""
    try:
        t = os.times()
    except (OSError, AttributeError):
        return None
    return (t.user, t.system)


def peak_rss_bytes() -> int | None:
    """Peak resident set size in bytes, or None if unmeasurable."""
    try:
        import resource
    except ImportError:
        return None
    try:
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (OSError, ValueError):
        return None
    if sys.platform == "darwin":
        return int(peak)  # macOS reports bytes
    return int(peak) * 1024  # Linux reports KiB


def collect(cpu_start: tuple[float, float] | None, wall_start: float) -> dict:
    """Build the stable resources payload for a finished benchmark run."""
    del wall_start  # wall time is recorded separately; kept for future use
    rss = peak_rss_bytes()
    cpu = cpu_times()
    cpu_s = None
    if cpu is not None and cpu_start is not None:
        cpu_s = max(0.0, (cpu[0] - cpu_start[0]) + (cpu[1] - cpu_start[1]))
    notes = []
    if rss is None:
        notes.append("peak RSS unavailable on this platform without extra dependencies.")
    return {
        "peak_rss_bytes": rss,
        "cpu_s": cpu_s,
        "note": " ".join(notes)
        or "stdlib-only measurement (os.times/resource); see ecdat.benchmark.resources.",
    }


def now_wall() -> float:
    """Wall-clock source for benchmark timing."""
    return time.perf_counter()
