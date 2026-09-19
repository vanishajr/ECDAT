from __future__ import annotations

import json
import ctypes
from pathlib import Path
import sys
import time
from typing import Any

try:
    import resource
except ImportError:  # pragma: no cover - Windows has no POSIX resource module.
    resource = None

from .ecdat_adapter import run_production_scan


ROOT = Path(__file__).resolve().parent


def load_repo_lock() -> dict[str, Any]:
    return json.loads((ROOT / "repo-lock.json").read_text(encoding="utf-8"))


def find_repo(repo_id: str) -> dict[str, Any]:
    for repo in load_repo_lock()["repositories"]:
        if repo["id"] == repo_id:
            return repo
    raise KeyError(repo_id)


def _peak_rss_mb() -> float:
    if resource is None:
        if sys.platform == "win32":
            class _ProcessMemoryCounters(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong),
                    ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = _ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            psapi = ctypes.WinDLL("psapi")
            kernel32 = ctypes.WinDLL("kernel32")
            psapi.GetProcessMemoryInfo.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(_ProcessMemoryCounters),
                ctypes.c_ulong,
            ]
            psapi.GetProcessMemoryInfo.restype = ctypes.c_bool
            if psapi.GetProcessMemoryInfo(
                kernel32.GetCurrentProcess(),
                ctypes.byref(counters),
                counters.cb,
            ):
                return counters.PeakWorkingSetSize / (1024 * 1024)
        return 0.0
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux = KiB, macOS = bytes.
    return value / (1024 * 1024) if value > 10_000_000 else value / 1024


def run_repo_benchmark(repo: dict[str, Any], profile: str) -> dict[str, Any]:
    started = time.perf_counter()
    before_rss = _peak_rss_mb()
    result = run_production_scan(
        repo["url"],
        profile=profile,
        display_name=repo["name"],
        commit=repo.get("commit"),
    )
    elapsed = time.perf_counter() - started
    after_rss = _peak_rss_mb()

    return {
        "repo": repo,
        "profile": profile,
        "wall_seconds": elapsed,
        "peak_rss_mb": max(before_rss, after_rss),
        "result": result,
    }
