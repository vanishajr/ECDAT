"""Expose the checked-in benchmark suite at the repository root.

The benchmark runner is intentionally kept in ``ECDAT_Benchmark_Suite`` while
the documented command imports a top-level ``benchmarks`` package. Extending
the package search path preserves that command without duplicating benchmark
implementation or changing scanner behavior.
"""

from pathlib import Path

_suite_path = Path(__file__).resolve().parent.parent / "ECDAT_Benchmark_Suite" / "benchmarks"
if _suite_path.is_dir():
    __path__.append(str(_suite_path))
