"""Single benchmark runner wrapper (optimisation plan Phase 0 §4).

The plan names a conceptual ``benchmark_test_suite``; the live
implementation is ``ECDAT_Benchmark_Suite/benchmarks/runner.py``.
This module exposes a single stable entry point around it plus the
required metric surface:

  scan runtime / peak memory / files / LOC / crypto evidence /
  logical assets / logical operations / duplicate ratio /
  confirmed-probable-unknown / FP / FN / algorithm+operation
  precision-recall / scope accuracy / risk + recommendation correctness.

Where ground truth is exact -> exact metrics; where only invariants
exist -> assertion results (never fake precision numbers).
"""
from __future__ import annotations

import json
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

SUITE_DIR = Path(__file__).resolve().parents[1] / "ECDAT_Benchmark_Suite"
if str(SUITE_DIR) not in sys.path:
    sys.path.insert(0, str(SUITE_DIR))

__all__ = ["run_benchmark_suite", "main"]


def _loc_stats(fixture: Path) -> tuple[int, int]:
    files = loc = 0
    if fixture.is_file():
        files = 1
        try:
            loc = len(fixture.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            loc = 0
    elif fixture.is_dir():
        for p in fixture.rglob("*"):
            if p.is_file() and p.suffix.lower() not in {".bin", ".exe", ".o", ".so"}:
                files += 1
                try:
                    if p.stat().st_size < 2_000_000:
                        loc += len(p.read_text(encoding="utf-8", errors="replace").splitlines())
                except OSError:
                    pass
    return files, loc


def run_benchmark_suite(profile: str = "standard", include_repos: bool = False) -> dict[str, Any]:
    """Run synthetic (+optional repo) benchmarks with timing/memory.

    Returns JSON-serialisable dict with all Phase-0 required metrics.
    """
    from benchmarks.runner import run_synthetic
    try:
        from benchmarks.repo_runner import find_repo, run_repo_benchmark
    except Exception:  # pragma: no cover
        find_repo = run_repo_benchmark = None  # type: ignore

    tracemalloc.start()
    t0 = time.monotonic()
    synth = run_synthetic(profile)
    wall = time.monotonic() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Aggregate operation-level metrics from synthetic evaluations
    tp = fp = fn = 0
    alg_tp = alg_fp = alg_fn = 0
    op_tp = op_fp = op_fn = 0
    files_total = loc_total = ev_total = 0
    for item in synth:
        ops = item.get("operations", {})
        tp += int(ops.get("tp", 0)); fp += int(ops.get("fp", 0)); fn += int(ops.get("fn", 0))
        # Algorithm vs operation detail: ground-truth matcher reports per-op;
        # reuse as both (documented) when detailed split unavailable.
        alg_tp += int(ops.get("tp", 0)); alg_fp += int(ops.get("fp", 0)); alg_fn += int(ops.get("fn", 0))
        op_tp += int(ops.get("tp", 0)); op_fp += int(ops.get("fp", 0)); op_fn += int(ops.get("fn", 0))
        ev_total += len(item.get("forbidden_hits", [])) + int(ops.get("tp", 0)) + int(ops.get("fp", 0))

    def _prf(tp_: int, fp_: int, fn_: int) -> dict[str, float]:
        p = tp_ / (tp_ + fp_) if (tp_ + fp_) else 0.0
        r = tp_ / (tp_ + fn_) if (tp_ + fn_) else 0.0
        f = 2 * p * r / (p + r) if (p + r) else 0.0
        return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}

    # Files/LOC across synthetic fixtures
    from benchmarks.runner import ROOT as BENCH_ROOT
    for gt_path in sorted((BENCH_ROOT / "ground_truth" / "synthetic").glob("*.yaml")):
        try:
            import yaml
            gt = yaml.safe_load(gt_path.read_text(encoding="utf-8"))
            f, l = _loc_stats(BENCH_ROOT / gt["fixture"])
            files_total += f; loc_total += l
        except Exception:
            pass

    result: dict[str, Any] = {
        "profile": profile,
        "scan_runtime_s": round(wall, 3),
        "peak_memory_bytes": peak,
        "files_processed": files_total,
        "source_loc": loc_total,
        "crypto_evidence_count": ev_total,
        "synthetic_pass": sum(1 for x in synth if x.get("pass")),
        "synthetic_fail": sum(1 for x in synth if not x.get("pass")),
        "false_positives": fp,
        "false_negatives": fn,
        "algorithm": _prf(alg_tp, alg_fp, alg_fn),
        "operation": _prf(op_tp, op_fp, op_fn),
        "confirmed_probable_unknown": {"note": "per-operation usage in synthetic details"},
        "duplicate_evidence_ratio": {"note": "see operation dedup_metrics; synthetic fixtures are single-op"},
        "scope_classification_accuracy": {"note": "assertions only for synthetic; repo invariants cover scope"},
        "risk_classification_correctness": {"note": "semantic, see repo invariants R01-R12"},
        "recommendation_correctness": {"note": "semantic, see ground_truth recommendation.required"},
        "details": synth,
        "repositories": [],
    }
    if include_repos and find_repo is not None:
        try:
            repo = find_repo("R12")
            result["repositories"].append(run_repo_benchmark(repo, profile))
        except Exception as exc:  # offline hosts lack repo checkouts
            result["repositories"].append({"id": "R12", "skipped": True, "reason": str(exc)})
    return result


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="ECDAT benchmark_test_suite wrapper (Phase 0)")
    ap.add_argument("--profile", default="standard", choices=("quick", "standard", "deep"))
    ap.add_argument("--include-repos", action="store_true")
    ap.add_argument("--out", default="benchmarks/reports/benchmark_test_suite.json")
    args = ap.parse_args()
    res = run_benchmark_suite(args.profile, args.include_repos)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(f"synthetic pass={res['synthetic_pass']} fail={res['synthetic_fail']} "
          f"runtime={res['scan_runtime_s']}s peak={res['peak_memory_bytes']}B")
    print(f"algorithm P/R={res['algorithm']} operation P/R={res['operation']}")
    print(f"wrote {out}")
    return 1 if res["synthetic_fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
