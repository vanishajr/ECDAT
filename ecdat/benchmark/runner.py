"""Benchmark runner (Person 3 platform layer).

Runs every doc of a dataset through a `BenchmarkTarget`, timing each
with wall-clock and recording ok/error/output_bytes. Failures are
captured per doc (the run continues) — a failing target never aborts
the benchmark. The runner depends only on the target interface, so
real CoreClient / discovery / baseline targets slot in later.

Each run uses a fresh temporary SQLite DB unless the caller passes an
explicit `db_path` (combined with idempotent target inserts, repeated
runs never corrupt the database).
"""

from __future__ import annotations

import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ecdat.benchmark import datasets as datasets_mod
from ecdat.benchmark import metrics, resources
from ecdat.benchmark.targets import BenchmarkTarget, MockPipelineTarget, RunContext

RESULT_VERSION = "1"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_benchmark(
    dataset: str | dict,
    target: BenchmarkTarget | None = None,
    db_path: str | Path | None = None,
) -> dict:
    """Run a dataset through a target. Returns a JSON-serializable result."""
    ds = datasets_mod.build_dataset(dataset) if isinstance(dataset, str) else dataset
    active = target if target is not None else MockPipelineTarget()
    run_id = f"bench-run-{uuid.uuid4().hex[:8]}"
    tmpdir = None
    if db_path is None:
        tmpdir = tempfile.TemporaryDirectory(prefix="ecdat-bench-")
        db_file = Path(tmpdir.name) / "bench.db"
    else:
        db_file = Path(db_path).expanduser()
    ctx = RunContext(db_path=db_file, run_id=run_id)
    cpu_start = resources.cpu_times()
    wall_start = resources.now_wall()
    runs: list[dict] = []
    findings_total = 0
    output_total = 0
    for doc in ds["docs"]:
        findings_total += len(doc["findings"])
        t0 = resources.now_wall()
        try:
            res = active.run(doc, ctx)
            entry = {
                "scan_id": doc["scan_id"],
                "findings": len(doc["findings"]),
                "elapsed_s": resources.now_wall() - t0,
                "ok": bool(res.ok),
                "error": None,
                "output_bytes": int(res.output_bytes),
            }
        except Exception as exc:  # noqa: BLE001 - recorded, run continues
            entry = {
                "scan_id": doc["scan_id"],
                "findings": len(doc["findings"]),
                "elapsed_s": resources.now_wall() - t0,
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "output_bytes": 0,
            }
        output_total += entry["output_bytes"]
        runs.append(entry)
    elapsed_s = resources.now_wall() - wall_start
    result = {
        "result_version": RESULT_VERSION,
        "benchmark": "mock-pipeline",
        "target": active.name,
        "run_id": run_id,
        "started_at": _utcnow(),
        "dataset": {
            "name": ds["name"],
            "seed": ds["seed"],
            "docs": len(ds["docs"]),
            "findings": findings_total,
        },
        "elapsed_s": elapsed_s,
        "latency": metrics.summarize([r["elapsed_s"] for r in runs]),
        "success": metrics.success_rate(runs),
        "throughput": metrics.throughput(findings_total, elapsed_s),
        "output_bytes": output_total,
        "resources": resources.collect(cpu_start, wall_start),
        "accuracy": metrics.accuracy_status(),
        "runs": runs,
        "notes": [
            "Mock engineering/performance measurement only; not detection accuracy.",
            "Real accuracy benchmarking connects after Person 1/Person 2 integration.",
        ],
    }
    if tmpdir is not None:
        tmpdir.cleanup()
    return result
