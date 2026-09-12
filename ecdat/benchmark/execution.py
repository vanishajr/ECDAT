"""Reproducible benchmark execution engine (Person 3 platform layer).

Orchestration only — no detection, no metrics of its own:

    BENCHMARK DEFINITION (Task 17 registry: SuiteCase, no predictions)
        -> BENCHMARK EXECUTION (this module: selection, timing, metadata)
        -> PREDICTION (Task 18 PredictionProvider)
        -> EVALUATION (Task 18 evaluate_selection -> Task 16 machinery)
        -> REPORTING (stable JSON via output.to_json; future tables/PDF)

Reproducibility contract: `run_suite()` returns run metadata
(run_id, timestamps, measured timing — naturally variable per run)
alongside logical content. `logical_result()` strips the variable
fields, so the same suite + provider configuration + selection
always yields byte-identical logical results. Per-case timing is
deliberately NOT measured: it would require duplicating the Task 18
evaluation loop; total wall time plus process resources are
measured honestly instead. No cache-speedup or superiority claims.
"""

from __future__ import annotations

import platform
import sys
import uuid
from datetime import datetime, timezone
from typing import Iterable

from ecdat.benchmark import output as output_mod
from ecdat.benchmark import resources as resources_mod
from ecdat.benchmark.predictions import PredictionProvider, evaluate_selection

ENGINE_ID = "ecdat-benchmark-execution"
ENGINE_VERSION = "1"

# Run-metadata keys excluded from the reproducible logical result.
_VOLATILE_KEYS = ("run_id", "started_at", "elapsed_s", "resources")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_suite(provider: PredictionProvider,
              *,
              group: str | None = None,
              case_ids: Iterable[str] | None = None,
              metadata: dict | None = None) -> dict:
    """Execute a registered suite selection against a provider.

    Selection reuses the Task 17 registry via Task 18
    `evaluate_selection` (unknown group/case id -> ValueError,
    empty selection -> valid empty result). Evaluation is NOT
    reimplemented here. Returns the full run result: logical
    evaluation plus measured timing, resources, and metadata.
    """
    requested_ids = list(case_ids) if case_ids is not None else None
    cpu_start = resources_mod.cpu_times()
    wall_start = resources_mod.now_wall()
    started_at = _utcnow()
    # Single evaluation call: selection + prediction + Task 16 metrics.
    evaluation = evaluate_selection(provider, group=group,
                                    case_ids=requested_ids)
    elapsed_s = resources_mod.now_wall() - wall_start
    return {
        "run_id": f"suite-run-{uuid.uuid4().hex[:8]}",
        "engine": ENGINE_ID,
        "engine_version": ENGINE_VERSION,
        "started_at": started_at,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "suite_id": evaluation["suite_id"],
        "suite_version": evaluation["version"],
        "provider": evaluation["provider"],
        "selection": {
            "group": group,
            "case_ids": requested_ids,
            "resolved": [c["case_id"] for c in evaluation["cases"]],
        },
        "case_count": evaluation["case_count"],
        "evaluated_n": evaluation["evaluated_n"],
        "failed_n": evaluation["failed_n"],
        "elapsed_s": elapsed_s,
        "resources": resources_mod.collect(cpu_start, wall_start),
        "totals": evaluation["totals"],
        "aggregate": evaluation["aggregate"],
        "cases": evaluation["cases"],
        "synthetic": evaluation["synthetic"],
        "metadata": dict(metadata or {}),
        "note": ("Execution over explicitly supplied predictions. "
                 "Timing/resources measured on this machine for this run; "
                 "logical content (see logical_result) is reproducible. "
                 + evaluation["note"]),
    }


def logical_result(run: dict) -> dict:
    """The reproducible subset of a run result. Pure.

    Drops run_id/timestamps/measured timing so identical
    suite + provider + selection compare byte-equal. Never
    presented without the synthetic/mock labels it retains.
    """
    return {k: v for k, v in run.items() if k not in _VOLATILE_KEYS}


def to_console(run: dict) -> str:
    """Human-readable one-line-per-fact summary. No trailing newline."""
    sel = run["selection"]
    scope = f"group={sel['group']}" if sel["group"] else (
        f"cases={len(sel['resolved'])}" if sel["case_ids"] is not None
        else "full suite")
    agg = run["aggregate"]
    lines = [
        f"suite-run: {run['suite_id']} v{run['suite_version']} "
        f"(provider: {run['provider']}, {scope})",
        f"cases:     {run['case_count']} total, "
        f"{run['evaluated_n']} evaluated, {run['failed_n']} failed",
        f"counts:    TP={run['totals']['tp']} FP={run['totals']['fp']} "
        f"FN={run['totals']['fn']} "
        f"TN={run['totals']['tn'] if run['totals']['tn'] is not None else 'n/a'}",
        f"elapsed:   {run['elapsed_s']:.3f}s wall",
        f"synthetic: {str(run['synthetic']).lower()} — fixtures only; "
        f"no detector accuracy claimed.",
    ]
    if agg["precision"] is None and agg["recall"] is None:
        lines.append("metrics:   unavailable — " + "; ".join(
            sorted(set(agg["unavailable"].values())))[:160])
    else:
        lines.append(
            "metrics:   precision="
            f"{agg['precision'] if agg['precision'] is not None else 'n/a'} "
            f"recall={agg['recall'] if agg['recall'] is not None else 'n/a'} "
            f"F1={agg['f1'] if agg['f1'] is not None else 'n/a'}")
    return "\n".join(lines)


def to_json(run: dict) -> str:
    """Stable machine-readable JSON via the existing output contract."""
    return output_mod.to_json(run)
