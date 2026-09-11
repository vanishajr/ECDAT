"""Benchmark report model + result analysis (Person 3 platform layer).

Transforms a completed Task 19 run result into a structured,
report-ready analysis — the canonical model future console/JSON/
CSV/HTML/PDF/chart renderers consume. Analysis only: no output
formats are built here.

Layering (never mixed):

    EXECUTION RESULT (Task 19 run_suite: timing, metadata, evaluation)
        -> ANALYSIS (this module: group/case summaries, rollups)
        -> PRESENTATION (future tasks render this model)

Mathematical rule: group (and overall) metrics come from SUMMED
confusion counts passed through the existing Task 16
`confusion_metrics()` — never mean-of-percentage averaging. TN is
summed only when every evaluated case in the scope defines it;
otherwise Task 16 unavailable semantics apply (None + reason, no
invented TN).

Status rule: "evaluated" vs "failed" describes CASE EXECUTION;
"unavailable" describes METRICS. An evaluated case with
accuracy=None (no universe) is NOT failed and never appears in
the failure list. A failed case contributes no TP/FP/TN/FN.

Honesty rule: only measured performance values appear (Task 19
elapsed/resources). No cache-speedup, throughput, superiority, or
baseline fields exist. `provider_type` accepts only "mock" or
"unknown" — "real" is rejected until a verified real provider
exists, so the model cannot imply real accuracy by construction.
"""

from __future__ import annotations

from ecdat.benchmark import output as output_mod
from ecdat.benchmark.metrics import confusion_metrics
from ecdat.benchmark.suite import GROUPS, get_case

REPORT_ID = "ecdat-benchmark-report"
REPORT_VERSION = "1"

_EVALUATED = "evaluated"
_FAILED = "failed"

# The only provider types this model can honestly describe today.
PROVIDER_TYPES = ("mock", "unknown")


def _sum_counts(counts_list: list[dict]) -> dict:
    """Micro-aggregate: sum TP/FP/FN; TN only when universally known."""
    tp = fp = fn = 0
    tn: int | None = 0
    for counts in counts_list:
        tp += counts["tp"]
        fp += counts["fp"]
        fn += counts["fn"]
        if tn is not None:
            tn = tn + counts["tn"] if counts["tn"] is not None else None
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def summarize_case(entry: dict) -> dict:
    """One report row for a run case entry. Pure, registry order kept."""
    if entry["status"] == _FAILED:
        return {
            "case_id": entry["case_id"],
            "group": entry["group"],
            "title": _title_of(entry["case_id"]),
            "status": _FAILED,
            "synthetic": entry["synthetic"],
            "predicted_n": None,
            "counts": None,
            "metrics": None,
            "unavailable": None,
            "error": entry["error"],
        }
    metrics = entry["metrics"]
    return {
        "case_id": entry["case_id"],
        "group": entry["group"],
        "title": _title_of(entry["case_id"]),
        "status": _EVALUATED,
        "synthetic": entry["synthetic"],
        "predicted_n": len(entry["predicted"]),
        "counts": dict(entry["counts"]),
        "metrics": dict(metrics),
        "unavailable": dict(metrics["unavailable"]),
        "error": None,
    }


def _title_of(case_id: str) -> str:
    registered = get_case(case_id)
    return registered.title if registered is not None else case_id


def summarize_group(group: str, entries: list[dict]) -> dict:
    """Micro-aggregate summary for one group's evaluated entries. Pure.

    Failed entries are counted in `failed` and excluded from the
    confusion sums. Metrics come from summed counts via the Task 16
    function — never averaged across cases.
    """
    evaluated = [e for e in entries if e["status"] == _EVALUATED]
    failed = [e["case_id"] for e in entries if e["status"] == _FAILED]
    totals = _sum_counts([e["counts"] for e in evaluated])
    metrics = confusion_metrics(totals["tp"], totals["fp"],
                                totals["tn"], totals["fn"])
    return {
        "group": group,
        "cases": len(entries),
        "evaluated": len(evaluated),
        "failed": len(failed),
        "failed_case_ids": failed,
        "counts": totals,
        "metrics": metrics,
        "unavailable": dict(metrics["unavailable"]),
    }


def build_report(run: dict, provider_type: str = "mock") -> dict:
    """Transform a Task 19 run result into the canonical report. Pure.

    No I/O, no SQLite, no network. Overall totals/metrics are reused
    from the run (single source of truth: Task 18); group summaries
    aggregate the same per-case data. Raises ValueError for any
    provider_type other than "mock"/"unknown".
    """
    if provider_type not in PROVIDER_TYPES:
        raise ValueError(
            f"provider_type must be one of {list(PROVIDER_TYPES)}; "
            f"got {provider_type!r} (no verified real provider exists)")
    rows = [summarize_case(e) for e in run["cases"]]
    present = [g for g in GROUPS
               if any(r["group"] == g for r in rows)]
    groups = [summarize_group(g, [e for e in run["cases"] if e["group"] == g])
              for g in present]
    failures = [{"case_id": r["case_id"], "group": r["group"],
                 "error": r["error"]} for r in rows
                if r["status"] == _FAILED]
    return {
        "report": REPORT_ID,
        "report_version": REPORT_VERSION,
        "run_id": run["run_id"],
        "suite_id": run["suite_id"],
        "suite_version": run["suite_version"],
        "provider": run["provider"],
        "provider_type": provider_type,
        "engine": run["engine"],
        "synthetic": run["synthetic"],
        "selection": dict(run["selection"]),
        "case_count": run["case_count"],
        "evaluated_n": run["evaluated_n"],
        "failed_n": run["failed_n"],
        "overall": {
            "counts": dict(run["totals"]),
            "metrics": dict(run["aggregate"]),
        },
        "groups": groups,
        "cases": rows,
        "unavailable": {
            "overall": dict(run["aggregate"]["unavailable"]),
            "by_group": {g["group"]: dict(g["unavailable"]) for g in groups
                         if g["unavailable"]},
        },
        "failures": failures,
        "performance": {
            "elapsed_s": run["elapsed_s"],
            "cpu_s": run["resources"]["cpu_s"],
            "peak_rss_bytes": run["resources"]["peak_rss_bytes"],
            "resources_note": run["resources"]["note"],
            "case_count": run["case_count"],
        },
        "metadata": dict(run.get("metadata", {})),
        "note": ("Report analysis over explicitly supplied predictions. "
                 "Group metrics aggregate summed confusion counts "
                 "(micro-average); unavailable metrics and failed cases "
                 "are preserved, never fabricated. Synthetic fixtures "
                 "only; no detector accuracy is claimed."),
    }


def to_json(report: dict) -> str:
    """Stable machine-readable JSON via the existing output contract."""
    return output_mod.to_json(report)
