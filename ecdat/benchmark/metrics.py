"""Pure metric helpers (Person 3 platform layer).

All functions are pure: numbers in, numbers out. No I/O, no timing.

Latency/throughput/success metrics are engineering measurements of
the mock pipeline. Accuracy metrics (precision/recall/F1/accuracy/
FPR/FNR) are NOT computed here: current datasets carry no
ground-truth labels, so `accuracy_status()` reports "unavailable".
Passing ground truth today raises NotImplementedError — the pairing
design belongs to post Person 1/Person 2 integration, and inventing
accuracy numbers for the mock system is forbidden.
"""

from __future__ import annotations


def summarize(values: list[float]) -> dict:
    """Count/total/mean/min/max over elapsed seconds. Empty -> zeros."""
    if not values:
        return {"count": 0, "total_s": 0.0, "mean_s": 0.0, "min_s": 0.0, "max_s": 0.0}
    total = sum(values)
    return {
        "count": len(values),
        "total_s": total,
        "mean_s": total / len(values),
        "min_s": min(values),
        "max_s": max(values),
    }


def success_rate(results: list[dict]) -> dict:
    """Succeeded/total over per-doc run dicts with an 'ok' key."""
    total = len(results)
    ok = sum(1 for r in results if r.get("ok"))
    return {"ok": ok, "total": total, "rate": (ok / total) if total else 0.0}


def throughput(findings: int, elapsed_s: float) -> dict:
    """Findings/sec and docs-independent rate. Zero elapsed -> rate 0."""
    return {
        "findings": findings,
        "elapsed_s": elapsed_s,
        "findings_per_s": (findings / elapsed_s) if elapsed_s > 0 else 0.0,
    }


def accuracy_status(ground_truth=None) -> dict:
    """Accuracy-metric availability gate.

    Returns {"status": "unavailable", "reason": ...} when datasets
    carry no ground truth (the case today). Raises NotImplementedError
    if ground truth IS supplied, because no validated
    prediction<->label pairing exists yet — that design arrives with
    Person 1/Person 2 integration and real accuracy datasets.
    """
    if ground_truth is None:
        return {
            "status": "unavailable",
            "reason": (
                "Benchmark datasets carry no ground-truth labels; "
                "precision/recall/F1/accuracy/FPR/FNR cannot be "
                "computed. Mock measurements are engineering "
                "(performance) measurements only."
            ),
        }
    raise NotImplementedError(
        "Accuracy metrics require a validated ground-truth pairing "
        "design (post Person 1/Person 2 integration)."
    )
