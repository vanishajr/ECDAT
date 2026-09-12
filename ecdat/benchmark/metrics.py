"""Pure metric helpers (Person 3 platform layer).

All functions are pure: numbers in, numbers out. No I/O, no timing.

Latency/throughput/success metrics are engineering measurements of
the mock pipeline. Confusion-matrix metrics (`confusion_metrics`)
are pure standard-definition formulas over caller-supplied
TP/FP/TN/FN counts (see `ecdat.benchmark.ground_truth` for the
pairing that produces such counts from independent labels).
Unavailable metrics are explicit None + reason, never fake zeros:
a metric with a zero denominator, or one needing true negatives
when no evaluable universe was supplied, reports unavailable.

`accuracy_status()` remains the gate for the engineering workload
datasets, which carry no ground-truth labels: it still reports
"unavailable" (and still raises when ground truth IS supplied
without a validated pairing — that pairing now exists for
explicitly labelled cases via `ground_truth.pair`).
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


def confusion_metrics(tp: int, fp: int, tn: int | None, fn: int) -> dict:
    """Standard confusion-matrix metrics over explicit counts. Pure.

    Definitions: precision = TP/(TP+FP), recall = TP/(TP+FN),
    F1 = 2PR/(P+R), accuracy = (TP+TN)/total,
    FPR = FP/(FP+TN), FNR = FN/(FN+TP), specificity = TN/(TN+FP).

    Honesty rules: negative counts raise ValueError; any metric
    whose denominator is zero — or that needs TN when `tn` is None
    (no evaluable universe supplied) — returns None with its reason
    recorded in "unavailable", never a fabricated zero.
    """
    for name, value in (("tp", tp), ("fp", fp), ("fn", fn)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{name} must be a non-negative int, got {value!r}")
    if tn is not None and (not isinstance(tn, int) or isinstance(tn, bool) or tn < 0):
        raise ValueError(f"tn must be a non-negative int or None, got {tn!r}")

    unavailable: dict[str, str] = {}

    def _ratio(num: int, denom: int) -> float | None:
        return (num / denom) if denom > 0 else None

    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)

    f1: float | None = None
    if precision is not None and recall is not None:
        if precision + recall > 0:
            f1 = 2 * precision * recall / (precision + recall)
        else:
            unavailable["f1"] = "precision and recall are both zero"

    accuracy: float | None = None
    fpr: float | None = None
    specificity: float | None = None
    if tn is None:
        for metric in ("accuracy", "fpr", "specificity"):
            unavailable[metric] = "true negatives unknown: no evaluable universe"
    else:
        total = tp + tn + fp + fn
        accuracy = (tp + tn) / total if total > 0 else None
        if accuracy is None:
            unavailable["accuracy"] = "no evaluable findings"
        fpr = fp / (fp + tn) if (fp + tn) > 0 else None
        if fpr is None:
            unavailable["fpr"] = "no predicted positives or true negatives"
        specificity = tn / (tn + fp) if (tn + fp) > 0 else None
        if specificity is None:
            unavailable["specificity"] = "no predicted positives or true negatives"

    fnr = fn / (fn + tp) if (fn + tp) > 0 else None
    if fnr is None:
        unavailable["fnr"] = "no expected positives"

    if precision is None and "precision" not in unavailable:
        unavailable["precision"] = "no predicted positives"
    if recall is None and "recall" not in unavailable:
        unavailable["recall"] = "no expected positives"
    if f1 is None and "f1" not in unavailable:
        unavailable["f1"] = "precision or recall unavailable"

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "fpr": fpr,
        "fnr": fnr,
        "specificity": specificity,
        "unavailable": unavailable,
    }
