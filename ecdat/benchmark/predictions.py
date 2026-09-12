"""Prediction provider interface + evaluation adapter (Person 3 platform layer).

The missing link between registered cases (Task 17) and metric
evaluation (Task 16), kept as four strictly separate concepts:

    Benchmark Case  (Task 17 SuiteCase: definition, NEVER predictions)
    Ground Truth    (Task 16 GroundTruth: independent expected keys)
    Prediction Provider (this module: future detectors/baselines plug in)
    Evaluation      (Task 16 pair()/evaluate_cases()/confusion_metrics())

Nothing here detects anything. A provider returns explicitly
produced prediction sets; the adapter pairs them against
independent truth via the existing `with_predictions()` bridge.
Provider failures are captured explicitly — a failed case never
contributes TP/FP/FN/TN and never silently becomes correct.

Deliberately NOT integrated with `BenchmarkTarget`/`runner.py`:
targets consume whole canonical docs while predictions are
per-case key sets; forcing one through the other would be
invasive. The Task 12 runner is untouched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Protocol, runtime_checkable

from ecdat.benchmark.ground_truth import BenchmarkCase, evaluate_cases
from ecdat.benchmark.suite import (
    SUITE_ID,
    SUITE_VERSION,
    SuiteCase,
    get_case,
    list_cases,
    with_predictions,
)


@dataclass(frozen=True)
class Prediction:
    """One provider answer for one case. JSON-serializable via asdict()."""

    keys: frozenset = field(default_factory=frozenset)
    ok: bool = True
    error: str | None = None
    detail: dict = field(default_factory=dict)


@runtime_checkable
class PredictionProvider(Protocol):
    """Interface every prediction source implements.

    Future real detectors (Person 1/Person 2) and baseline tools
    implement this: given a registered case, return the finding keys
    they predict. Keys reuse the Task 16 identity semantics
    (`finding_key`: 'RULE@file:line'); no second key system exists.
    """

    name: str

    def predict(self, case: SuiteCase) -> Prediction:
        """Return this provider's prediction set for one case."""
        ...


class MockPredictionProvider:
    """Deterministic test-only provider. Explicit configuration only.

    `predictions` maps case_id -> the exact keys to return.
    `errors` maps case_id -> an error message producing an
    unsuccessful Prediction. Cases absent from BOTH get an empty
    prediction set — the mock NEVER copies ground truth, so
    evaluation independence is provable.
    """

    name = "mock-predictions"

    def __init__(self, predictions: Mapping[str, Iterable[str]] | None = None,
                 errors: Mapping[str, str] | None = None) -> None:
        self._predictions = {k: frozenset(v)
                             for k, v in (predictions or {}).items()}
        self._errors = dict(errors or {})

    def predict(self, case: SuiteCase) -> Prediction:
        if case.case_id in self._errors:
            return Prediction(keys=frozenset(), ok=False,
                              error=self._errors[case.case_id])
        return Prediction(keys=self._predictions.get(case.case_id, frozenset()))


def _failed_entry(case: SuiteCase, error: str) -> dict:
    return {
        "case_id": case.case_id,
        "group": case.group,
        "status": "failed",
        "predicted": None,
        "error": error,
        "counts": None,
        "metrics": None,
        "synthetic": case.ground_truth.synthetic,
    }


def evaluate_suite(cases: Iterable[SuiteCase],
                   provider: PredictionProvider) -> dict:
    """Evaluate cases with a provider. Pure (provider calls excepted).

    For each case in registry order: obtain predictions, bridge via
    Task 17 `with_predictions()`, evaluate via Task 16
    `evaluate_cases()` (reused verbatim for every successful case).
    Provider exceptions and unsuccessful Predictions become explicit
    "failed" entries excluded from totals/aggregate — no fabricated
    counts. Fully deterministic; result is JSON-serializable.
    """
    cases = list(cases)
    evaluated: list[BenchmarkCase] = []
    failed: dict[str, dict] = {}
    for case in cases:
        try:
            prediction = provider.predict(case)
        except Exception as exc:  # noqa: BLE001 - recorded, run continues
            failed[case.case_id] = _failed_entry(
                case, f"{type(exc).__name__}: {exc}")
            continue
        if not prediction.ok:
            failed[case.case_id] = _failed_entry(
                case, prediction.error or "provider reported failure")
            continue
        evaluated.append(with_predictions(case, prediction.keys))

    # Task 16 machinery, reused — not reimplemented.
    accuracy = evaluate_cases(evaluated)
    by_id = {c["case_id"]: c for c in accuracy["cases"]}

    ordered: list[dict] = []
    for case in cases:
        if case.case_id in failed:
            ordered.append(failed[case.case_id])
            continue
        entry = by_id[case.case_id]
        ordered.append({
            "case_id": entry["case_id"],
            "group": entry["group"],
            "status": "evaluated",
            "predicted": sorted(_predicted_of(case, evaluated)),
            "error": None,
            "counts": entry["counts"],
            "metrics": entry["metrics"],
            "synthetic": entry["synthetic"],
        })
    return {
        "suite_id": SUITE_ID,
        "version": SUITE_VERSION,
        "provider": provider.name,
        "case_count": len(cases),
        "evaluated_n": len(evaluated),
        "failed_n": len(failed),
        "cases": ordered,
        "totals": accuracy["totals"],
        "aggregate": accuracy["aggregate"],
        "synthetic": all(c.ground_truth.synthetic for c in cases),
        "note": ("Adapter evaluation over explicitly supplied predictions. "
                 "Failed cases contribute no counts. Synthetic fixtures only; "
                 "no detector accuracy is claimed."),
    }


def _predicted_of(case: SuiteCase, evaluated: list[BenchmarkCase]) -> frozenset:
    for candidate in evaluated:
        if candidate.case_id == case.case_id:
            return candidate.predicted
    return frozenset()


def evaluate_selection(provider: PredictionProvider,
                       group: str | None = None,
                       case_ids: Iterable[str] | None = None) -> dict:
    """Evaluate the full suite, one group, or an explicit id subset. Pure.

    Filtering reuses the Task 17 registry (no duplicated logic).
    `case_ids` preserves the given order with duplicates removed;
    unknown ids raise ValueError (fail fast, deterministic).
    """
    if case_ids is not None:
        seen: list[str] = []
        for cid in case_ids:
            if cid not in seen:
                seen.append(cid)
        cases: list[SuiteCase] = []
        for cid in seen:
            case = get_case(cid)
            if case is None:
                raise ValueError(f"unknown benchmark case id: {cid!r}")
            cases.append(case)
        return evaluate_suite(cases, provider)
    return evaluate_suite(list_cases(group), provider)
