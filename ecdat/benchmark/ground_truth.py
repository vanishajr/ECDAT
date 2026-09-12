"""Ground-truth model + prediction/label pairing (Person 3 platform layer).

Reusable foundation for real detection-accuracy benchmarking after
Person 1/Person 2 integration. Honest by construction:

- A `GroundTruth` carries ONLY caller-supplied expected finding keys
  plus an optional evaluable universe. It is NEVER derived from the
  predictions under test: deriving "truth" from ECDAT's own output
  would be circular and is forbidden here.
- Finding keys are opaque strings (see `finding_key()`); pairing is
  exact set membership. Duplicate predictions collapse (documented
  set semantics — this module does not measure duplicate
  suppression, it stays neutral to it).
- True negatives require an explicit universe. Without one, TN is
  UNKNOWN and every metric needing it reports unavailable (None +
  reason) instead of a fake zero — see `metrics.confusion_metrics`.
- `synthetic_cases()` builds deterministic LABELLED cases for
  exercising this machinery end to end. Every synthetic case is
  flagged `synthetic=True` and must never be presented as
  production accuracy.

Future real inputs plug in without redesign: Person 1/Person 2
outputs and baseline-tool outputs all become `predicted` sets
against independently labelled `GroundTruth` sets.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from ecdat.benchmark import metrics as metrics_mod


def finding_key(rule_id: str, file: str, line: int) -> str:
    """Standard finding key: 'RULE@file:line'. Opaque to the pairing."""
    return f"{rule_id}@{file}:{int(line)}"


@dataclass(frozen=True)
class GroundTruth:
    """Independent expected results for one benchmark case.

    `expected`: keys that should be reported. `universe`: every key
    that was evaluable (None when the negative space is undefined —
    then TN is unknown). `synthetic` marks deterministic stand-ins
    for real labels.
    """

    expected: frozenset = field(default_factory=frozenset)
    universe: frozenset | None = None
    synthetic: bool = False
    note: str = ""


@dataclass(frozen=True)
class BenchmarkCase:
    """One evaluable unit: independent truth + one prediction set."""

    case_id: str
    group: str
    ground_truth: GroundTruth
    predicted: frozenset = field(default_factory=frozenset)


def pair(case: BenchmarkCase) -> dict:
    """Pair one case's predictions against its ground truth. Pure.

    Returns {"tp", "fp", "fn", "tn" (int or None when the universe
    is undefined), "predicted_n", "expected_n"}. Set semantics:
    repeated predictions of the same key count once.
    """
    expected = set(case.ground_truth.expected)
    predicted = set(case.predicted)
    tp = len(predicted & expected)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    tn = None
    if case.ground_truth.universe is not None:
        universe = set(case.ground_truth.universe)
        tn = len(universe - expected - predicted)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "predicted_n": len(predicted),
        "expected_n": len(expected),
    }


def evaluate_cases(cases: list[BenchmarkCase]) -> dict:
    """Evaluate cases individually plus a micro-average aggregate. Pure.

    The aggregate sums TP/FP/FN over all cases; TN sums only when
    EVERY case defines a universe, else TN is unknown (None) and
    TN-dependent aggregate metrics report unavailable. Deterministic
    case order is preserved.
    """
    per_case = []
    tp = fp = fn = 0
    tn: int | None = 0
    for case in cases:
        counts = pair(case)
        tp += counts["tp"]
        fp += counts["fp"]
        fn += counts["fn"]
        if tn is not None:
            tn = tn + counts["tn"] if counts["tn"] is not None else None
        per_case.append({
            "case_id": case.case_id,
            "group": case.group,
            "counts": counts,
            "metrics": metrics_mod.confusion_metrics(
                counts["tp"], counts["fp"], counts["tn"], counts["fn"]),
            "synthetic": case.ground_truth.synthetic,
        })
    totals = {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
    return {
        "case_count": len(cases),
        "cases": per_case,
        "totals": totals,
        "aggregate": metrics_mod.confusion_metrics(tp, fp, tn, fn),
        "synthetic": all(c.ground_truth.synthetic for c in cases),
    }


_SYNTH_GROUPS = ("source", "binary", "container")


def synthetic_cases(seed: int = 7, per_group: int = 2) -> list[BenchmarkCase]:
    """Deterministic synthetic labelled cases. NOT production accuracy.

    Seeded generator producing small labelled cases with a realistic
    mix of hits, misses, and false alarms so the pairing + metric
    machinery can run end to end today. Every case is flagged
    synthetic with an explanatory note.
    """
    rng = random.Random(seed)
    rules = ["RSA-1024", "MD5-USAGE", "AES-ECB", "TLS-1.0", "DES-USAGE"]
    cases: list[BenchmarkCase] = []
    for group in _SYNTH_GROUPS:
        for i in range(per_group):
            pool = [
                finding_key(r, f"samples/synth/{group}/mod{j}.py",
                            10 * (j + 1))
                for j, r in enumerate(rules)
            ]
            expected = frozenset(k for k in pool if rng.random() < 0.6)
            predicted = frozenset(k for k in pool if rng.random() < 0.6)
            cases.append(BenchmarkCase(
                case_id=f"synth-{group}-{i:02d}",
                group=group,
                ground_truth=GroundTruth(
                    expected=expected,
                    universe=frozenset(pool),
                    synthetic=True,
                    note=("Deterministic synthetic labels for exercising "
                          "the accuracy machinery; not production accuracy."),
                ),
                predicted=predicted,
            ))
    return cases
