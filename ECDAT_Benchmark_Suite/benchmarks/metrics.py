from __future__ import annotations
from dataclasses import dataclass
from typing import Any


def safe_div(n: float, d: float) -> float:
    return n / d if d else 0.0


def precision(tp: int, fp: int) -> float:
    return safe_div(tp, tp + fp)


def recall(tp: int, fn: int) -> float:
    return safe_div(tp, tp + fn)


def f1(p: float, r: float) -> float:
    return safe_div(2 * p * r, p + r)


def normalize_text(v: Any) -> str:
    return str(v or "").strip().lower().replace("_", "-")


def operation_key(op: dict[str, Any]) -> tuple:
    return (
        normalize_text(op.get("algorithm") or op.get("canonical")),
        normalize_text(op.get("mode")),
        str(op.get("key_size") or ""),
        normalize_text(op.get("operation") or op.get("purpose")),
        normalize_text(op.get("usage") or op.get("usage_state")),
    )


def match_operation(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    aliases = {
        "algorithm": ("algorithm", "canonical"),
        "mode": ("mode",),
        "key_size": ("key_size", "keySize"),
        "operation": ("operation", "purpose"),
        "usage": ("usage", "usage_state", "usageState"),
    }
    for field, names in aliases.items():
        if field not in expected:
            continue
        ev = expected[field]
        av = None
        for name in names:
            if name in actual and actual[name] not in (None, ""):
                av = actual[name]
                break
        if field == "key_size":
            if str(ev) != str(av):
                return False
        elif normalize_text(ev) != normalize_text(av):
            return False
    return True


def score_operations(expected: list[dict], actual: list[dict]) -> dict[str, Any]:
    unused = list(range(len(actual)))
    tp = 0
    missed = []
    for exp in expected:
        found = None
        for idx in unused:
            if match_operation(exp, actual[idx]):
                found = idx
                break
        if found is None:
            missed.append(exp)
        else:
            unused.remove(found)
            tp += 1
    fp = len(unused)
    fn = len(missed)
    p = precision(tp, fp)
    r = recall(tp, fn)
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": p, "recall": r, "f1": f1(p, r),
        "missed": missed,
        "unexpected": [actual[i] for i in unused],
    }
