"""Summarize suite latest.json -> aggregate op P/R/F1 + FP/FN totals."""
import json
import sys
from pathlib import Path

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
    "D:/Coding/Websites/ECDAT/ECDAT_Benchmark_Suite/benchmarks/reports/latest.json")
d = json.loads(path.read_text(encoding="utf-8"))
tp = fp = fn = 0
fails = []
for prof, items in (d.get("synthetic") or {}).items():
    for it in items:
        ops = it.get("operations", {}) or {}
        tp += int(ops.get("tp", 0) or 0)
        fp += int(ops.get("fp", 0) or 0)
        fn += int(ops.get("fn", 0) or 0)
        if not it.get("pass"):
            fails.append(f"{prof}/{it.get('id')}")
prec = tp / (tp + fp) if (tp + fp) else 0.0
rec = tp / (tp + fn) if (tp + fn) else 0.0
f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
print(f"suite ops: TP={tp} FP={fp} FN={fn} P={prec:.4f} R={rec:.4f} F1={f1:.4f}")
print(f"pass={d.get('summary', {}).get('synthetic_pass')} "
      f"fail={d.get('summary', {}).get('synthetic_fail')} fails={fails}")
