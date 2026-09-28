"""Score ECDAT slice outputs against EVAL-*.yaml ground truth.

Matching: same basename + |line diff| <= 25 (tier=file*: file only).
Canonicals normalized (upper, size-tokens stripped). tier strict/file-strict
require normalized equality; dyn/file accept any canonical (detection only);
config never matches (coverage items -> clean FN). Many-to-one: one finding
may cover several GT items (grouped ops). Unmatched findings are FP.
Writes repo_eval/REPORT.json and prints per-repo + aggregate P/R/F1.
"""
import json
import re
import sys
from pathlib import Path

BASE = Path("D:/Coding/Websites/ECDAT/ECDAT_Benchmark_Suite/benchmarks/repo_eval")
# ±15: same-statement grouping (init/update/final clusters) matches, while
# distinct same-function operations ~20+ lines apart (dgst.c:373 sha256 vs
# 395 verify-init) correctly do not.
WINDOW = 15
SIZE_TOKENS = ("-4096", "-3072", "-2048", "-1024", "-512", "-256", "-192", "-128")


def norm(canonical):
    text = str(canonical or "").upper()
    for tok in SIZE_TOKENS:
        text = text.replace(tok, "")
    return re.sub(r"[^A-Z0-9]", "", text)


def load_yaml_items(path):
    items, in_items = [], False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("items:"):
            in_items = True
            continue
        if not in_items or not line.strip().startswith("- {"):
            continue
        body = line.strip()[3:].rstrip("}")
        item = {}
        for part in re.split(r",(?![^(]*\))", body):
            key, _, val = part.partition(":")
            item[key.strip()] = val.strip().strip('"')
        line_no = item.get("line")
        item["line"] = None if line_no in (None, "", "null") else int(line_no)
        items.append(item)
    return items


def main():
    try:
        import yaml  # type: ignore
        have_yaml = True
    except ImportError:
        have_yaml = False
    _ = have_yaml
    report = {"window": WINDOW, "repos": {}, "aggregate": {}}
    agg_tp = agg_fp = agg_fn = 0
    for gt_path in sorted((BASE / "ground_truth").glob("EVAL-*.yaml")):
        repo = gt_path.stem.split("-", 1)[1]
        items = load_yaml_items(gt_path)
        doc = json.loads((BASE / "outputs" / f"{repo}.canonical.json").read_text())
        findings = doc.get("findings", [])
        frecs = [
            {"idx": i, "file": Path(f.get("file", "")).name,
             "line": int(f.get("line", 0) or 0),
             "canonical": f.get("rule_id", "") or "",
             "title": f.get("title", ""), "matched": []}
            for i, f in enumerate(findings)
        ]
        tp_items, fn_items = [], []
        # Many-to-many: a finding is TP when it matches ANY GT item, and a
        # GT item is TP when ANY finding matches it. This credits both
        # directions of grouping (one finding covering an op group; several
        # findings on adjacent lines of one config group).
        for item in items:
            tier = item.get("tier", "strict")
            hit = False
            for fr in frecs:
                if fr["file"] != item["file"]:
                    continue
                if tier not in ("file", "file-strict") and item["line"] is not None:
                    if abs(fr["line"] - item["line"]) > WINDOW:
                        continue
                if tier in ("strict", "file-strict", "config"):
                    if not item.get("canonical") or norm(fr["canonical"]) != norm(item["canonical"]):
                        continue
                fr["matched"].append(item["id"])
                hit = True
            if hit:
                tp_items.append(item["id"])
            else:
                fn_items.append({"id": item["id"], "file": item["file"],
                                 "line": item["line"], "canonical": item.get("canonical"),
                                 "kind": item.get("kind"), "tier": tier,
                                 "note": item.get("note", "")})
        fp_items = [{"finding": f"{fr['file']}:{fr['line']}",
                     "canonical": fr["canonical"], "title": fr["title"]}
                    for fr in frecs if not fr["matched"]]
        tp, fp, fn = len(tp_items), len(fp_items), len(fn_items)
        prec = tp / (tp + fp) if (tp + fp) else None
        rec = tp / (tp + fn) if (tp + fn) else None
        f1 = (2 * prec * rec / (prec + rec)) if prec and rec else None
        report["repos"][repo] = {
            "gt_items": len(items), "findings": len(findings),
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(prec, 4) if prec is not None else None,
            "recall": round(rec, 4) if rec is not None else None,
            "f1": round(f1, 4) if f1 is not None else None,
            "tp_items": tp_items, "fp_items": fp_items, "fn_items": fn_items,
        }
        agg_tp, agg_fp, agg_fn = agg_tp + tp, agg_fp + fp, agg_fn + fn
    ap = agg_tp / (agg_tp + agg_fp)
    ar = agg_tp / (agg_tp + agg_fn)
    report["aggregate"] = {
        "gt_items": sum(r["gt_items"] for r in report["repos"].values()),
        "findings": sum(r["findings"] for r in report["repos"].values()),
        "tp": agg_tp, "fp": agg_fp, "fn": agg_fn,
        "precision": round(ap, 4), "recall": round(ar, 4),
        "f1": round(2 * ap * ar / (ap + ar), 4),
    }
    (BASE / "REPORT.json").write_text(json.dumps(report, indent=1))
    for repo, r in report["repos"].items():
        print(f"{repo}: GT={r['gt_items']} F={r['findings']} TP={r['tp']} FP={r['fp']} FN={r['fn']} "
              f"P={r['precision']} R={r['recall']} F1={r['f1']}")
    a = report["aggregate"]
    print(f"AGGREGATE: GT={a['gt_items']} F={a['findings']} TP={a['tp']} FP={a['fp']} FN={a['fn']} "
          f"P={a['precision']} R={a['recall']} F1={a['f1']}")
    print("wrote REPORT.json")


if __name__ == "__main__":
    sys.exit(main())
