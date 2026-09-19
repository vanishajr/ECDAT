from __future__ import annotations

import argparse
import json
from pathlib import Path
import time
from typing import Any
import yaml

from .ecdat_adapter import run_production_scan
from .ground_truth import load_ground_truth, evaluate_ground_truth
from .repo_runner import find_repo, run_repo_benchmark


ROOT = Path(__file__).resolve().parent


def _load_manifest() -> dict[str, Any]:
    return yaml.safe_load((ROOT / "manifest.yaml").read_text(encoding="utf-8"))


def run_synthetic(profile: str) -> list[dict[str, Any]]:
    results = []
    gt_dir = ROOT / "ground_truth" / "synthetic"
    for gt_path in sorted(gt_dir.glob("*.yaml")):
        gt = load_ground_truth(gt_path)
        fixture = ROOT / gt["fixture"]
        scan = run_production_scan(
            str(fixture),
            profile=profile,
            display_name=gt["id"],
        )
        results.append(evaluate_ground_truth(gt, scan))
    return results


def compare_baseline(current: dict[str, Any], baseline_path: Path) -> dict[str, Any]:
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    return {
        "baseline_created_at": baseline.get("created_at"),
        "synthetic_pass_delta":
            current["summary"]["synthetic_pass"] - baseline.get("summary", {}).get("synthetic_pass", 0),
        "synthetic_fail_delta":
            current["summary"]["synthetic_fail"] - baseline.get("summary", {}).get("synthetic_fail", 0),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("fast", "nightly", "full"), default="fast")
    parser.add_argument("--profile", choices=("quick", "standard", "deep"))
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()

    mode_cfg = _load_manifest()["modes"][args.mode]
    profiles = [args.profile] if args.profile else mode_cfg["profiles"]

    output: dict[str, Any] = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": args.mode,
        "profiles": profiles,
        "synthetic": {},
        "repositories": [],
    }

    for profile in profiles:
        synth = run_synthetic(profile) if mode_cfg.get("synthetic") else []
        output["synthetic"][profile] = synth

    for repo_id in mode_cfg.get("real_repos", []):
        repo = find_repo(repo_id)
        for profile in profiles:
            output["repositories"].append(run_repo_benchmark(repo, profile))

    all_synth = [item for items in output["synthetic"].values() for item in items]
    output["summary"] = {
        "synthetic_pass": sum(1 for x in all_synth if x["pass"]),
        "synthetic_fail": sum(1 for x in all_synth if not x["pass"]),
        "repo_runs": len(output["repositories"]),
    }

    if args.baseline:
        output["comparison"] = compare_baseline(output, args.baseline)

    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "latest.json").write_text(json.dumps(output, indent=2), encoding="utf-8")

    md = [
        f"# ECDAT benchmark — {output['created_at']}",
        "",
        f"- Mode: `{args.mode}`",
        f"- Profiles: {', '.join(profiles)}",
        f"- Synthetic pass: **{output['summary']['synthetic_pass']}**",
        f"- Synthetic fail: **{output['summary']['synthetic_fail']}**",
        f"- Repository runs: **{output['summary']['repo_runs']}**",
        "",
        "## Synthetic failures",
        "",
    ]
    failures = [x for x in all_synth if not x["pass"]]
    if failures:
        for item in failures:
            md.append(f"- `{item['id']}` — FN={item['operations']['fn']} "
                      f"FP={item['operations']['fp']} forbidden={len(item['forbidden_hits'])}")
    else:
        md.append("- None")
    (reports / "latest.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    return 1 if output["summary"]["synthetic_fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
