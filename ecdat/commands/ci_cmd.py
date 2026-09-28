"""Scan a target and enforce a severity threshold in CI.

Phase 1: CI uses the same ScanOrchestrator pipeline as CLI/GUI (via
RealCoreClient).  --fail-on is policy gating only; it never replaces
P1 risk with a separate score.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ecdat.commands import ERROR, TARGET_NOT_FOUND
from ecdat.commands import export_cmd
from ecdat.core.client import RealCoreClient
from ecdat.store import db

POLICY_FAILED = ERROR
SEVERITIES = ("info", "low", "medium", "high", "critical")


def _rank(severity: str) -> int | None:
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return None


def evaluate(findings: list[dict], fail_on: str | None) -> dict:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = str(finding.get("severity", ""))
        counts[severity] = counts.get(severity, 0) + 1
    known = [severity for severity in SEVERITIES if counts[severity]]
    triggered = [severity for severity in known if fail_on and _rank(severity) >= _rank(fail_on)]
    return {
        "by_severity": counts,
        "max_severity": known[-1] if known else None,
        "triggered": triggered,
        "passed": not triggered,
    }


def _posture(cir: dict, finding_count: int) -> dict:
    from ecdat.adapters.risk_view import summarize_wire_risks

    posture = summarize_wire_risks(cir.get("risks", []) or [], finding_count)
    return {"score": posture["score"], "level": posture["level"]}


def _limitations_from(diagnostics: dict | None) -> dict:
    """Scan limitations for CI output (Phase 11: never gate silently).

    Surfaces unavailable tools, permission-gated surfaces, and cache
    state from run diagnostics so a green gate cannot hide missing
    coverage. Pure; never raises.
    """
    diagnostics = diagnostics if isinstance(diagnostics, dict) else {}
    try:
        unavailable = sorted(map(str, diagnostics.get("unavailable", []) or []))
    except Exception:
        unavailable = []
    try:
        permissions_required = sorted(map(
            str, diagnostics.get("permissions_required", []) or []))
    except Exception:
        permissions_required = []
    try:
        scanner_status = dict(diagnostics.get("scanner_status", {}) or {})
    except Exception:
        scanner_status = {}
    failed = sorted(
        name for name, status in scanner_status.items()
        if isinstance(status, str) and status.startswith("failed"))
    return {
        "unavailable_tools": unavailable,
        "permission_gated": permissions_required,
        "failed_scanners": failed,
        "cache_hit": bool(diagnostics.get("cache_hit", False)),
    }


def build_result(target: str, doc: dict, fail_on: str | None,
                 sarif_path: str | None = None,
                 risk: dict | None = None,
                 diagnostics: dict | None = None) -> dict:
    policy = evaluate(doc["findings"], fail_on)
    posture = risk or {"score": 0.0, "level": "none"}
    return {
        "tool": "ecdat-ci",
        "target": target,
        "scan_id": doc["scan_id"],
        "finding_count": len(doc["findings"]),
        "by_severity": policy["by_severity"],
        "risk": posture,
        "fail_on": fail_on,
        "verdict": "pass" if policy["passed"] else "fail",
        "triggered": policy["triggered"],
        "max_severity": policy["max_severity"],
        "sarif": sarif_path,
        "limitations": _limitations_from(diagnostics),
        "note": "Integrated P2 discovery and P1 analysis.",
    }


def _summary_lines(result: dict) -> list[str]:
    counts = " ".join(f"{s}={result['by_severity'].get(s, 0)}" for s in SEVERITIES)
    lines = [
        f"ci: {result['target']}",
        f"scan_id: {result['scan_id']}",
        f"findings: {result['finding_count']} ({counts})",
        f"risk: {result['risk']['level']} ({result['risk']['score']})",
        f"fail-on: {result['fail_on'] if result['fail_on'] else 'none (report only)'}",
        f"verdict: {'PASS' if result['verdict'] == 'pass' else 'FAIL'}",
    ]
    limitations = result.get("limitations") or {}
    flagged = [f"{k}={v}" for k, v in limitations.items()
               if v and k != "cache_hit"]
    if flagged:
        lines.append("limitations: " + "; ".join(flagged))
    return lines


def run(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.exists():
        print(f"error: target not found: {target}", file=sys.stderr)
        return TARGET_NOT_FOUND
    # Same orchestrator pipeline as CLI/GUI (Phase 1 convergence via
    # RealCoreClient -> ScanOrchestrator).  CI only adds policy gating.
    from ecdat.core.orchestrator import context_from_args, risk_z_from_args
    client = RealCoreClient(
        scanners=[s.strip().lower() for s in args.scanners.split(",") if s.strip()] if args.scanners else None,
        allow_container=bool(args.allow_container),
        allow_cloud=bool(args.allow_cloud),
        allow_runtime=bool(args.allow_runtime),
        allow_pull=bool(getattr(args, "allow_pull", False)),
        allow_build=bool(getattr(args, "allow_build", False)),
        region=str(getattr(args, "region", None) or "").strip() or None,
        profile=str(getattr(args, "profile", "standard") or "standard"),
        risk_z=risk_z_from_args(args),
        context=context_from_args(args),
        caller="ci",
    )
    try:
        scan_result = client.scan_result(target)
        cir, doc = scan_result.as_tuple()
    except Exception as exc:
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return ERROR
    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = db.open_db(db_path)
    try:
        from ecdat.store.persist import store_scan_result as _store
        _scan_id, reused = _store(
            conn, doc, cir, scan_result.plan.as_dict(),
            scan_result.diagnostics,
            replace=bool(getattr(args, "replace", False)))
        if reused:
            print(f"scan {_scan_id} already stored in {db_path} (reused)",
                  file=sys.stderr)
    except Exception as exc:
        print(f"error: could not store scan: {exc}", file=sys.stderr)
        return ERROR
    finally:
        conn.close()
    sarif_path = str(args.sarif) if args.sarif else None
    if sarif_path:
        out = Path(sarif_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(export_cmd.render(doc, "sarif") + "\n")
    result = build_result(str(target), doc, args.fail_on, sarif_path,
                          _posture(cir, len(doc["findings"])),
                          scan_result.diagnostics)
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else "\n".join(_summary_lines(result)))
    return 0 if result["verdict"] == "pass" else POLICY_FAILED
