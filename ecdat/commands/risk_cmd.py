"""ecdat risk <scan-id> [--db PATH] [--json].

Read-only risk summary computed on demand from stored findings.
Does NOT persist risk results. Exit 0 on success, 1 when the scan
id is unknown.

MOCK SCORING MODEL (temporary, replaceable): Person 1 owns the real
quantum/classical risk engine. Until that API is finalized, risk is a
deterministic sum of per-severity weights:

    critical = 10, high = 5, medium = 3, low = 1, info = 0

Levels: 0 = none, 1-4 = low, 5-9 = medium, 10-19 = high, 20+ = critical.

Do NOT present this as ECDAT's final risk engine. Person 1's engine
replaces risk_from_findings() without redesigning the CLI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ecdat.commands import ERROR
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore

# Temporary mock weights. Person 1's real engine replaces this table.
WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 5,
    "medium": 3,
    "low": 1,
    "info": 0,
}


def level_for(score: int) -> str:
    """Map a mock score to a level. Pure helper, no I/O."""
    if score <= 0:
        return "none"
    if score <= 4:
        return "low"
    if score <= 9:
        return "medium"
    if score <= 19:
        return "high"
    return "critical"


def risk_from_findings(findings: list[dict]) -> dict:
    """Compute mock risk from finding rows. Pure helper, no I/O.

    Returns {"score": int, "level": str, "breakdown": {severity: count},
    "finding_count": int}. Unknown severities count 0 and are still
    included in the breakdown for transparency.
    """
    breakdown: dict[str, int] = {}
    score = 0
    for f in findings:
        sev = str(f.get("severity", ""))
        breakdown[sev] = breakdown.get(sev, 0) + 1
        score += WEIGHTS.get(sev, 0)
    return {
        "score": score,
        "level": level_for(score),
        "breakdown": breakdown,
        "finding_count": len(findings),
    }


def run(args: argparse.Namespace) -> int:
    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = db.open_db(db_path)
    try:
        row = sstore.get_scan(conn, args.scan_id)
        if row is None:
            print(f"error: scan not found: {args.scan_id}", file=sys.stderr)
            return ERROR
        findings = fstore.list_findings(conn, args.scan_id)
        cir = sstore.get_scan_cir(conn, args.scan_id)
    finally:
        conn.close()

    if cir is not None:
        return _run_real(args, findings, cir)
    result = risk_from_findings(findings)

    if args.json:
        print(
            json.dumps(
                {
                    "scan_id": args.scan_id,
                    "risk": {"score": result["score"], "level": result["level"]},
                    "breakdown": result["breakdown"],
                    "finding_count": result["finding_count"],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    print(f"scan_id: {args.scan_id}")
    print(f"risk:    {result['level']} ({result['score']}) [mock scoring]")
    print(f"findings: {result['finding_count']}")
    if result["breakdown"]:
        parts = " ".join(
            f"{sev}={count}" for sev, count in sorted(result["breakdown"].items())
        )
        print(f"breakdown: {parts}")
    else:
        print("breakdown: none")
    return 0


def _run_real(
    args: argparse.Namespace, findings: list[dict], cir: dict
) -> int:
    """Real-risk output from stored P1 wire risks (no mock scoring)."""
    from ecdat.adapters import risk_view as _risk_view

    posture = _risk_view.summarize_wire_risks(
        cir.get("risks", []) or [], len(findings))
    breakdown: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", ""))
        breakdown[sev] = breakdown.get(sev, 0) + 1
    if args.json:
        print(
            json.dumps(
                {
                    "scan_id": args.scan_id,
                    "risk": {"score": posture["score"],
                             "level": posture["level"]},
                    "breakdown": dict(sorted(breakdown.items())),
                    "finding_count": posture["finding_count"],
                    "risk_count": posture["risk_count"],
                    "model": posture["model"],
                    "source": posture["source"],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    print(f"scan_id: {args.scan_id}")
    print(f"risk:    {posture['level']} ({posture['score']}) [p1 risk engine]")
    print(f"findings: {posture['finding_count']}")
    if breakdown:
        parts = " ".join(
            f"{sev}={count}" for sev, count in sorted(breakdown.items())
        )
        print(f"breakdown: {parts}")
    else:
        print("breakdown: none")
    return 0
