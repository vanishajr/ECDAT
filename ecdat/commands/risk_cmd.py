"""Display the P1 risk posture stored with a scan."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ecdat.commands import ERROR
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore


def run(args: argparse.Namespace) -> int:
    conn = db.open_db(Path(args.db).expanduser())
    try:
        scan = sstore.get_scan(conn, args.scan_id)
        cir = sstore.get_scan_cir(conn, args.scan_id)
        findings = fstore.list_findings(conn, args.scan_id)
    finally:
        conn.close()
    if scan is None:
        print(f"error: scan not found: {args.scan_id}", file=sys.stderr)
        return ERROR
    if cir is None:
        print(f"error: scan {args.scan_id} has no analysis record", file=sys.stderr)
        return ERROR

    from ecdat.adapters.risk_view import summarize_wire_risks

    posture = summarize_wire_risks(cir.get("risks", []) or [], len(findings))
    if args.json:
        print(json.dumps({"scan_id": args.scan_id, "risk": posture}, indent=2, sort_keys=True))
    else:
        print(f"scan_id: {args.scan_id}")
        print(f"risk:    {posture['level']} ({posture['score']})")
        print(f"findings: {posture['finding_count']}")
        print(f"risk records: {posture['risk_count']}")
    return 0
