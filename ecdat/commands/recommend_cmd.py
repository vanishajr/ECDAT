"""Display P1 migration recommendations stored with a scan."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ecdat.commands import ERROR
from ecdat.store import db
from ecdat.store import scans as sstore


def run(args: argparse.Namespace) -> int:
    conn = db.open_db(Path(args.db).expanduser())
    try:
        scan = sstore.get_scan(conn, args.scan_id)
        cir = sstore.get_scan_cir(conn, args.scan_id)
    finally:
        conn.close()
    if scan is None:
        print(f"error: scan not found: {args.scan_id}", file=sys.stderr)
        return ERROR
    if cir is None:
        print(f"error: scan {args.scan_id} has no analysis record", file=sys.stderr)
        return ERROR

    from ecdat.adapters.migration_adapter import build_real_items

    recommendations = build_real_items(cir)
    if args.severity is not None:
        recommendations = [item for item in recommendations if item["severity"] == args.severity]
    if args.json:
        print(json.dumps({"scan_id": args.scan_id, "recommendations": recommendations}, indent=2, sort_keys=True))
    else:
        print(f"scan_id: {args.scan_id}")
        if not recommendations:
            print("no recommendations")
        for item in recommendations:
            print(f"  {item['rule_id']} [{item['severity']}] {item['title']}: {item['action']}")
    return 0
