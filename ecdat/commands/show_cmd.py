"""ecdat show <scan_id> [--db PATH] [--json].

Shows one scan's metadata and its findings. Exit 0 on success,
1 when the scan id is unknown.
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


def run(args: argparse.Namespace) -> int:
    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = db.open_db(db_path)
    try:
        row = sstore.get_scan(conn, args.scan_id)
        if row is None:
            print(f"error: scan not found: {args.scan_id}", file=sys.stderr)
            return ERROR
        rows = fstore.list_findings(conn, args.scan_id)
    finally:
        conn.close()

    if args.json:
        print(json.dumps({"scan": row, "findings": rows}, indent=2, sort_keys=True))
        return 0

    print(f"scan_id:  {row['id']}")
    print(f"target:   {row['target']}")
    print(f"started:  {row['started_at']}")
    print(f"finished: {row['finished_at']}")
    print(f"findings: {len(rows)}")
    for f in rows:
        print(f"  [{f['severity']}] {f['rule_id']} {f['file']}:{f['line']} {f['title']}")
    return 0
