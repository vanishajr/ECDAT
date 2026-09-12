"""ecdat list [--db PATH] [--limit N] [--json].

Lists stored scans with finding counts. Exit 0 on success.
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
        rows = sstore.list_scans(conn, limit=args.limit)
        counts = {r["id"]: fstore.count_findings(conn, r["id"]) for r in rows}
    except Exception as exc:  # noqa: BLE001 - CLI boundary: clean message
        print(f"error: list failed: {exc}", file=sys.stderr)
        return ERROR
    finally:
        conn.close()

    if args.json:
        print(
            json.dumps(
                [{**r, "finding_count": counts[r["id"]]} for r in rows],
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if not rows:
        print("no scans")
        return 0
    print(f"{'scan_id':<20} {'target':<30} {'started_at':<25} {'findings'}")
    for r in rows:
        print(
            f"{r['id']:<20} {r['target']:<30} {r['started_at']:<25} {counts[r['id']]}"
        )
    return 0
