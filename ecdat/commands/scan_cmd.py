"""ecdat scan <path> [--db PATH] [--output JSON] [--mock | --real].

Flow: CoreClient.scan() -> validate() -> SQLite insert. Prints scan_id.
Default client is mock. --real runs the integrated P2/P1 pipeline
(explicit scanner subset; opt-in families via --allow-*) and stores
the canonical document plus the CIR sidecar. Exit codes: 0 ok,
1 error (incl. real-mode failure, duplicate scan), 2 target not
found, 3 validation failure.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from jsonschema import ValidationError

from ecdat.commands import ERROR, TARGET_NOT_FOUND, VALIDATION_FAILED
from ecdat.core.client import get_client
from ecdat.core.validate import validate
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore


def run(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"error: target not found: {target}", file=sys.stderr)
        return TARGET_NOT_FOUND

    if args.real:
        from ecdat.commands._real_scan import run_real_and_store

        return run_real_and_store(args, target)

    client = get_client("mock")
    doc = client.scan(target)

    try:
        validate(doc)
    except ValidationError as exc:
        print(f"error: validation failed: {exc.message}", file=sys.stderr)
        return VALIDATION_FAILED

    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = db.open_db(db_path)
    try:
        scan_id = sstore.insert_scan(conn, doc)
        fstore.insert_findings_for_scan(conn, doc)
    except sqlite3.IntegrityError:
        print(
            f"error: scan {doc['scan_id']} already exists in {db_path}",
            file=sys.stderr,
        )
        return ERROR
    finally:
        conn.close()

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")

    print(scan_id)
    return 0
