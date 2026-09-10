"""ecdat scan-binary <binary> [--deep auto] [--db PATH] [--output JSON] [--mock | --real].

Flow: mock fixture -> validate() -> SQLite insert. Prints scan_id.
Default client is mock. Exit codes: 0 ok, 1 error (incl. real-mode
placeholder, duplicate scan), 2 target not found, 3 validation failure.

Mock limitation: the mock does NOT analyze the binary. It returns the
deterministic binary.json fixture with "target" overwritten. --deep is
accepted (currently only "auto") but ignored by the mock and reserved
for Person 1 / Person 2 integration.
"""

from __future__ import annotations

import argparse
import copy
import json
import sqlite3
import sys
from pathlib import Path

from jsonschema import ValidationError

from ecdat.commands import ERROR, TARGET_NOT_FOUND, VALIDATION_FAILED
from ecdat.core.client import get_client
from ecdat.core.validate import load_json, validate
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore

_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "fixtures"
    / "canonical"
    / "binary.json"
)


def _mock_doc(target_label: str) -> dict:
    """Return the deterministic binary mock doc with target overwritten."""
    doc = copy.deepcopy(load_json(_FIXTURE))
    doc["target"] = target_label
    return validate(doc)


def run(args: argparse.Namespace) -> int:
    target = Path(args.binary)
    if not target.exists():
        print(f"error: target not found: {target}", file=sys.stderr)
        return TARGET_NOT_FOUND

    # --deep is accepted for CLI compatibility but ignored by the mock.
    _ = args.deep

    if args.real:
        client = get_client("real")
        try:
            doc = client.scan(target)
        except NotImplementedError as exc:
            # RealCoreClient placeholder: clean message, no traceback.
            print(f"error: {exc}", file=sys.stderr)
            return ERROR
    else:
        doc = _mock_doc(str(target))

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
