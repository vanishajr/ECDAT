"""ecdat scan-cloud aws [--profile PROFILE] [--services SERVICES] [--db PATH] [--output JSON] [--mock | --real].

Flow: mock fixture -> validate() -> SQLite insert. Prints scan_id.
Default client is mock. Exit codes: 0 ok, 1 error (incl. real-mode
placeholder, duplicate scan, empty services), 3 validation failure.

Mock limitation: the mock does NOT contact AWS. It returns the
deterministic cloud-aws.json fixture with "target" overwritten as
"aws:<profile>:services=<comma-normalized-services>".

Only the "aws" provider is supported (enforced by argparse choices).
--services accepts a comma-separated list such as "kms,acm,elb".
"""

from __future__ import annotations

import argparse
import copy
import json
import sqlite3
import sys
from pathlib import Path

from jsonschema import ValidationError

from ecdat.commands import ERROR, VALIDATION_FAILED
from ecdat.core.validate import load_json, validate
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore

_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "fixtures"
    / "canonical"
    / "cloud-aws.json"
)


def build_target_label(profile: str, services: str) -> str | None:
    """Build the deterministic target label, or None if services is empty."""
    parts = [s.strip() for s in str(services).split(",")]
    parts = [s for s in parts if s]
    if not parts:
        return None
    return f"aws:{profile}:services={','.join(parts)}"


def _mock_doc(target_label: str) -> dict:
    """Return the deterministic cloud mock doc with target overwritten."""
    doc = copy.deepcopy(load_json(_FIXTURE))
    doc["target"] = target_label
    return validate(doc)


def run(args: argparse.Namespace) -> int:
    label = build_target_label(args.profile, args.services)
    if label is None:
        print("error: --services must list at least one service", file=sys.stderr)
        return ERROR

    if args.real:
        from ecdat.commands._real_scan import run_real_and_store

        return run_real_and_store(args, label, scanners=["cloud"])
    doc = _mock_doc(label)

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
