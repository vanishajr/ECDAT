"""ecdat scan-container <image-or-path> [--db PATH] [--output JSON] [--mock | --real].

Flow: mock fixture -> validate() -> SQLite insert. Prints scan_id.
Default client is mock. Exit codes: 0 ok, 1 error (incl. real-mode
placeholder, duplicate scan), 3 validation failure.

Mock limitation: the mock does NOT analyze the image. It returns the
deterministic container.json fixture with "target" overwritten.

Target semantics: accepts both local paths and registry references such
as nginx:1.25 or registry/org/image@sha256:.... Registry references
are never required to exist as local files, so no existence check is
performed. Only an empty value is rejected (exit 2).
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
from ecdat.core.validate import load_json, validate
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore

_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "fixtures"
    / "canonical"
    / "container.json"
)


def _mock_doc(target_label: str) -> dict:
    """Return the deterministic container mock doc with target overwritten."""
    doc = copy.deepcopy(load_json(_FIXTURE))
    doc["target"] = target_label
    return validate(doc)


def run(args: argparse.Namespace) -> int:
    label = str(args.image_or_path)
    if not label.strip():
        print(f"error: target not found: {label}", file=sys.stderr)
        return TARGET_NOT_FOUND

    if args.real:
        from ecdat.commands._real_scan import run_real_and_store

        return run_real_and_store(
            args, label, scanners=["container", "binary", "config"])
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
