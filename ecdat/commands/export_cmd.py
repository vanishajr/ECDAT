"""ecdat export <scan-id> --format {json,csv,cbom-json,cbom-xml,sarif} [--output PATH] [--db PATH].

Read-only export of the preserved canonical document. Flow:
get_scan_doc() -> validate() -> pure renderer -> file or stdout.
Exit 0 on success, 1 when the scan id is unknown, 3 on validation
failure. Unknown --format values are rejected by argparse (exit 2).

Only explicitly allowed canonical fields are rendered. DB internals
(created_at, raw_json) are never exported.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import ValidationError

from ecdat.commands import ERROR, VALIDATION_FAILED
from ecdat.core.validate import validate
from ecdat.exports import cbom, sarif
from ecdat.exports import csv_gen
from ecdat.store import db
from ecdat.store import scans as sstore

FORMATS = ("json", "csv", "cbom-json", "cbom-xml", "sarif")


def render(doc: dict, format: str) -> str:
    """Render a validated canonical doc. Pure dispatch, no I/O."""
    if format == "json":
        return json.dumps(doc, indent=2, sort_keys=True)
    if format == "csv":
        return csv_gen.to_csv(doc)
    if format == "cbom-json":
        return cbom.to_cbom_json(doc)
    if format == "cbom-xml":
        return cbom.to_cbom_xml(doc)
    if format == "sarif":
        return sarif.to_sarif(doc)
    raise ValueError(f"unknown export format: {format!r}")


def run(args: argparse.Namespace) -> int:
    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = db.open_db(db_path)
    try:
        doc = sstore.get_scan_doc(conn, args.scan_id)
    finally:
        conn.close()
    if doc is None:
        print(f"error: scan not found: {args.scan_id}", file=sys.stderr)
        return ERROR

    try:
        validate(doc)
    except ValidationError as exc:
        print(f"error: validation failed: {exc.message}", file=sys.stderr)
        return VALIDATION_FAILED

    try:
        content = render(doc, args.format)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ERROR

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content + "\n")
    else:
        print(content)
    return 0
