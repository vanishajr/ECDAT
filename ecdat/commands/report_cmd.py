"""ecdat report <scan-id> --format {markdown,console,html,pdf} [--output PATH] [--db PATH].

Read-only report built from the preserved canonical document. Flow:
get_scan_doc() -> validate() -> build_report() -> renderer -> file
or stdout. Exit 0 on success, 1 when the scan id is unknown (or when
PDF output has no --output file), 3 on validation failure. Unknown
--format values are rejected by argparse (exit 2).

Risk/migration sections reuse the Task 6 mock helpers and are
labeled mock/placeholder. PDF is a minimal stdlib executive summary,
never written to stdout.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from jsonschema import ValidationError

from ecdat.commands import ERROR, VALIDATION_FAILED
from ecdat.core.validate import validate
from ecdat.reports import aggregate, console, html, markdown, pdf
from ecdat.store import db
from ecdat.store import scans as sstore

FORMATS = ("markdown", "console", "html", "pdf")


def render(report: dict, format: str) -> str | bytes:
    """Render an aggregated report. Pure dispatch, no I/O."""
    if format == "markdown":
        return markdown.to_markdown(report)
    if format == "console":
        return console.to_console(report)
    if format == "html":
        return html.to_html(report)
    if format == "pdf":
        return pdf.to_pdf_bytes(report)
    raise ValueError(f"unknown report format: {format!r}")


def run(args: argparse.Namespace) -> int:
    if args.format == "pdf" and not args.output:
        print("error: pdf format requires --output PATH", file=sys.stderr)
        return ERROR

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

    report = aggregate.build_report(doc)
    try:
        content = render(report, args.format)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ERROR

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            out.write_bytes(content)
        else:
            out.write_text(content + "\n")
    else:
        print(content)  # text formats only; pdf always has --output here
    return 0
