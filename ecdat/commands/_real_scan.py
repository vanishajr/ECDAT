"""Shared --real execution helper (Person 3 platform layer).

ONE place that runs the integrated pipeline and persists both the
canonical document and the CIR sidecar. Used by scan/scan-binary/
scan-container/scan-cloud so real-mode behavior (errors, storage,
exit codes) is identical everywhere. No mock logic lives here.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from ecdat.adapters.pipeline import RealScanError
from ecdat.commands import ERROR
from ecdat.core.client import RealCoreClient
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore


def run_real_and_store(
    args: argparse.Namespace,
    target: str | Path,
    scanners: list[str] | None = None,
) -> int:
    """Run the real pipeline for ``target`` and store the result.

    Returns a CLI exit code (0 + prints scan_id on success). Failures
    print an actionable stderr message and return ERROR — never mock.
    Honors ``--output`` (canonical JSON) and ``--cir-out`` (CIR JSON)
    when the caller declares those arguments.
    """
    allow_container = bool(getattr(args, "allow_container", False))
    allow_cloud = bool(getattr(args, "allow_cloud", False))
    allow_runtime = bool(getattr(args, "allow_runtime", False))
    region = getattr(args, "region", None)
    region = str(region).strip() if region else None
    arg_scanners = getattr(args, "scanners", None)
    if arg_scanners:
        scanners = [s.strip().lower() for s in str(arg_scanners).split(",")
                    if s.strip()]
    client = RealCoreClient(
        scanners=scanners,
        allow_container=allow_container,
        allow_cloud=allow_cloud,
        allow_runtime=allow_runtime,
        region=region,
    )
    try:
        # Pass the raw label through: cloud labels (``aws:...``) and
        # container image refs (``nginx:1.25``) are not filesystem paths
        # and must not be coerced via Path().
        cir, doc = client.scan_with_cir(str(target))
    except RealScanError as exc:
        print(f"error: real scan failed: {exc}", file=sys.stderr)
        return ERROR

    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = db.open_db(db_path)
    try:
        scan_id = sstore.insert_scan(conn, doc, cir)
        fstore.insert_findings_for_scan(conn, doc)
    except sqlite3.IntegrityError:
        print(
            f"error: scan {doc['scan_id']} already exists in {db_path}",
            file=sys.stderr,
        )
        return ERROR
    finally:
        conn.close()

    if getattr(args, "output", None):
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    if getattr(args, "cir_out", None):
        cout = Path(args.cir_out)
        cout.parent.mkdir(parents=True, exist_ok=True)
        cout.write_text(json.dumps(cir, indent=2, sort_keys=True) + "\n")

    print(scan_id)
    return 0
