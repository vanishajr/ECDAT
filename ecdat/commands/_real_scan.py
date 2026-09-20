"""Shared --real execution helper (Person 3 platform layer).

ONE place that runs the integrated pipeline and persists both the
canonical document and the CIR sidecar. Used by scan/scan-binary/
scan-container/scan-cloud so real-mode behavior (errors, storage,
exit codes) is identical everywhere.

Phase 1: delegates to RealCoreClient, which delegates to the shared
ScanOrchestrator (single production pipeline).  ``caller`` records
which specialized command asked (hint/provenance only, never a
separate pipeline).
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
    caller: str = "cli-scan",
) -> int:
    """Run the real pipeline for ``target`` and store the result.

    Returns a CLI exit code (0 + prints scan_id on success). Failures
    print an actionable stderr message and return ERROR.
    Honors ``--output`` (canonical JSON) and ``--cir-out`` (CIR JSON)
    when the caller declares those arguments. When ``--repo URL`` is
    given, the repository is acquired first with the shared
    ``ecdat.acquisition`` implementation (same as the GUI) and the
    extracted tree becomes the scan target.
    """
    display_name: str | None = None
    repo_url = str(getattr(args, "repo", "") or "").strip()
    if repo_url:
        from ecdat.acquisition import acquire_github_repository
        from ecdat.acquisition import is_github_url as _is_github_url

        if not _is_github_url(repo_url):
            print(f"error: invalid GitHub repository URL: {repo_url}",
                  file=sys.stderr)
            return ERROR
        try:
            acquired = acquire_github_repository(repo_url)
        except ValueError as exc:
            print(f"error: repository acquisition failed: {exc}",
                  file=sys.stderr)
            return ERROR
        target = str(acquired["target"])
        display_name = str(acquired["label"])
        print(f"repository: {repo_url} -> {target} (kept; delete when done)",
              file=sys.stderr)
    allow_container = bool(getattr(args, "allow_container", False))
    allow_cloud = bool(getattr(args, "allow_cloud", False))
    allow_runtime = bool(getattr(args, "allow_runtime", False))
    allow_pull = bool(getattr(args, "allow_pull", False))
    allow_build = bool(getattr(args, "allow_build", False))
    region = getattr(args, "region", None)
    region = str(region).strip() if region else None
    profile = str(getattr(args, "scan_profile", getattr(args, "profile", "standard")) or "standard")
    arg_scanners = getattr(args, "scanners", None)
    if arg_scanners:
        scanners = [s.strip().lower() for s in str(arg_scanners).split(",")
                    if s.strip()]
    from ecdat.core.orchestrator import context_from_args, risk_z_from_args
    import os as _os

    # Explicit flags win; ambient env vars apply when flags are absent
    # (shell-history hygiene). Values are never logged or persisted.
    _ENV_FALLBACK = {
        "aws_access_key_id": "AWS_ACCESS_KEY_ID",
        "aws_secret_access_key": "AWS_SECRET_ACCESS_KEY",
        "aws_session_token": "AWS_SESSION_TOKEN",
        "aws_profile": "AWS_PROFILE",
    }

    def _opt_arg(name: str) -> str | None:
        value = getattr(args, name, None)
        text = str(value).strip() if value else ""
        if not text:
            text = str(_os.getenv(_ENV_FALLBACK[name], "") or "").strip()
        return text or None

    client = RealCoreClient(
        scanners=scanners,
        allow_container=allow_container,
        allow_cloud=allow_cloud,
        allow_runtime=allow_runtime,
        allow_pull=allow_pull,
        allow_build=allow_build,
        region=region,
        profile=profile,
        risk_z=risk_z_from_args(args),
        context=context_from_args(args),
        caller=caller,
        display_name=display_name,
        cloud_aws_access_key_id=_opt_arg("aws_access_key_id"),
        cloud_aws_secret_access_key=_opt_arg("aws_secret_access_key"),
        cloud_aws_session_token=_opt_arg("aws_session_token"),
        cloud_aws_profile=_opt_arg("aws_profile"),
    )
    try:
        # Pass the raw label through: cloud labels (``aws:...``) and
        # container image refs (``nginx:1.25``) are not filesystem paths
        # and must not be coerced via Path().
        result = client.scan_result(str(target))
        cir, doc = result.as_tuple()
    except RealScanError as exc:
        print(f"error: real scan failed: {exc}", file=sys.stderr)
        return ERROR

    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = db.open_db(db_path)
    try:
        scan_id = sstore.insert_scan(conn, doc, cir)
        fstore.insert_findings_for_scan(conn, doc)
        # Phase 11: durable plan + diagnostics alongside the scan.
        from ecdat.store.repository import save_meta as _save_meta
        _save_meta(conn, scan_id, result.plan.as_dict(),
                   result.diagnostics)
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
