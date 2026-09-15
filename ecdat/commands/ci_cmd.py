"""ecdat ci <target> [--db PATH] [--mock | --real] [--fail-on SEV] [--summary] [--json] [--sarif PATH].

Mock-first CI gate (Person 3 platform layer). Orchestration/policy only —
no second analysis engine. Flow:

    CoreClient.scan() -> validate() -> SQLite insert (idempotent reuse
    when the fixture scan_id is already stored) -> risk_from_findings()
    (Task 6, reused) -> policy evaluation -> human/JSON stdout, with an
    optional SARIF file through the existing Task 7 exporter
    (export_cmd.render(doc, "sarif"), reused verbatim).

Exit codes (existing conventions): 0 scan ok and policy passed (or no
--fail-on threshold configured), 1 policy failure or general error
(incl. real-mode placeholder), 2 target not found (also argparse
rejections), 3 validation failure. Stdout carries ONLY the selected
payload (human summary by default, pure JSON with --json); errors go
to stderr. A SARIF file never touches stdout.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from jsonschema import ValidationError

from ecdat.commands import ERROR, TARGET_NOT_FOUND, VALIDATION_FAILED
from ecdat.commands import export_cmd
from ecdat.commands.risk_cmd import risk_from_findings
from ecdat.core.client import get_client
from ecdat.core.validate import validate
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore

# Policy failure is a predictable non-zero CI signal. It reuses the
# existing general-error code (1) rather than inventing a new one; the
# human/JSON verdict field is what distinguishes "findings tripped the
# gate" from "the scanner errored".
POLICY_FAILED = ERROR

# Severity rank order for --fail-on evaluation. This is CI policy owned
# by this module (which severities trip the gate), NOT the Task 6 risk
# model (weights/score/level, reused via risk_from_findings).
SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

MOCK_NOTE = (
    "Mock pipeline: MockCoreClient fixture data with Task 6 mock risk "
    "scoring. No Person 1/2 engines, no PQC/accuracy claims."
)


def _rank(severity: str) -> int | None:
    """Rank of a known severity, or None for severities v1 never defines."""
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return None


def evaluate(findings: list[dict], fail_on: str | None) -> dict:
    """Evaluate the CI gate. Pure helper, no I/O.

    Returns {"by_severity": {sev: count} (zero-filled, known levels
    first in rank order), "max_severity": highest known severity
    present or None, "triggered": known severities at/above the
    threshold in rank order, "passed": bool}. With fail_on=None the
    gate reports only and always passes. Unknown severities are
    counted honestly but never trip the gate.
    """
    by_severity: dict[str, int] = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        sev = str(f.get("severity", ""))
        by_severity[sev] = by_severity.get(sev, 0) + 1
    known = [s for s in SEVERITIES if by_severity.get(s, 0) > 0]
    max_severity = known[-1] if known else None
    triggered: list[str] = []
    if fail_on is not None:
        threshold = SEVERITIES.index(fail_on)
        triggered = [s for s in known if SEVERITIES.index(s) >= threshold]
    return {
        "by_severity": by_severity,
        "max_severity": max_severity,
        "triggered": triggered,
        "passed": not triggered,
    }


REAL_NOTE = (
    "Real pipeline: P2 discovery with P1 risk scoring; gate policy "
    "evaluates stored finding severities. No PQC/accuracy claims."
)


def build_result(target: str, doc: dict, fail_on: str | None,
                 sarif_path: str | None = None, mock: bool = True,
                 risk: dict | None = None) -> dict:
    """Build the deterministic machine-readable CI result. Pure, no I/O.

    ``risk`` overrides the displayed score/level (real scans pass the
    stored P1 posture; mock scans use Task 6 mock scoring). Gate policy
    always evaluates finding severities, never the score.
    """
    shown = risk if risk is not None else risk_from_findings(doc["findings"])
    policy = evaluate(doc["findings"], fail_on)
    return {
        "tool": "ecdat-ci",
        "mock": mock,
        "target": target,
        "scan_id": doc["scan_id"],
        "finding_count": len(doc["findings"]),
        "by_severity": policy["by_severity"],
        "risk": {"score": shown["score"], "level": shown["level"]},
        "fail_on": fail_on,
        "verdict": "pass" if policy["passed"] else "fail",
        "triggered": policy["triggered"],
        "max_severity": policy["max_severity"],
        "sarif": sarif_path,
        "note": MOCK_NOTE if mock else REAL_NOTE,
    }


def _summary_lines(result: dict) -> list[str]:
    counts = " ".join(
        f"{sev}={result['by_severity'].get(sev, 0)}" for sev in SEVERITIES
    )
    pipeline = "mock pipeline" if result.get("mock", True) else "real pipeline"
    scoring = "[mock scoring]" if result.get("mock", True) else "[p1 risk engine]"
    engines = "(mock — no Person 1/2 engines)" if result.get("mock", True) else "(p1 risk engine)"
    return [
        f"ci: {result['target']} ({pipeline})",
        f"scan_id: {result['scan_id']}",
        f"findings: {result['finding_count']} ({counts})",
        f"risk: {result['risk']['level']} ({result['risk']['score']}) {scoring}",
        f"fail-on: {result['fail_on'] if result['fail_on'] is not None else 'none (report only)'}",
        f"verdict: {'PASS' if result['verdict'] == 'pass' else 'FAIL'} {engines}",
    ]


def _real_posture(cir: dict, doc: dict) -> dict:
    """Displayed CI risk for real scans (stored P1 posture, no mock math)."""
    from ecdat.adapters import risk_view as _risk_view

    posture = _risk_view.summarize_wire_risks(
        cir.get("risks", []) or [], len(doc["findings"]))
    return {"score": posture["score"], "level": posture["level"]}


def run(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.exists():
        print(f"error: target not found: {target}", file=sys.stderr)
        return TARGET_NOT_FOUND

    if args.real:
        # Real mode honors the same scanner selection flags as `scan`.
        from ecdat.core.client import RealCoreClient

        arg_scanners = getattr(args, "scanners", None)
        scanners = None
        if arg_scanners:
            scanners = [s.strip().lower() for s in str(arg_scanners).split(",")
                        if s.strip()]
        client = RealCoreClient(
            scanners=scanners,
            allow_container=bool(getattr(args, "allow_container", False)),
            allow_cloud=bool(getattr(args, "allow_cloud", False)),
            allow_runtime=bool(getattr(args, "allow_runtime", False)),
            region=getattr(args, "region", None),
        )
    else:
        client = get_client("mock")
    cir: dict | None = None
    if args.real:
        from typing import cast

        from ecdat.adapters.pipeline import RealScanError

        scan_with_cir = getattr(client, "scan_with_cir", None)
        if not callable(scan_with_cir):
            print("error: real client cannot produce a CIR sidecar",
                  file=sys.stderr)
            return ERROR
        try:
            pair = cast("tuple[dict, dict]", scan_with_cir(target))
            cir, doc = pair[0], pair[1]
        except RealScanError as exc:
            print(f"error: real scan failed: {exc}", file=sys.stderr)
            return ERROR
    else:
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
        try:
            sstore.insert_scan(conn, doc, cir)
            fstore.insert_findings_for_scan(conn, doc)
        except sqlite3.IntegrityError:
            # Fixture scan_id already stored: reuse it (same convention
            # as the GUI service). Mock limitation: the stored doc keeps
            # the first scan's target label; findings are identical.
            conn.rollback()
            stored = sstore.get_scan_doc(conn, doc["scan_id"])
            if stored is None:
                print(
                    f"error: scan {doc['scan_id']} unreadable in {db_path}",
                    file=sys.stderr,
                )
                return ERROR
            doc = stored
    finally:
        conn.close()

    sarif_path = str(args.sarif) if args.sarif else None
    if sarif_path:
        # Existing Task 7 SARIF path verbatim — no second serializer.
        content = export_cmd.render(doc, "sarif")
        out = Path(sarif_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content + "\n")

    result = build_result(str(target), doc, args.fail_on, sarif_path,
                          mock=cir is None,
                          risk=_real_posture(cir, doc) if cir is not None else None)

    if args.json:
        # Pure JSON on stdout: no human lines, no logging noise.
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for line in _summary_lines(result):
            print(line)

    return 0 if result["verdict"] == "pass" else POLICY_FAILED
