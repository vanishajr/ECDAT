"""ecdat recommend <scan-id> [--db PATH] [--json] [--severity LEVEL].

Read-only placeholder recommendations derived from stored findings.
Does NOT persist recommendations, perform scanning, contact any
network, or call CoreClient/LLMs. Exit 0 on success, 1 when the scan
id is unknown.

MOCK/PLACEHOLDER OUTPUT (temporary, replaceable): Person 1 owns the
real PQC recommendation engine. Until that API is finalized, this
module maps known fixture rule_ids to static remediation text and
uses a severity-based fallback for unknown rules. Results are
deduplicated by rule_id and sorted for determinism.
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

# Deterministic placeholder map for rule_ids present in fixtures.
# Person 1's real engine replaces this map.
RULE_RECOMMENDATIONS: dict[str, dict] = {
    "RSA-1024": {
        "action": "Replace 1024-bit RSA keys with 2048-bit+ RSA or PQC KEM (mock).",
        "refs": ["https://csrc.nist.gov/pubs/fips/186-5/final"],
    },
    "MD5-USAGE": {
        "action": "Stop using MD5; migrate to SHA-256+ for integrity (mock).",
        "refs": ["https://cwe.mitre.org/data/definitions/327.html"],
    },
    "AES-ECB": {
        "action": "Stop using AES-ECB; use AES-GCM with unique nonces (mock).",
        "refs": ["https://csrc.nist.gov/pubs/sp/800/38/d/final"],
    },
    "TLS-1.0": {
        "action": "Disable TLS 1.0/1.1; require TLS 1.2+ (mock).",
        "refs": ["https://datatracker.ietf.org/doc/html/rfc8996"],
    },
    "KMS-NO-ROTATION": {
        "action": "Enable automatic KMS key rotation (mock).",
        "refs": ["https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"],
    },
    "ACM-EXPIRY": {
        "action": "Renew/replace the ACM certificate before expiry (mock).",
        "refs": ["https://docs.aws.amazon.com/acm/latest/userguide/managed-renewal.html"],
    },
    "ELB-TLS-OLD": {
        "action": "Move the ELB listener to a modern TLS security policy (mock).",
        "refs": ["https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html"],
    },
}

# Severity-based fallback for rules not in the map above.
SEVERITY_FALLBACK: dict[str, str] = {
    "critical": "Triage immediately per team runbook for critical findings (mock).",
    "high": "Prioritize remediation in the next change window (mock).",
    "medium": "Schedule remediation in the backlog (mock).",
    "low": "Address opportunistically or accept with sign-off (mock).",
    "info": "No action required; informational only (mock).",
}


def recommend_for_findings(
    findings: list[dict], severity: str | None = None
) -> list[dict]:
    """Build deterministic placeholder recommendations. Pure helper, no I/O.

    Deduplicates by rule_id, optionally filters by severity, sorts by
    rule_id. Each item: {rule_id, severity, title, action, refs, count}.
    """
    by_rule: dict[str, dict] = {}
    for f in findings:
        if severity is not None and f.get("severity") != severity:
            continue
        rule_id = str(f.get("rule_id", ""))
        entry = by_rule.get(rule_id)
        if entry is None:
            mapped = RULE_RECOMMENDATIONS.get(rule_id)
            if mapped is not None:
                action, refs = mapped["action"], list(mapped["refs"])
            else:
                action = SEVERITY_FALLBACK.get(
                    str(f.get("severity", "")),
                    "Review per team runbook (mock).",
                )
                refs = []
            by_rule[rule_id] = {
                "rule_id": rule_id,
                "severity": str(f.get("severity", "")),
                "title": str(f.get("title", "")),
                "action": action,
                "refs": refs,
                "count": 1,
            }
        else:
            entry["count"] += 1
    return [by_rule[k] for k in sorted(by_rule)]


def run(args: argparse.Namespace) -> int:
    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = db.open_db(db_path)
    try:
        row = sstore.get_scan(conn, args.scan_id)
        if row is None:
            print(f"error: scan not found: {args.scan_id}", file=sys.stderr)
            return ERROR
        findings = fstore.list_findings(conn, args.scan_id)
        cir = sstore.get_scan_cir(conn, args.scan_id)
    finally:
        conn.close()

    if cir is not None:
        return _run_real(args, cir)

    recs = recommend_for_findings(findings, severity=args.severity)

    if args.json:
        print(
            json.dumps(
                {"scan_id": args.scan_id, "recommendations": recs},
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    print(f"scan_id: {args.scan_id} (mock recommendations)")
    if not recs:
        print("no recommendations")
        return 0
    for r in recs:
        print(f"  {r['rule_id']} [{r['severity']}] x{r['count']}: {r['action']}")
    return 0


def _run_real(args: argparse.Namespace, cir: dict) -> int:
    """Real recommendations from stored P1 records (no placeholder map)."""
    from ecdat.adapters import migration_adapter as _migration_adapter

    items = _migration_adapter.build_real_items(cir)
    if args.severity is not None:
        items = [i for i in items if i["severity"] == args.severity]
    recs = [
        {
            "rule_id": i["rule_id"],
            "severity": i["severity"],
            "title": i["title"],
            "action": i["action"],
            "refs": i["refs"],
            "affected_files": i["affected_files"],
        }
        for i in items
    ]
    if args.json:
        print(
            json.dumps(
                {"scan_id": args.scan_id, "recommendations": recs,
                 "source": "p1"},
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    print(f"scan_id: {args.scan_id} (p1 recommendations)")
    if not recs:
        print("no recommendations")
        return 0
    for r in recs:
        print(f"  {r['rule_id']} [{r['severity']}] {r['title']}: {r['action']}")
    return 0
