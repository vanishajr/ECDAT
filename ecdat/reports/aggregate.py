"""Report aggregation. Pure function over a validated canonical doc.

Reuses Task 6 helpers (risk_from_findings, recommend_for_findings)
without duplicating their logic. Person 1's real engine replaces
those helpers; this module keeps working unchanged.
"""

from __future__ import annotations

from ecdat.commands import recommend_cmd, risk_cmd

TOP_FILES_LIMIT = 5


def build_report(doc: dict, real_risk: dict | None = None) -> dict:
    """Aggregate a canonical doc into a report dict. No I/O.

    ``real_risk`` is the stored P1 posture (``risk_view`` shape) for real
    scans; mock-only reports pass None and render byte-identically to
    before. Real reports carry both the canonical severity breakdown
    (mock scoring, for format stability) and the P1 posture.
    """
    findings = doc["findings"]

    by_severity: dict[str, int] = {}
    for f in findings:
        sev = str(f["severity"])
        by_severity[sev] = by_severity.get(sev, 0) + 1

    by_rule_map: dict[str, dict] = {}
    for f in findings:
        rule_id = str(f["rule_id"])
        entry = by_rule_map.get(rule_id)
        if entry is None:
            by_rule_map[rule_id] = {
                "rule_id": rule_id,
                "title": str(f["title"]),
                "severity": str(f["severity"]),
                "count": 1,
            }
        else:
            entry["count"] += 1
    by_rule = sorted(by_rule_map.values(), key=lambda r: (-r["count"], r["rule_id"]))

    file_counts: dict[str, int] = {}
    for f in findings:
        name = str(f["file"])
        file_counts[name] = file_counts.get(name, 0) + 1
    top_files = [
        {"file": name, "count": count}
        for name, count in sorted(file_counts.items(), key=lambda kv: (-kv[1], kv[0]))[
            :TOP_FILES_LIMIT
        ]
    ]

    return {
        "scan_id": doc["scan_id"],
        "target": doc["target"],
        "started_at": doc["started_at"],
        "finished_at": doc["finished_at"],
        "tool_versions": dict(doc["tool_versions"]),
        "finding_count": len(findings),
        "files_scanned": doc["stats"]["files_scanned"],
        "by_severity": dict(sorted(by_severity.items())),
        "by_rule": by_rule,
        "top_files": top_files,
        "risk": risk_cmd.risk_from_findings(findings),
        "recommendations": recommend_cmd.recommend_for_findings(findings),
        "real_risk": dict(real_risk) if real_risk is not None else None,
    }
