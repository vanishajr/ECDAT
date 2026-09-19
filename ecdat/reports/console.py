"""Console (human terminal) report renderer. Pure function.

Compact judge-facing default: identity, coverage, P1 risk posture, top
issues, migration triage. Detail stays behind flags/JSON exports.
No trailing newline.
"""

from __future__ import annotations


def _duration(report: dict) -> str:
    seconds = report.get("duration_sec")
    if isinstance(seconds, (int, float)):
        return f"{seconds:.1f}s"
    cov = report.get("coverage", {}) if isinstance(
        report.get("coverage"), dict) else {}
    elapsed = cov.get("elapsed_sec")
    if isinstance(elapsed, (int, float)):
        return f"{float(elapsed):.1f}s"
    return "n/a"


def to_console(report: dict) -> str:
    r = report
    risk = r.get("risk", {}) if isinstance(r.get("risk"), dict) else {}
    covsum = r.get("coverage_summary", {}) if isinstance(
        r.get("coverage_summary"), dict) else {}
    by_sev = r.get("by_severity", {}) or {}
    counts = r.get("migration_counts", {}) or {}
    lines = [
        "ECDAT",
        "--------------------------------",
        "",
        f"Target        {r.get('project_name', r.get('display_target', r.get('target', '')))}",
        f"Status        {r.get('status', 'COMPLETE')}",
        f"Duration      {_duration(r)}",
        f"Files         {covsum.get('files_analyzed', r.get('files_scanned', 0))} / "
        f"{covsum.get('files_discovered', r.get('files_scanned', 0))}",
        "",
        "RISK",
        f"Overall       {str(risk.get('level', 'none')).upper()} "
        f"\u00b7 {risk.get('score', 0.0)}/10",
        f"High          {by_sev.get('high', 0) + by_sev.get('critical', 0)}",
        f"Medium        {by_sev.get('medium', 0)}",
        f"Low           {by_sev.get('low', 0) + by_sev.get('info', 0)}",
        "",
        "CRYPTOGRAPHY",
        f"Assets        {r.get('asset_count', 0)}",
        f"Operations    {r.get('operation_count', 0)}",
        f"Algorithms    {len(r.get('inventory', []) or [])}",
        "",
        "TOP ISSUES",
    ]
    top_issues = r.get("top_issues", []) or []
    if top_issues:
        for issue in top_issues[:5]:
            sev = str(issue.get("severity", "")).upper()
            lines.append(
                f"{sev:<8} {issue.get('rule_id', ''):<14} "
                f"{issue.get('count', 0)} occurrence"
                f"{'s' if issue.get('count', 0) != 1 else ''}")
    else:
        lines.append("No findings.")
    lines += ["", "MIGRATION"]
    if counts:
        lines.append(f"Immediate       {counts.get('Immediate', 0)}")
        lines.append(f"High priority   {counts.get('High priority', 0)}")
        lines.append(f"Planned         {counts.get('Planned', 0)}")
        lines.append(f"Informational   {counts.get('Informational', 0)}")
    elif r.get("recommendations"):
        lines.append(f"Actions         {len(r['recommendations'])}")
    else:
        lines.append("No migration actions.")
    summary = str(r.get("summary", "") or "")
    if summary:
        lines += ["", "SUMMARY", summary]
    return "\n".join(lines)
