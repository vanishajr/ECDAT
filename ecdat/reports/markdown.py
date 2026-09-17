"""Markdown report renderer."""

from __future__ import annotations


def to_markdown(report: dict) -> str:
    lines = [
        f"# ECDAT Report: {report['scan_id']}", "", "## Executive Summary", "",
        f"- Target: {report['target']}",
        f"- Findings: {report['finding_count']} (files scanned: {report['files_scanned']})",
        f"- Risk: {report['risk']['level']} ({report['risk']['score']})",
        f"- Rules affected: {len(report['by_rule'])}", "", "## Scan Information", "",
        f"- Started: {report['started_at']}", f"- Finished: {report['finished_at']}",
    ]
    lines.extend(f"- Tool {k}: {v}" for k, v in sorted(report["tool_versions"].items()))
    lines.extend(["", "## Findings by Severity", ""])
    if report["by_severity"]:
        lines.extend(["| Severity | Count |", "| --- | --- |"])
        lines.extend(f"| {s} | {n} |" for s, n in sorted(report["by_severity"].items()))
    else:
        lines.append("No findings.")
    lines.extend(["", "## Findings by Rule", ""])
    if report["by_rule"]:
        lines.extend(["| Rule | Severity | Count | Title |", "| --- | --- | --- | --- |"])
        lines.extend(f"| {r['rule_id']} | {r['severity']} | {r['count']} | {r['title']} |" for r in report["by_rule"])
    else:
        lines.append("No findings.")
    lines.extend(["", "## Top Affected Files/Services", ""])
    lines.extend((f"- {r['file']}: {r['count']}" for r in report["top_files"]))
    if not report["top_files"]:
        lines.append("No findings.")
    lines.extend(["", "## Risk Summary", "", f"Score {report['risk']['score']} / level {report['risk']['level']} from the P1 analysis engine.", "", "## Migration Recommendations", ""])
    if report["recommendations"]:
        lines.extend(f"- {r['rule_id']} [{r['severity']}] x{r['count']}: {r['action']}" for r in report["recommendations"])
    else:
        lines.append("No recommendations.")
    usage = report.get("usage_states", {}) or {}
    if usage:
        lines.extend(["", "## Crypto Usage (Operations)", ""])
        lines.extend(f"- {state}: {count}" for state, count in sorted(usage.items()))
    top_ops = report.get("top_operations", []) or []
    if top_ops:
        lines.extend(["", "## High-Priority Operations", ""])
        lines.extend(
            f"- {o.get('operation_type', '')} {o.get('canonical', '')} "
            f"[{o.get('risk_class', '')}] usage={o.get('usage_state', '')} "
            f"at {o.get('file', '')}" for o in top_ops[:5])
    coverage = report.get("coverage", {}) or {}
    if coverage:
        lines.extend(["", "## Coverage and Limitations", ""])
        status = coverage.get("scanner_status", {}) or {}
        lines.extend(f"- {name}: {state}" for name, state in sorted(status.items()))
        for key, value in sorted((report.get("limitations", {}) or {}).items()):
            if value:
                rendered = ", ".join(map(str, value)) if isinstance(value, list) else value
                lines.append(f"- {key}: {rendered}")
    return "\n".join(lines)
