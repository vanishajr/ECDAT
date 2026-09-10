"""Markdown report renderer. Pure function. No trailing newline."""

from __future__ import annotations


def to_markdown(report: dict) -> str:
    r = report
    lines = [
        f"# ECDAT Report: {r['scan_id']}",
        "",
        "## Executive Summary",
        "",
        f"- Target: {r['target']}",
        f"- Findings: {r['finding_count']} "
        f"(files scanned: {r['files_scanned']})",
        f"- Risk: {r['risk']['level']} ({r['risk']['score']}) [mock scoring]",
        f"- Rules affected: {len(r['by_rule'])}",
        "",
        "## Scan Information",
        "",
        f"- Scan ID: {r['scan_id']}",
        f"- Target: {r['target']}",
        f"- Started: {r['started_at']}",
        f"- Finished: {r['finished_at']}",
    ]
    for name in sorted(r["tool_versions"]):
        lines.append(f"- Tool {name}: {r['tool_versions'][name]}")
    lines += ["", "## Findings by Severity", ""]
    if r["by_severity"]:
        lines += ["| Severity | Count |", "| --- | --- |"]
        for sev, count in sorted(r["by_severity"].items()):
            lines.append(f"| {sev} | {count} |")
    else:
        lines.append("No findings.")
    lines += ["", "## Findings by Rule", ""]
    if r["by_rule"]:
        lines += ["| Rule | Severity | Count | Title |", "| --- | --- | --- | --- |"]
        for row in r["by_rule"]:
            lines.append(
                f"| {row['rule_id']} | {row['severity']} | {row['count']} | {row['title']} |"
            )
    else:
        lines.append("No findings.")
    lines += ["", "## Top Affected Files/Services", ""]
    if r["top_files"]:
        lines += ["| File/Service | Count |", "| --- | --- |"]
        for row in r["top_files"]:
            lines.append(f"| {row['file']} | {row['count']} |")
    else:
        lines.append("No findings.")
    lines += [
        "",
        "## Risk Summary (mock)",
        "",
        f"Score {r['risk']['score']} / level {r['risk']['level']} "
        "using the temporary mock scoring model.",
        "",
        "## Migration Summary (mock placeholder)",
        "",
    ]
    if r["recommendations"]:
        for rec in r["recommendations"]:
            lines.append(f"- {rec['rule_id']} [{rec['severity']}] x{rec['count']}: {rec['action']}")
    else:
        lines.append("No recommendations.")
    lines += [
        "",
        "## Disclaimer",
        "",
        "Risk and migration sections are mock/placeholder output pending "
        "Person 1's real risk and PQC recommendation engine.",
    ]
    return "\n".join(lines)
