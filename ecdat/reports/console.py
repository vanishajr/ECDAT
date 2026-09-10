"""Console (human terminal) report renderer. Pure function. No trailing newline."""

from __future__ import annotations


def to_console(report: dict) -> str:
    r = report
    lines = [
        f"ECDAT report: {r['scan_id']}",
        f"target:   {r['target']}",
        f"findings: {r['finding_count']} (files scanned: {r['files_scanned']})",
        f"risk:     {r['risk']['level']} ({r['risk']['score']}) [mock scoring]",
        "",
        "by severity:",
    ]
    if r["by_severity"]:
        for sev, count in sorted(r["by_severity"].items()):
            lines.append(f"  {sev:<10} {count}")
    else:
        lines.append("  none")
    lines.append("")
    lines.append("by rule:")
    if r["by_rule"]:
        for row in r["by_rule"]:
            lines.append(f"  {row['rule_id']:<18} [{row['severity']}] x{row['count']} {row['title']}")
    else:
        lines.append("  none")
    lines.append("")
    lines.append("top files/services:")
    if r["top_files"]:
        for row in r["top_files"]:
            lines.append(f"  {row['file']} x{row['count']}")
    else:
        lines.append("  none")
    lines.append("")
    lines.append("migration (mock placeholder):")
    if r["recommendations"]:
        for rec in r["recommendations"]:
            lines.append(f"  {rec['rule_id']} [{rec['severity']}] x{rec['count']}: {rec['action']}")
    else:
        lines.append("  no recommendations")
    return "\n".join(lines)
