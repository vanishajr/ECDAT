"""Console (human terminal) report renderer. Pure function.

Phase 12 actionable default: coverage, crypto usage, P1 risk posture,
top migration actions, limitations. Detail stays behind flags/JSON.
No trailing newline.
"""

from __future__ import annotations


def to_console(report: dict) -> str:
    r = report
    risk = r.get("risk", {}) if isinstance(r.get("risk"), dict) else {}
    cov = r.get("coverage", {}) if isinstance(r.get("coverage"), dict) else {}
    lim = r.get("limitations", {}) if isinstance(
        r.get("limitations"), dict) else {}
    lines = [
        "Scan complete",
        f"Target:  {r.get('display_target', r.get('target', ''))}",
        f"Profile: {cov.get('profile', 'standard')}",
        "",
        "Coverage:",
    ]
    status = cov.get("scanner_status", {}) or {}
    if status:
        for name in sorted(status):
            lines.append(f"  {name:12} {status[name]}")
    else:
        for name in sorted((r.get("tool_versions", {}) or {})):
            lines.append(f"  {name:12} OK")
        if not lines[4:]:
            lines.append("  (no scanner status recorded)")
    lines += ["", "Crypto usage:"]
    usage = r.get("usage_states", {}) or {}
    if usage:
        for state in ("Confirmed", "Probable", "Possible", "ProvidedOnly",
                      "FalsePositiveSuppressed"):
            if state in usage:
                lines.append(f"  {state:12} {usage[state]}")
        for state, count in sorted(usage.items()):
            if state not in ("Confirmed", "Probable", "Possible",
                             "ProvidedOnly", "FalsePositiveSuppressed"):
                lines.append(f"  {state:12} {count}")
    else:
        lines.append(f"  findings: {r.get('finding_count', 0)} "
                     "(no reconstructed operations)")
    lines += ["",
              f"Risk: {risk.get('level', 'none')} ({risk.get('score', 0.0)})"]
    top_ops = [o for o in (r.get("top_operations", []) or [])
               if o.get("risk_class") in ("Critical", "High")][:3]
    if top_ops:
        lines.append("Top risks:")
        for op in top_ops:
            lines.append(f"  {op.get('canonical', '')} "
                         f"[{op.get('risk_class', '')}] "
                         f"{op.get('file', '')}")
    lines += ["", "Migration:"]
    recs = r.get("recommendations", []) or []
    if recs:
        for i, rec in enumerate(recs[:5], 1):
            lines.append(f"  {i}. {rec.get('title', rec.get('rule_id', ''))}")
    else:
        lines.append("  no migration actions")
    flagged = [(k, v) for k, v in lim.items() if v]
    lines += ["", "Limitations:"]
    if flagged:
        for key, value in flagged:
            if isinstance(value, list):
                lines.append(f"  {key}: {', '.join(map(str, value))}")
            else:
                lines.append(f"  {key}: {value}")
    else:
        lines.append("  none recorded")
    return "\n".join(lines)
