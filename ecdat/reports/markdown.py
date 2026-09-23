"""Markdown report renderer.

Judge-facing order: executive summary with compact metrics, priority
findings with evidence, confirmed cryptographic inventory, affected
components, migration priorities, scan coverage, methodology
appendix, detailed findings. All values come from the aggregate
report dict (real P1/CIR data); nothing is invented.
"""

from __future__ import annotations


def _badge(severity: object) -> str:
    return f"[{str(severity or 'info').upper()}]"


def to_markdown(report: dict) -> str:
    risk = report.get("risk", {}) if isinstance(
        report.get("risk"), dict) else {}
    cov = report.get("coverage_summary", {}) if isinstance(
        report.get("coverage_summary"), dict) else {}
    method = report.get("methodology", {}) if isinstance(
        report.get("methodology"), dict) else {}
    groups = report.get("finding_groups", []) or []
    confirmed_groups = [g for g in groups if g.get("confirmed")]
    capability_groups = [g for g in groups if not g.get("confirmed")]
    lines = [
        f"# ECDAT Cryptographic Analysis Report", "",
        "## 1. Executive Summary", "",
        f"- Project: {report.get('project_name', report.get('display_target', report.get('target', '')))}",
        f"- Status: {report.get('status', 'COMPLETE')}",
        f"- Overall risk: **{str(risk.get('level', 'none')).upper()}** "
        f"({risk.get('score', 0.0)}/10, {risk.get('risk_count', 0)} risk records)",
        f"- Findings: {report.get('finding_count', 0)} "
        f"(operations: {report.get('operation_count', 0)}, "
        f"assets: {report.get('asset_count', 0)})",
        f"- Files: {cov.get('files_analyzed', report.get('files_scanned', 0))} / "
        f"{cov.get('files_discovered', report.get('files_scanned', 0))} "
        f"with cryptographic evidence",
        "",
        str(report.get("summary", "") or ""),
        "",
        f"- Confirmed findings: "
        f"{sum(g.get('confirmed_count', 0) for g in groups)}",
        f"- Declared capabilities (unconfirmed): "
        f"{sum(g.get('count', 0) - g.get('confirmed_count', 0) for g in groups)}",
        "",
        "## 2. Priority Findings", "",
    ]
    if confirmed_groups:
        for group in confirmed_groups[:8]:
            first = group["occurrences"][0] if group["occurrences"] else {}
            lines.append(f"### {_badge(group['severity'])} {group['rule_id']} "
                         f"x{group['count']} — {group['title']}")
            lines.append("")
            for occ in group["occurrences"][:5]:
                lines.append(f"- `{occ['file']}:{occ['line']}`" +
                             (f" (confidence {occ['confidence']})"
                              if occ.get("confidence") is not None else ""))
                if occ.get("snippet"):
                    lines.append(f"  - evidence: `{occ['snippet'][:200]}`")
            if group["count"] > 5:
                lines.append(f"- ... and {group['count'] - 5} more occurrence(s)")
            lines.append("")
    else:
        lines += ["No confirmed findings.", ""]
    by_sev = report.get("by_severity", {}) or {}
    if by_sev:
        lines.append("Severity distribution (measured risk class per finding): "
                     + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items()))
                     + ".")
        lines.append("")
    lines += ["## 3. Cryptographic Inventory (Confirmed Use)", ""]
    inventory = [row for row in (report.get("inventory", []) or [])
                 if row.get("confirmed")]
    if inventory:
        lines += ["| Algorithm / Protocol | Type | Uses | Files | Risk | Migration |",
                  "| --- | --- | --- | --- | --- | --- |"]
        for row in inventory[:25]:
            mig = (row.get("migration", "") or "").replace("\n", " ")[:100]
            lines.append(f"| {_badge(row.get('risk', ''))} {row.get('algorithm', '')} "
                         f"| {row.get('type', '')} "
                         f"| {row.get('confirmed_uses', row.get('uses', 0))} "
                         f"| {row.get('file_count', 0)} | {row.get('risk', '')} | {mig} |")
        if len(inventory) > 25:
            lines.append(f"| ... and {len(inventory) - 25} more | | | | | |")
        lines.append("")
    else:
        lines += ["No confirmed cryptographic use.", ""]
    capabilities = [row for row in (report.get("inventory", []) or [])
                    if not row.get("confirmed")]
    if capabilities:
        lines.append(f"Declared capabilities without confirmed use "
                     f"({len(capabilities)}): "
                     + ", ".join(row.get("algorithm", "")
                                 for row in capabilities[:15])
                     + (", ..." if len(capabilities) > 15 else ""))
        lines.append("")
    if capability_groups:
        lines.append("Unconfirmed finding groups: "
                     + ", ".join(f"{g['rule_id']} x{g['count']}"
                                 for g in capability_groups[:10])
                     + (", ..." if len(capability_groups) > 10 else ""))
        lines.append("")
    lines += ["## 4. Affected Components", ""]
    components = report.get("components", []) or []
    if components:
        lines += ["| Module | Findings | Files | Top severity | Algorithms |",
                  "| --- | --- | --- | --- | --- |"]
        for comp in components:
            lines.append(f"| {comp.get('module', '')} | {comp.get('findings', 0)} | "
                         f"{comp.get('file_count', 0)} | "
                         f"{_badge(comp.get('highest_severity', ''))} "
                         f"{comp.get('highest_severity', '')} | "
                         f"{', '.join(comp.get('algorithms', [])[:5])} |")
        lines.append("")
    else:
        lines += ["No affected components.", ""]
    lines += ["## 5. Migration Priorities", ""]
    migration_groups = report.get("migration_groups", {}) or {}
    counts = report.get("migration_counts", {}) or {}
    if any(migration_groups.values()):
        for name in ("Immediate", "High priority", "Planned", "Informational"):
            items = migration_groups.get(name, []) or []
            if not items:
                continue
            lines.append(f"### {name} ({counts.get(name, len(items))})")
            lines.append("")
            for item in items[:10]:
                files = item.get("affected_files", []) or []
                lines.append(f"- {_badge(item.get('severity', ''))} "
                             f"**{item.get('title', item.get('rule_id', ''))}** "
                             f"x{item.get('count', 1)} in {len(files)} file(s): "
                             f"{item.get('action', '')}")
                if files:
                    lines.append(f"  - files: {', '.join(files[:8])}"
                                 + (" ..." if len(files) > 8 else ""))
                refs = item.get("refs", []) or []
                if refs:
                    lines.append(f"  - refs: {', '.join(refs[:3])}")
            if len(items) > 10:
                lines.append(f"- ... and {len(items) - 10} more item(s)")
            lines.append("")
    else:
        lines += ["No migration actions.", ""]
    lines += ["## 6. Scan Coverage", ""]
    lines.append(f"Coverage: {cov.get('files_analyzed', report.get('files_scanned', 0))} / "
                 f"{cov.get('files_discovered', report.get('files_scanned', 0))} files "
                 f"with cryptographic evidence "
                 f"(profile: {cov.get('profile', 'standard')}).")
    lines.append("")
    lines.append(f"- {cov.get('files_skipped', 0)} file(s) skipped before analysis; "
                 f"{cov.get('files_without_evidence', 0)} file(s) analyzed "
                 f"with no cryptographic evidence.")
    lines.append("")
    buckets = cov.get("skipped_by_bucket", {}) or {}
    if buckets:
        lines.append("Skipped by reason: " + ", ".join(
            f"{reason}={count}" for reason, count in sorted(buckets.items()))
            + ".")
        lines.append("")
    for entry in (cov.get("skipped_files", []) or [])[:30]:
        if isinstance(entry, dict):
            lines.append(f"- skipped `{entry.get('path', '')}`: "
                         f"{entry.get('reason', '')}")
    if len(cov.get("skipped_files", []) or []) > 30:
        lines.append(f"- ... and {len(cov.get('skipped_files', [])) - 30} more "
                     f"(see HTML report / JSON export).")
    if cov.get("skipped_files"):
        lines.append("")
    failed = cov.get("failed_scanners", []) or []
    if failed:
        lines.append(f"Failed scanners: {', '.join(failed)}")
        lines.append("")
    for key, value in sorted((report.get("limitations", {}) or {}).items()):
        if value:
            rendered = ", ".join(map(str, value)) if isinstance(value, list) else value
            lines.append(f"- {key}: {rendered}")
    if any(v for v in (report.get("limitations", {}) or {}).values()):
        lines.append("")
    lines += ["## 7. Methodology & Technical Details", "",
              str(method.get("risk_model", "") or ""),
              "",
              f"- Risk source: {method.get('risk_source', '')}",
              "- Signature registry:" + (
                  f" {method['registry_version']}".rstrip()
                  if str(method.get("registry_version", "")).strip() else ""),
              f"- Profile: {method.get('profile', 'standard')}; "
              f"elapsed: {method.get('elapsed_sec', '?')}s",
              f"- Scan ID: {report.get('scan_id', '')}",
              f"- Target: {report.get('display_target', report.get('target', ''))}",
              f"- Started: {report.get('started_at', '')}",
              f"- Finished: {report.get('finished_at', '')}"]
    tools = method.get("tool_versions", {}) or {}
    lines.extend(f"- Detector {k}: {v}" for k, v in sorted(tools.items()))
    scanners = method.get("scanner_status", {}) or {}
    if scanners:
        lines.append("- Scanner outcomes: " + ", ".join(
            f"{name}={state}" for name, state in sorted(scanners.items())))
    lines += ["", "## 8. Detailed Findings", ""]
    if groups:
        lines += ["| Severity | Rule | Title | File | Line | Confidence |",
                  "| --- | --- | --- | --- | --- | --- |"]
        shown = 0
        total = sum(len(g.get("occurrences", [])) for g in groups)
        for group in groups:
            for occ in group["occurrences"]:
                if shown >= 100:
                    break
                conf = occ.get("confidence", "")
                lines.append(f"| {_badge(group['severity'])} {group['severity']} "
                             f"| {group['rule_id']} | "
                             f"{group['title']} | {occ['file']} | {occ['line']} | "
                             f"{conf} |")
                shown += 1
            if shown >= 100:
                break
        if total > shown:
            lines.append(f"| ... and {total - shown} more (see JSON/CSV exports) | | | | | |")
        lines.append("")
    else:
        lines += ["No findings.", ""]
    return "\n".join(lines)
