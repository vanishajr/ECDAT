"""Self-contained offline HTML report renderer.

Judge-facing order: executive summary with compact metrics, risk
overview, confirmed cryptographic inventory, priority findings with
evidence, affected components, migration priorities, scan coverage,
methodology appendix, detailed findings. Inline CSS/JS only (no CDN,
no live-server dependency); evidence snippets are scrubbed upstream
and HTML-escaped here. A small script filters the inventory table.
"""

from __future__ import annotations

import html


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


_SEV_CLASS = {
    "critical": "sev-critical",
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
    "info": "sev-info",
}


def _badge(severity: object) -> str:
    sev = str(severity or "info").lower()
    return (f'<span class="badge {_SEV_CLASS.get(sev, "sev-info")}">'
            f"{_e(sev.upper())}</span>")


_CSS = (
    "body{font-family:sans-serif;max-width:64em;margin:2em auto;padding:0 1em;"
    "line-height:1.45;color:#1a1a1a}"
    "table{border-collapse:collapse;width:100%;margin:.6em 0}"
    "th,td{border:1px solid #999;padding:.3em .6em;text-align:left;vertical-align:top}"
    "th{background:#f0ede6}"
    ".muted{color:#666;font-size:.85em}"
    "nav a{margin-right:1em}"
    "details{margin:.4em 0}summary{cursor:pointer}"
    ".metrics{display:flex;flex-wrap:wrap;gap:.6em;margin:.8em 0}"
    ".metric{flex:1 1 10em;border:1px solid #999;border-radius:.5em;"
    "padding:.5em .8em;background:#f8f6f1}"
    ".metric b{display:block;font-size:1.3em}"
    ".metric span{font-size:.8em;color:#555}"
    ".badge{display:inline-block;min-width:4.5em;text-align:center;"
    "border-radius:1em;padding:.1em .6em;font-size:.78em;font-weight:bold;color:#fff}"
    ".sev-critical{background:#8b1a1a}.sev-high{background:#b3541e}"
    ".sev-medium{background:#9a7b1e}.sev-low{background:#3f6d4e}"
    ".sev-info{background:#5b6b7a}"
    "code.evidence{display:block;background:#f0ede6;border-radius:.3em;"
    "padding:.3em .5em;margin-top:.25em;white-space:pre-wrap;"
    "word-break:break-word;font-size:.85em}"
    "h2{margin-top:1.6em;border-bottom:2px solid #333;padding-bottom:.2em}"
    "@media print{nav,#q,#q2{display:none}"
    ".pagebreak{break-before:page}}"
)


def to_html(report: dict) -> str:
    risk = report.get("risk", {}) if isinstance(
        report.get("risk"), dict) else {}
    cov = report.get("coverage_summary", {}) if isinstance(
        report.get("coverage_summary"), dict) else {}
    lim = report.get("limitations", {}) if isinstance(
        report.get("limitations"), dict) else {}
    method = report.get("methodology", {}) if isinstance(
        report.get("methodology"), dict) else {}
    by_sev = report.get("by_severity", {}) or {}
    files_analyzed = cov.get("files_analyzed", report.get("files_scanned", 0))
    files_discovered = cov.get("files_discovered", report.get("files_scanned", 0))

    metric_cards = "".join(
        f'<div class="metric"><b>{_e(value)}</b><span>{_e(label)}</span></div>'
        for label, value in [
            ("Overall risk",
             f"{str(risk.get('level', 'none')).upper()} "
             f"({risk.get('score', 0.0)}/10)"),
            ("Findings", str(report.get("finding_count", 0))),
            ("Operations", str(report.get("operation_count", 0))),
            ("Files analyzed",
             f"{files_analyzed} / {files_discovered}"),
        ]
    )
    sev = "".join(
        f"<tr><td>{_badge(k)}</td><td>{v}</td></tr>"
        for k, v in sorted(by_sev.items())
    ) or "<tr><td colspan='2'>No findings.</td></tr>"
    contributors = "".join(
        f"<tr><td>{_badge(i.get('severity', i.get('class', '')))}</td>"
        f"<td>{_e(i.get('algorithm', ''))}</td>"
        f"<td>{_e(i.get('score', ''))}</td>"
        f"<td>{_e(i.get('confidence', ''))}</td>"
        f"<td><code>{_e(i.get('file', ''))}"
        + (f":{_e(i.get('line', ''))}" if i.get("line") else "")
        + "</code></td>"
        f"<td>{_e(i.get('usage_state', ''))}</td></tr>"
        + (f"<tr><td></td><td colspan='5'>"
           f"<code class='evidence'>{_e((i.get('snippet', '') or '')[:300])}</code>"
           f"</td></tr>" if i.get("snippet") else "")
        for i in (report.get("top_risks", []) or [])
    ) or "<tr><td colspan='6'>No risk records.</td></tr>"

    inventory_rows = report.get("inventory", []) or []
    confirmed_rows = [r for r in inventory_rows if r.get("confirmed")]
    capability_rows = [r for r in inventory_rows if not r.get("confirmed")]

    def _inv_table(rows: list) -> str:
        return "".join(
            f"<tr><td>{_e(r.get('algorithm', ''))}</td>"
            f"<td>{_e(r.get('type', ''))}</td>"
            f"<td>{r.get('uses', 0)}</td>"
            f"<td>{r.get('file_count', 0)}</td>"
            f"<td>{_badge(r.get('risk', ''))}</td>"
            f"<td>{_e((r.get('migration', '') or '').replace(chr(10), ' ')[:120])}</td></tr>"
            for r in rows[:100]
        )

    inventory = _inv_table(confirmed_rows) or (
        "<tr><td colspan='6'>No confirmed cryptographic use.</td></tr>")
    if len(confirmed_rows) > 100:
        inventory += (f"<tr><td colspan='6'>… and {len(confirmed_rows) - 100} "
                      f"more rows (see JSON/CSV exports).</td></tr>")
    capabilities = _inv_table(capability_rows) or (
        "<tr><td colspan='6'>No declared capabilities.</td></tr>")
    if len(capability_rows) > 100:
        capabilities += (f"<tr><td colspan='6'>… and {len(capability_rows) - 100} "
                         f"more rows (see JSON/CSV exports).</td></tr>")

    groups = report.get("finding_groups", []) or []
    confirmed_groups = [g for g in groups if g.get("confirmed")]
    capability_groups = [g for g in groups if not g.get("confirmed")]

    def _group_block(g: dict, show_snippets: bool) -> str:
        occs = "".join(
            f"<li><code>{_e(o['file'])}:{o['line']}</code>"
            + (f" (confidence {o['confidence']})"
               if o.get("confidence") is not None else "")
            + (f" [{_e(o.get('usage_state', ''))}]"
               if o.get("usage_state") else "")
            + (f"<code class='evidence'>{_e((o.get('snippet', '') or '')[:300])}</code>"
               if show_snippets and o.get("snippet") else "")
            + "</li>"
            for o in g["occurrences"][:8])
        more = (f"<li>… and {g['count'] - 8} more occurrence(s)</li>"
                if g["count"] > 8 else "")
        return (
            f"<details open><summary>{_badge(g['severity'])} "
            f"{_e(g['title'])} · {g['count']} occurrence(s) across "
            f"{g['file_count']} file(s)</summary><ul>{occs}{more}</ul></details>")

    major = "".join(
        _group_block(g, True) for g in confirmed_groups[:10]
    ) or "<p>No confirmed findings.</p>"
    if len(confirmed_groups) > 10:
        major += (f"<p>… and {len(confirmed_groups) - 10} more confirmed "
                  f"finding groups (see detailed findings).</p>")
    caps = "".join(
        _group_block(g, False) for g in capability_groups[:10]
    ) or "<p>No declared capabilities.</p>"
    if len(capability_groups) > 10:
        caps += (f"<p>… and {len(capability_groups) - 10} more capability "
                 f"groups (see detailed findings).</p>")

    detail_rows = "".join(
        f"<tr><td>{_badge(g['severity'])}</td><td>{_e(g['rule_id'])}</td>"
        f"<td>{_e(g['title'])}</td><td>{_e(o['file'])}</td>"
        f"<td>{o['line']}</td><td>{_e(o.get('confidence', ''))}</td></tr>"
        for g in groups[:30] for o in g["occurrences"][:20]
    ) or "<tr><td colspan='6'>No findings.</td></tr>"
    components = "".join(
        f"<tr><td>{_e(c.get('module', ''))}</td>"
        f"<td>{c.get('findings', 0)}</td>"
        f"<td>{c.get('file_count', 0)}</td>"
        f"<td>{_badge(c.get('highest_severity', ''))}</td>"
        f"<td>{_e(', '.join(c.get('algorithms', [])[:5]))}</td></tr>"
        for c in (report.get("components", []) or [])
    ) or "<tr><td colspan='5'>No affected components.</td></tr>"

    mig_groups = report.get("migration_groups", {}) or {}
    mig_counts = report.get("migration_counts", {}) or {}
    migration = ""
    for name in ("Immediate", "High priority", "Planned", "Informational"):
        items = mig_groups.get(name, []) or []
        migration += (f"<h3>{_e(name)} ({mig_counts.get(name, len(items))})</h3><ul>"
                      + "".join(
                          f"<li><b>{_e(i.get('title', i.get('rule_id', '')))}</b> "
                          f"×{i.get('count', 1)} across "
                          f"{len(i.get('affected_files', []) or [])} file(s): "
                          f"{_e(i.get('action', ''))} "
                          f"<span class='muted'>{_e(', '.join(i.get('refs', []) or [])[:160])}</span>"
                          + (f"<br><span class='muted'>Files: "
                             f"{_e(', '.join((i.get('affected_files', []) or [])[:8]))}"
                             f"{' …' if len(i.get('affected_files', []) or []) > 8 else ''}"
                             f"</span>" if i.get("affected_files") else "")
                          + "</li>"
                          for i in items[:15])
                      + (f"<li>… and {len(items) - 15} more item(s)</li>"
                         if len(items) > 15 else "")
                      + "</ul>")
    if not any(mig_groups.values()):
        migration = "<p>No migration actions.</p>"

    skipped_files = cov.get("skipped_files", []) or []
    skipped_table = "".join(
        f"<tr><td><code>{_e(e.get('path', ''))}</code></td>"
        f"<td>{_e(e.get('reason', ''))}</td></tr>"
        for e in skipped_files[:200]
    )
    if len(skipped_files) > 200:
        skipped_table += (f"<tr><td colspan='2'>… and {len(skipped_files) - 200} "
                          f"more (see JSON export).</td></tr>")
    buckets = "".join(
        f"<tr><td>{_e(reason)}</td><td>{count}</td></tr>"
        for reason, count in sorted(
            (cov.get("skipped_by_bucket", {}) or {}).items())
    )
    no_evidence = cov.get("files_without_evidence", 0) or 0
    tools = "".join(
        f"<li>{_e(k)}: {_e(v)}</li>"
        for k, v in sorted((method.get("tool_versions", {}) or {}).items()))
    scanners = "".join(
        f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>"
        for k, v in sorted((method.get("scanner_status", {}) or {}).items()))
    lim_items = "".join(
        f"<li>{_e(k)}: {_e(', '.join(map(str, v)) if isinstance(v, list) else v)}</li>"
        for k, v in sorted(lim.items()) if v) or "<li>None recorded.</li>"
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">""" \
        f"""<title>ECDAT Report: {_e(report.get('scan_id', ''))}</title>""" \
        f"""<style>{_CSS}</style></head><body>""" \
        f"""<h1>ECDAT Cryptographic Analysis Report</h1>""" \
        f"""<nav><a href="#summary">Summary</a><a href="#risk">Risk</a>""" \
        f"""<a href="#inventory">Inventory</a><a href="#findings">Findings</a>""" \
        f"""<a href="#components">Components</a><a href="#migration">Migration</a>""" \
        f"""<a href="#coverage">Coverage</a><a href="#method">Methodology</a>""" \
        f"""<a href="#details">Details</a></nav>""" \
        f"""<h2 id="summary">1. Executive Summary</h2>""" \
        f"""<div class="metrics">{metric_cards}</div>""" \
        f"""<p>{_e(report.get('summary', ''))}</p><ul>""" \
        f"""<li>Project: {_e(report.get('project_name', report.get('display_target', report.get('target', ''))))}</li>""" \
        f"""<li>Status: {_e(report.get('status', 'COMPLETE'))}</li>""" \
        f"""<li>Confirmed findings: """ \
        f"""{sum(g.get('confirmed_count', 0) for g in groups)} """ \
        f"""· declared capabilities (unconfirmed): """ \
        f"""{sum(g.get('count', 0) - g.get('confirmed_count', 0) for g in groups)}</li>""" \
        f"""</ul>""" \
        f"""<h2 id="risk">2. Risk Overview</h2>""" \
        f"""<p>Overall risk {_badge(str(risk.get('level', 'none')))} """ \
        f"""<b>{risk.get('score', 0.0)}/10</b> from the P1 risk engine """ \
        f"""({risk.get('risk_count', 0)} risk records). Severity labels below """ \
        f"""are the measured risk class for each finding.</p>""" \
        f"""<table><tr><th>Severity</th><th>Count</th></tr>{sev}</table>""" \
        f"""<h3>Main risk contributors</h3>""" \
        f"""<table><tr><th>Severity</th><th>Algorithm</th><th>Score</th><th>Confidence</th><th>Location</th><th>Usage</th></tr>{contributors}</table>""" \
        f"""<h2 id="inventory">3. Cryptographic Inventory — Confirmed Use</h2>""" \
        f"""<p><input id="q" type="search" placeholder="Filter inventory" oninput="filterRows('inv', this.value)"></p>""" \
        f"""<table id="inv"><tr><th>Algorithm / Protocol</th><th>Type</th><th>Uses</th><th>Files</th><th>Risk</th><th>Migration</th></tr>{inventory}</table>""" \
        f"""<h3>Declared Capabilities &amp; Dependencies (No Confirmed Use)</h3>""" \
        f"""<table><tr><th>Algorithm / Protocol</th><th>Type</th><th>Uses</th><th>Files</th><th>Risk</th><th>Migration</th></tr>{capabilities}</table>""" \
        f"""<h2 id="findings">4. Priority Findings</h2>{major}""" \
        f"""<h3>Declared Capabilities (Unconfirmed)</h3>{caps}""" \
        f"""<h2 id="components">5. Affected Components</h2>""" \
        f"""<table><tr><th>Module</th><th>Findings</th><th>Files</th><th>Top severity</th><th>Algorithms</th></tr>{components}</table>""" \
        f"""<h2 id="migration">6. Migration Priorities</h2>{migration}""" \
        f"""<h2 id="coverage">7. Scan Coverage</h2>""" \
        f"""<p><b>{files_analyzed} / {files_discovered}</b> files with cryptographic evidence """ \
        f"""(profile: {_e(cov.get('profile', 'standard'))}; """ \
        f"""cache: {'hit' if cov.get('cache_hit') else 'miss'}).</p>""" \
        f"""<ul><li>{cov.get('files_skipped', 0)} file(s) skipped before analysis """ \
        f"""(see table below for every path and reason).</li>""" \
        f"""<li>{no_evidence} file(s) analyzed with no cryptographic evidence.</li></ul>""" \
        f"""<h3>Skipped files by reason</h3>""" \
        f"""<table><tr><th>Reason</th><th>Count</th></tr>{buckets or "<tr><td colspan='2'>None skipped.</td></tr>"}</table>""" \
        f"""<h3>Every skipped file</h3>""" \
        f"""<table><tr><th>Path</th><th>Reason</th></tr>{skipped_table or "<tr><td colspan='2'>None skipped.</td></tr>"}</table>""" \
        f"""<ul>{lim_items}</ul>""" \
        f"""<h2 id="method" class="pagebreak">8. Methodology &amp; Technical Details</h2>""" \
        f"""<p>{_e(method.get('risk_model', ''))}</p>""" \
        f"""<ul><li>Risk source: {_e(method.get('risk_source', ''))}</li>""" \
        f"""<li>Signature registry: {_e(method.get('registry_version', ''))}</li>""" \
        f"""<li>Profile: {_e(method.get('profile', 'standard'))}; """ \
        f"""elapsed: {_e(method.get('elapsed_sec', ''))}s; """ \
        f"""cache: {'hit' if method.get('cache_hit') else 'miss'}</li>""" \
        f"""<li>Scan: {_e(report.get('scan_id', ''))}</li>""" \
        f"""<li>Target: {_e(report.get('display_target', report.get('target', '')))}</li>""" \
        f"""<li>Started: {_e(report.get('started_at', ''))}</li>""" \
        f"""<li>Finished: {_e(report.get('finished_at', ''))}</li>{tools}</ul>""" \
        f"""<h3>Scanner outcomes</h3>""" \
        f"""<table><tr><th>Scanner</th><th>Status</th></tr>{scanners or "<tr><td colspan='2'>Not recorded.</td></tr>"}</table>""" \
        f"""<h2 id="details" class="pagebreak">9. Detailed Findings</h2>""" \
        f"""<p><input id="q2" type="search" placeholder="Filter findings" oninput="filterRows('det', this.value)"></p>""" \
        f"""<table id="det"><tr><th>Severity</th><th>Rule</th><th>Title</th><th>File</th><th>Line</th><th>Confidence</th></tr>{detail_rows}</table>""" \
        f"""<script>function filterRows(id, q){{q=q.toLowerCase();""" \
        f"""for(const r of document.querySelectorAll('#'+id+' tr')){{if(!r.querySelectorAll('th').length)""" \
        f"""r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';}}}}</script>""" \
        f"""</body></html>"""
