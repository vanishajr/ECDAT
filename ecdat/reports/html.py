"""Self-contained offline HTML report renderer (Phase 12).

Derived from the same aggregate report dict as PDF/console: overview,
crypto inventory, operations, risk, recommendations, coverage. Inline
CSS/JS only (no CDN, no live-server dependency); redacted evidence
only. A small script filters the operations/findings tables.
"""

from __future__ import annotations

import html


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def to_html(report: dict) -> str:
    risk = report.get("risk", {}) if isinstance(
        report.get("risk"), dict) else {}
    cov = report.get("coverage", {}) if isinstance(
        report.get("coverage"), dict) else {}
    lim = report.get("limitations", {}) if isinstance(
        report.get("limitations"), dict) else {}
    sev = "".join(
        f"<tr><td>{_e(k)}</td><td>{v}</td></tr>"
        for k, v in sorted((report.get("by_severity", {}) or {}).items())
    ) or "<tr><td colspan='2'>No findings.</td></tr>"
    rules = "".join(
        f"<tr><td>{_e(r['rule_id'])}</td><td>{_e(r['severity'])}</td>"
        f"<td>{r['count']}</td><td>{_e(r['title'])}</td></tr>"
        for r in (report.get("by_rule", []) or [])
    ) or "<tr><td colspan='4'>No findings.</td></tr>"
    files = "".join(
        f"<tr><td>{_e(r['file'])}</td><td>{r['count']}</td></tr>"
        for r in (report.get("top_files", []) or [])
    ) or "<tr><td colspan='2'>No findings.</td></tr>"
    ops = "".join(
        f"<tr><td>{_e(o.get('operation_type', ''))}</td>"
        f"<td>{_e(o.get('canonical', ''))}</td>"
        f"<td>{_e(o.get('usage_state', ''))}</td>"
        f"<td>{_e(o.get('risk_class', ''))}</td>"
        f"<td>{_e(o.get('file', ''))}</td>"
        f"<td>{o.get('evidence_count', 0)}</td></tr>"
        for o in (report.get("top_operations", []) or [])
    ) or "<tr><td colspan='6'>No reconstructed operations.</td></tr>"
    usage = "".join(
        f"<tr><td>{_e(k)}</td><td>{v}</td></tr>"
        for k, v in sorted((report.get("usage_states", {}) or {}).items())
    ) or "<tr><td colspan='2'>No operations.</td></tr>"
    recs = "".join(
        f"<li><b>{_e(r['rule_id'])}</b> [{_e(r['severity'])}]: "
        f"{_e(r['action'])} "
        f"<span class='muted'>{_e(', '.join(r.get('refs', []) or []))}</span>"
        f"</li>"
        for r in (report.get("recommendations", []) or [])
    ) or "<li>No recommendations.</li>"
    tools = "".join(
        f"<li>{_e(k)}: {_e(v)}</li>"
        for k, v in sorted((report.get("tool_versions", {}) or {}).items()))
    status = "".join(
        f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>"
        for k, v in sorted((cov.get("scanner_status", {}) or {}).items()))
    lim_items = "".join(
        f"<li>{_e(k)}: {_e(', '.join(map(str, v)) if isinstance(v, list) else v)}</li>"
        for k, v in sorted(lim.items()) if v) or "<li>None recorded.</li>"
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">""" \
        f"""<title>ECDAT Report: {_e(report['scan_id'])}</title>""" \
        f"""<style>body{{font-family:sans-serif;max-width:64em;margin:2em auto;padding:0 1em}}""" \
        f"""table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #999;padding:.3em .6em;text-align:left}}""" \
        f""".muted{{color:#666;font-size:.85em}}nav a{{margin-right:1em}}</style></head><body>""" \
        f"""<h1>ECDAT Report: {_e(report['scan_id'])}</h1>""" \
        f"""<nav><a href="#overview">Overview</a><a href="#inventory">Inventory</a>""" \
        f"""<a href="#operations">Operations</a><a href="#risk">Risk</a>""" \
        f"""<a href="#recommendations">Recommendations</a><a href="#coverage">Coverage</a></nav>""" \
        f"""<h2 id="overview">Overview</h2><ul>""" \
        f"""<li>Target: {_e(report.get('display_target', report.get('target', '')))}</li>""" \
        f"""<li>Operations: {report.get('operation_count', 0)} """ \
        f"""(assets: {report.get('asset_count', 0)}, """ \
        f"""evidence findings: {report.get('finding_count', 0)}, """ \
        f"""files scanned: {report.get('files_scanned', 0)})</li>""" \
        f"""<li>Risk: {_e(risk.get('level', 'none'))} ({risk.get('score', 0.0)}) """ \
        f"""from the P1 risk engine</li>""" \
        f"""<li>Profile: {_e(cov.get('profile', 'standard'))}; """ \
        f"""cache: {'hit' if cov.get('cache_hit') else 'miss'}</li></ul>""" \
        f"""<h2>Scan scope and methodology</h2><ul><li>Started: {_e(report.get('started_at', ''))}</li>""" \
        f"""<li>Finished: {_e(report.get('finished_at', ''))}</li>{tools}</ul>""" \
        f"""<h2 id="inventory">Cryptographic inventory</h2>""" \
        f"""<h3>Usage states</h3><table><tr><th>State</th><th>Operations</th></tr>{usage}</table>""" \
        f"""<h3>Findings by severity</h3><table><tr><th>Severity</th><th>Count</th></tr>{sev}</table>""" \
        f"""<h3>Findings by rule</h3><table><tr><th>Rule</th><th>Severity</th><th>Count</th><th>Title</th></tr>{rules}</table>""" \
        f"""<h3>Top files</h3><table><tr><th>File</th><th>Count</th></tr>{files}</table>""" \
        f"""<h2 id="operations">Operations</h2>""" \
        f"""<p><input id="q" type="search" placeholder="Filter operations" oninput="filterRows('ops', this.value)"></p>""" \
        f"""<table id="ops"><tr><th>Type</th><th>Algorithm</th><th>Usage</th><th>Risk</th><th>Location</th><th>Evidence</th></tr>{ops}</table>""" \
        f"""<h2 id="risk">Risk</h2>""" \
        f"""<p>Posture {_e(risk.get('level', 'none'))} ({risk.get('score', 0.0)}). """ \
        f"""Unknown inputs stay unknown with explicit recorded assumptions """ \
        f"""(see JSON/CIR exports for per-operation provenance).</p>""" \
        f"""<h2 id="recommendations">Migration roadmap</h2><ul>{recs}</ul>""" \
        f"""<h2 id="coverage">Coverage and limitations</h2>""" \
        f"""<table><tr><th>Scanner</th><th>Status</th></tr>{status or "<tr><td colspan='2'>Not recorded.</td></tr>"}</table>""" \
        f"""<ul>{lim_items}</ul>""" \
        f"""<script>function filterRows(id, q){{q=q.toLowerCase();""" \
        f"""for(const r of document.querySelectorAll('#'+id+' tr')){{if(!r.querySelectorAll('th').length)""" \
        f"""r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';}}}}</script>""" \
        f"""</body></html>"""
