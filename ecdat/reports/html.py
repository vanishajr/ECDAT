"""Single-file HTML report renderer (stdlib only). Pure function. No trailing newline."""

from __future__ import annotations

import html


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def to_html(report: dict) -> str:
    r = report
    sev_rows = "".join(
        f"<tr><td>{_e(sev)}</td><td>{count}</td></tr>"
        for sev, count in sorted(r["by_severity"].items())
    ) or "<tr><td colspan='2'>No findings.</td></tr>"
    rule_rows = "".join(
        f"<tr><td>{_e(row['rule_id'])}</td><td>{_e(row['severity'])}</td>"
        f"<td>{row['count']}</td><td>{_e(row['title'])}</td></tr>"
        for row in r["by_rule"]
    ) or "<tr><td colspan='4'>No findings.</td></tr>"
    file_rows = "".join(
        f"<tr><td>{_e(row['file'])}</td><td>{row['count']}</td></tr>" for row in r["top_files"]
    ) or "<tr><td colspan='2'>No findings.</td></tr>"
    rec_items = "".join(
        f"<li><b>{_e(rec['rule_id'])}</b> [{_e(rec['severity'])}] "
        f"x{rec['count']}: {_e(rec['action'])}</li>"
        for rec in r["recommendations"]
    ) or "<li>No recommendations.</li>"
    tools = "".join(f"<li>{_e(k)}: {_e(v)}</li>" for k, v in sorted(r["tool_versions"].items()))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ECDAT Report: {_e(r['scan_id'])}</title>
<style>body{{font-family:sans-serif;max-width:60em;margin:2em auto;padding:0 1em}}table{{border-collapse:collapse}}th,td{{border:1px solid #999;padding:.3em .6em;text-align:left}}</style>
</head>
<body>
<h1>ECDAT Report: {_e(r['scan_id'])}</h1>
<h2>Executive Summary</h2>
<ul>
<li>Target: {_e(r['target'])}</li>
<li>Findings: {r['finding_count']} (files scanned: {r['files_scanned']})</li>
<li>Risk: {_e(r['risk']['level'])} ({r['risk']['score']}) [mock scoring]</li>
</ul>
<h2>Scan Information</h2>
<ul>
<li>Started: {_e(r['started_at'])}</li>
<li>Finished: {_e(r['finished_at'])}</li>
{tools}</ul>
<h2>Findings by Severity</h2>
<table><tr><th>Severity</th><th>Count</th></tr>{sev_rows}</table>
<h2>Findings by Rule</h2>
<table><tr><th>Rule</th><th>Severity</th><th>Count</th><th>Title</th></tr>{rule_rows}</table>
<h2>Top Affected Files/Services</h2>
<table><tr><th>File/Service</th><th>Count</th></tr>{file_rows}</table>
<h2>Risk Summary (mock)</h2>
<p>Score {r['risk']['score']} / level {_e(r['risk']['level'])} using the temporary mock scoring model.</p>
<h2>Migration Summary (mock placeholder)</h2>
<ul>{rec_items}</ul>
<p><em>Risk and migration sections are mock/placeholder output pending Person 1's real engine.</em></p>
</body>
</html>"""
