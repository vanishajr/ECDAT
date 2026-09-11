"""Benchmark HTML + CSV renderers (Person 3 platform layer).

Presentation only, over the Task 20 canonical report model:

    Benchmark execution -> Canonical report (report.build_report)
        -> Renderer (this module) -> HTML / CSV

Renderers NEVER rerun predictions or evaluation, compute no
metrics, touch no SQLite, and call no P1/P2 code — they present
whatever the report already says, including None/unavailable and
synthetic/mock labels, verbatim.

Conventions follow the existing project renderers
(`reports/html.py`, `exports/csv_gen.py`): stdlib only, pure
functions, no trailing newline (callers add it), "" for None in
CSV, html.escape(quote=True) for every interpolated value, fully
self-contained offline output with no external resources.
"""

from __future__ import annotations

import csv
import html
import io

# Canonical metric column order, shared by HTML tables and CSV.
METRIC_COLUMNS: tuple[str, ...] = (
    "precision", "recall", "f1", "accuracy", "fpr", "fnr", "specificity",
)

MOCK_WARNING = (
    "Synthetic/mock benchmark execution — not a real ECDAT accuracy claim."
)


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _num(value: object) -> str:
    """Cell text for a metric/count: raw value, never 0 for None."""
    return "n/a" if value is None else str(value)


def _bool(value: bool) -> str:
    return "true" if value else "false"


def _unavailable_text(unavailable: dict | None) -> str:
    if not unavailable:
        return ""
    return "; ".join(f"{k}: {v}" for k, v in sorted(unavailable.items()))


# --- HTML ----------------------------------------------------------------------


def _metric_rows(metrics: dict) -> str:
    order = ["tp", "fp", "tn", "fn", *METRIC_COLUMNS]
    rows = []
    for key in order:
        value = metrics.get(key)
        reason = (metrics.get("unavailable") or {}).get(key, "")
        rows.append(
            f"<tr><td>{_e(key)}</td><td>{_e(_num(value))}</td>"
            f"<td>{_e(reason)}</td></tr>")
    return "".join(rows)


def render_html(report: dict) -> str:
    """Render the canonical report as self-contained offline HTML."""
    sel = report["selection"]
    scope = ", ".join(
        f"{k}={v}" for k, v in
        (("group", sel["group"]), ("case_ids", sel["case_ids"]))
        if v is not None) or "full suite"
    group_rows = "".join(
        "<tr>" + "".join(
            f"<td>{_e(cell)}</td>" for cell in
            (g["group"], g["cases"], g["evaluated"], g["failed"],
             g["counts"]["tp"], g["counts"]["fp"],
             _num(g["counts"]["tn"]), g["counts"]["fn"],
             *(_num(g["metrics"][m]) for m in METRIC_COLUMNS))) + "</tr>"
        for g in report["groups"])
    case_rows = "".join(
        "<tr>" + "".join(
            f"<td>{_e(cell)}</td>" for cell in
            (c["case_id"], c["group"], c["title"], c["status"],
             _bool(c["synthetic"]),
             _num(c["predicted_n"]) if c["status"] == "evaluated" else "n/a",
             *(str(c["counts"][k]) if c["counts"] is not None and
               c["counts"][k] is not None else "n/a"
               for k in ("tp", "fp", "tn", "fn")),
             *(_num(c["metrics"][m]) if c["metrics"] is not None else "n/a"
               for m in METRIC_COLUMNS),
             c["error"] or "")) + "</tr>"
        for c in report["cases"])
    failure_rows = "".join(
        f"<tr><td>{_e(f['case_id'])}</td><td>{_e(f['group'])}</td>"
        f"<td>{_e(f['error'])}</td></tr>"
        for f in report["failures"])
    unavailable_rows = "".join(
        f"<tr><td>{_e(scope_)}</td><td>{_e(metric)}</td>"
        f"<td>{_e(reason)}</td></tr>"
        for scope_, metrics in (
            ("overall", report["unavailable"]["overall"]),
            *((f"group:{g}", r) for g, r in
              report["unavailable"]["by_group"].items()))
        for metric, reason in sorted(metrics.items()))
    perf = report["performance"]
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ECDAT Benchmark Report: {_e(report['suite_id'])}</title>
<style>body{{font-family:sans-serif;max-width:70em;margin:2em auto;padding:0 1em}}table{{border-collapse:collapse}}th,td{{border:1px solid #999;padding:.3em .6em;text-align:left}}.warn{{border:2px solid #a00;background:#fee;padding:.6em 1em}}</style>
</head>
<body>
<h1>ECDAT Benchmark Report: {_e(report['suite_id'])} v{_e(report['suite_version'])}</h1>
<p class="warn"><b>{_e(MOCK_WARNING)}</b> Provider: {_e(report['provider'])} ({_e(report['provider_type'])}){_e(", all cases synthetic" if report['synthetic'] else "")}.</p>
<h2>1. Benchmark overview</h2>
<ul>
<li>Report: {_e(report['report'])} v{_e(report['report_version'])} (run {_e(report['run_id'])})</li>
<li>Cases: {_e(report['case_count'])} total, {_e(report['evaluated_n'])} evaluated, {_e(report['failed_n'])} failed</li>
</ul>
<h2>2. Provider / execution mode</h2>
<ul>
<li>Provider: {_e(report['provider'])} (type: {_e(report['provider_type'])})</li>
<li>Engine: {_e(report['engine'])}</li>
</ul>
<h2>3. Selection summary</h2>
<p>{_e(scope)} — resolved: {_e(", ".join(sel['resolved'])) or _e("none")}</p>
<h2>4. Overall metrics</h2>
<table><tr><th>Metric</th><th>Value</th><th>Unavailable reason</th></tr>{_metric_rows(report['overall']['metrics'])}</table>
<h2>5. Per-group results</h2>
<table><tr><th>Group</th><th>Cases</th><th>Evaluated</th><th>Failed</th><th>TP</th><th>FP</th><th>TN</th><th>FN</th><th>Precision</th><th>Recall</th><th>F1</th><th>Accuracy</th><th>FPR</th><th>FNR</th><th>Specificity</th></tr>{group_rows or "<tr><td colspan='15'>No groups.</td></tr>"}</table>
<h2>6. Per-case results</h2>
<table><tr><th>Case</th><th>Group</th><th>Title</th><th>Status</th><th>Synthetic</th><th>Predicted</th><th>TP</th><th>FP</th><th>TN</th><th>FN</th><th>Precision</th><th>Recall</th><th>F1</th><th>Accuracy</th><th>FPR</th><th>FNR</th><th>Specificity</th><th>Error</th></tr>{case_rows or "<tr><td colspan='18'>No cases.</td></tr>"}</table>
<h2>7. Failures</h2>
<table><tr><th>Case</th><th>Group</th><th>Error</th></tr>{failure_rows or "<tr><td colspan='3'>No failures.</td></tr>"}</table>
<h2>8. Unavailable metrics</h2>
<table><tr><th>Scope</th><th>Metric</th><th>Reason</th></tr>{unavailable_rows or "<tr><td colspan='3'>None — all metrics computable.</td></tr>"}</table>
<h2>9. Performance / resources (measured)</h2>
<ul>
<li>Wall time: {_e(perf['elapsed_s'])}s</li>
<li>CPU: {_e(_num(perf['cpu_s']))}s</li>
<li>Peak RSS: {_e(_num(perf['peak_rss_bytes']))} bytes</li>
<li>Note: {_e(perf['resources_note'])}</li>
</ul>
<h2>10. Disclaimer / synthetic status</h2>
<p><em>{_e(report['note'])}</em></p>
</body>
</html>"""


# --- CSV --------------------------------------------------------------------------
# One valid standalone CSV per logical table (section name -> text),
# mirroring the existing multi-artifact file naming in __main__.py
# ("<stem>-<section>.csv"). None renders as "" with reasons kept in
# explicit unavailable columns — never as zero.


def _dump(header: list[str], rows: list[list[object]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow(["" if v is None else v for v in row])
    return buf.getvalue().rstrip("\n")


def render_csv_sections(report: dict) -> dict[str, str]:
    """Render overall/groups/cases/failures as standalone CSV texts."""
    overall_header = ["metric", "value", "unavailable_reason"]
    overall_rows = [[k, report["overall"]["counts"].get(k), ""]
                    for k in ("tp", "fp", "tn", "fn")]
    overall_rows += [[m, report["overall"]["metrics"].get(m),
                      (report["overall"]["metrics"].get("unavailable") or {}).get(m, "")]
                     for m in METRIC_COLUMNS]
    groups_header = (["group", "cases", "evaluated", "failed",
                      "tp", "fp", "tn", "fn", *METRIC_COLUMNS, "unavailable"])
    groups_rows = [[g["group"], g["cases"], g["evaluated"], g["failed"],
                    g["counts"]["tp"], g["counts"]["fp"], g["counts"]["tn"],
                    g["counts"]["fn"],
                    *(g["metrics"][m] for m in METRIC_COLUMNS),
                    _unavailable_text(g["unavailable"]) or None]
                   for g in report["groups"]]
    cases_header = (["case_id", "group", "title", "status", "synthetic",
                     "predicted_n", "tp", "fp", "tn", "fn",
                     *METRIC_COLUMNS, "unavailable", "error"])
    cases_rows = []
    for c in report["cases"]:
        if c["status"] == "failed":
            cases_rows.append([c["case_id"], c["group"], c["title"],
                               c["status"], _bool(c["synthetic"]),
                               None, None, None, None, None,
                               *[None for _ in METRIC_COLUMNS],
                               None, c["error"]])
        else:
            cases_rows.append([c["case_id"], c["group"], c["title"],
                               c["status"], _bool(c["synthetic"]),
                               c["predicted_n"],
                               c["counts"]["tp"], c["counts"]["fp"],
                               c["counts"]["tn"], c["counts"]["fn"],
                               *(c["metrics"][m] for m in METRIC_COLUMNS),
                               _unavailable_text(c["unavailable"]) or None,
                               None])
    failures_rows = [[f["case_id"], f["group"], f["error"]]
                     for f in report["failures"]]
    return {
        "overall": _dump(overall_header, overall_rows),
        "groups": _dump(groups_header, groups_rows),
        "cases": _dump(cases_header, cases_rows),
        "failures": _dump(["case_id", "group", "error"], failures_rows),
    }
