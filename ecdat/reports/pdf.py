"""ECDAT Concise PDF Report Renderer (ReportLab Platypus).

Deliberately concise: page count scales with distinct algorithms and
rules, never with the raw finding count, so even very large scans
(e.g. OpenSSL-scale, thousands of findings) stay a short document:

  Page 1  Title + overview (mirrors the GUI result header)
  Page 2+ Cryptographic inventory (every algorithm, uncapped) +
          grouped operations summary (one row per algorithm x type)
  Next    Migration recommendations (one bullet per deduped action:
          "14 RSA findings -> 1 point")
  Next    Findings summary (one row per finding group, not per
          occurrence) + scan coverage appendix.

Per-occurrence detail lives in the HTML/CSV/JSON exports. Only
``reportlab`` is required (pure pip install, no system libraries).
Output bytes are deterministic: PDF dates and document ID are pinned
so golden tests stay byte-stable.
"""

from __future__ import annotations

import io
import re
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    HRFlowable,
    KeepTogether,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Frame,
    PageBreak,
)

# ─── Theme ──────────────────────────────────────────────────────────────
PRIMARY = colors.HexColor("#1a3a5c")
ACCENT = colors.HexColor("#4a2c6e")
MUTED = colors.HexColor("#666677")
LIGHT_LINE = colors.HexColor("#d8dce2")
ALT_ROW = colors.HexColor("#f2f4f8")
WHITE = colors.white
BLACK = colors.HexColor("#1a1a2e")

SEV_HEX = {
    "critical": "#d92626",
    "high": "#eb5a17",
    "medium": "#c78d0d",
    "low": "#17a34a",
    "info": "#2661bf",
}

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

MARGIN = 16 * mm
PAGE_W, PAGE_H = A4

# Fixed PDF metadata so output bytes are deterministic across runs.
FIXED_DATE = "D:20260101000000Z"
FIXED_ID = "ECDAT0000000000000000000000000000"

# ─── Sanitising (ASCII-fold; Helvetica is WinAnsi) ──────────────────────
_FOLD = {
    "\u2013": "-", "\u2014": "-", "\u2212": "-",
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    "\u2022": "-", "\u00b7": "-", "\u25cf": "-", "\u25cb": "-",
    "\u2713": "Yes", "\u2714": "Yes", "\u2717": "No", "\u2718": "No",
    "\u2192": "->", "\u2190": "<-", "\u2500": "-", "\u2502": "|",
    "\u250c": "+", "\u2510": "+", "\u2514": "+", "\u2518": "+",
    "\u253c": "+", "\u2501": "=", "\u2503": "|",
    "\u2588": "#", "\u2591": "-", "\u2592": "-", "\u2593": "-",
    "\u2026": "...", "\u00a0": " ", "\u200b": "",
    "\u00e0": "a", "\u00e1": "a", "\u00e2": "a", "\u00e4": "a", "\u00e5": "a",
    "\u00e8": "e", "\u00e9": "e", "\u00ea": "e", "\u00eb": "e",
    "\u00ec": "i", "\u00ed": "i", "\u00ee": "i", "\u00ef": "i",
    "\u00f2": "o", "\u00f3": "o", "\u00f4": "o", "\u00f6": "o",
    "\u00f9": "u", "\u00fa": "u", "\u00fb": "u", "\u00fc": "u",
    "\u00fd": "y", "\u00ff": "y", "\u00f1": "n", "\u00e7": "c",
    "\u00c0": "A", "\u00c1": "A", "\u00c2": "A", "\u00c4": "A",
    "\u00c8": "E", "\u00c9": "E", "\u00ca": "E", "\u00cb": "E",
    "\u00cc": "I", "\u00cd": "I", "\u00ce": "I", "\u00cf": "I",
    "\u00d2": "O", "\u00d3": "O", "\u00d4": "O", "\u00d6": "O",
    "\u00d9": "U", "\u00da": "U", "\u00db": "U", "\u00dc": "U",
    "\u00d1": "N", "\u00c7": "C",
}


def _clean(value: Any, limit: int = 0) -> str:
    try:
        text = str(value if value is not None else "")
    except Exception:
        return ""
    for uni, rep in _FOLD.items():
        if uni in text:
            text = text.replace(uni, rep)
    out = "".join(ch if 32 <= ord(ch) < 127 else (" " if ch in ("\t",) else "?")
                  for ch in text)
    out = re.sub(r"\s+", " ", out).strip()
    return out[:limit].strip() if limit else out


def _fmt_date(value: Any) -> str:
    try:
        text = str(value or "").strip()
        if not text:
            return "Not recorded"
        return datetime.fromisoformat(text.replace("Z", "+00:00")).strftime("%d %B %Y")
    except Exception:
        return _clean(value) or "Not recorded"


def _sev(value: Any) -> str:
    sev = _clean(value).lower() or "info"
    return sev if sev in SEV_HEX else "info"


def _sev_tag(sev: str) -> str:
    label = "INFORMATIONAL" if sev == "info" else sev.upper()
    return f'<font color="{SEV_HEX[sev]}"><b>[{label}]</b></font>'


# ─── Styles ─────────────────────────────────────────────────────────────
def _styles() -> dict[str, ParagraphStyle]:
    base = {"fontName": "Helvetica", "textColor": BLACK}
    cell = ParagraphStyle("cell", fontSize=8, leading=10.5, **base)
    return {
        "cover_brand": ParagraphStyle("cover_brand", fontName="Helvetica-Bold",
                                      fontSize=30, leading=32, textColor=WHITE),
        "cover_sub": ParagraphStyle("cover_sub", fontName="Helvetica",
                                    fontSize=11, leading=14, textColor=colors.HexColor("#e6e6f0")),
        "cover_report": ParagraphStyle("cover_report", fontName="Helvetica-Bold",
                                       fontSize=13, leading=16, textColor=WHITE),
        "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=15,
                             leading=18, textColor=PRIMARY, spaceBefore=26, spaceAfter=6),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11.5,
                             leading=14, textColor=PRIMARY, spaceBefore=14, spaceAfter=5),
        "body": ParagraphStyle("body", fontSize=9.5, leading=13.5, **base),
        "small": ParagraphStyle("small", fontSize=8.5, leading=11.5,
                                textColor=MUTED, **{k: v for k, v in base.items()
                                                    if k not in ("textColor", "leading")}),
        "cell": cell,
        "cell_h": ParagraphStyle("cell_h", parent=cell, fontName="Helvetica-Bold",
                                 textColor=WHITE),
        "cell_small": ParagraphStyle("cell_small", fontSize=7.5, leading=10, **base),
        "bullet": ParagraphStyle("bullet", fontSize=9.5, leading=13.5,
                                 leftIndent=18, firstLineIndent=0,
                                 spaceBefore=1, spaceAfter=3, **base),
    }


def _p(style: ParagraphStyle, text: str) -> Paragraph:
    return Paragraph(_clean(text) or "-", style)


def _px(style: ParagraphStyle, markup: str) -> Paragraph:
    """Paragraph where markup (<b>/<font>) is trusted; text already cleaned."""
    return Paragraph(markup, style)


def _hr() -> HRFlowable:
    return HRFlowable(width="100%", thickness=1.2, color=ACCENT,
                      spaceBefore=2, spaceAfter=8)


def _bullets(markups: list[str]) -> list[Paragraph]:
    """Hanging bullets via Paragraph <bullet> (keeps marker on text line)."""
    return [Paragraph(f"<bullet>&bull;</bullet>{m}", S["bullet"]) for m in markups]


def _table(headers: list[str], rows: list[list[Paragraph]],
           widths: list[float], header_bg: Any = PRIMARY) -> Table:
    data = [[Paragraph(f"<b>{_xml_escape(h)}</b>", S["cell_h"]) for h in headers]]
    data.extend(rows)
    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, LIGHT_LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ])
    if len(data) > 1:
        style.add("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, ALT_ROW])
    return Table(data, colWidths=widths, repeatRows=1, style=style)


# ─── Header / footer ────────────────────────────────────────────────────
def _header_footer(canvas: Any, doc: Any) -> None:
    canvas.saveState()
    if doc.page > 1:
        canvas.setStrokeColor(PRIMARY)
        canvas.setLineWidth(1.2)
        canvas.line(MARGIN, PAGE_H - MARGIN + 8, PAGE_W - MARGIN, PAGE_H - MARGIN + 8)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(PRIMARY)
        canvas.drawString(MARGIN, PAGE_H - MARGIN + 12, "ECDAT Cryptographic Risk Report")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - MARGIN + 12, str(doc.page))
    canvas.setStrokeColor(LIGHT_LINE)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, MARGIN - 12, PAGE_W - MARGIN, MARGIN - 12)
    canvas.setFont("Helvetica-Oblique", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(MARGIN, MARGIN - 22, "CONFIDENTIAL - ECDAT Cryptographic Analysis")
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(PAGE_W - MARGIN, MARGIN - 22, f"Page {doc.page}")
    canvas.restoreState()


def _cover_bg(canvas: Any, doc: Any) -> None:
    _header_footer(canvas, doc)
    if doc.page == 1:
        canvas.saveState()
        canvas.setFillColor(PRIMARY)
        canvas.rect(0, PAGE_H - 132, PAGE_W, 132, stroke=0, fill=1)
        canvas.setFillColor(ACCENT)
        canvas.rect(0, PAGE_H - 134, PAGE_W, 2, stroke=0, fill=1)
        canvas.restoreState()


# ─── Sections ───────────────────────────────────────────────────────────
def _title_block(r: dict) -> list:
    target = _clean(r.get("display_target") or r.get("target") or "Unknown Target")
    scan_id = _clean(r.get("scan_id"))
    cov = r.get("coverage_summary", {}) if isinstance(r.get("coverage_summary"), dict) else {}
    profile = _clean(cov.get("profile", "standard")).title() or "Standard"
    scan_date = _fmt_date(r.get("finished_at") or r.get("started_at"))

    assets = int(r.get("asset_count", 0) or 0)
    ops = int(r.get("operation_count", 0) or 0)
    findings = int(r.get("finding_count", 0) or 0)
    by_sev = r.get("by_severity", {}) if isinstance(r.get("by_severity"), dict) else {}
    high = int(by_sev.get("critical", 0) or 0) + int(by_sev.get("high", 0) or 0)

    story: list = [
        Spacer(1, 34),
        Paragraph("ECDAT", S["cover_brand"]),
        Paragraph("Cryptographic Discovery &amp; Quantum Risk Analysis", S["cover_sub"]),
        Spacer(1, 4),
        Paragraph("SECURITY SCAN REPORT", S["cover_report"]),
        Spacer(1, 26),
    ]
    meta = [
        [_px(S["body"], "<b>Target:</b>"),
         _p(S["body"], target)],
        [_px(S["body"], "<b>Scan type:</b>"), _p(S["body"], f"{profile} scan")],
        [_px(S["body"], "<b>Scan date:</b>"), _p(S["body"], scan_date)],
        [_px(S["body"], "<b>Scan ID:</b>"), _p(S["cell_small"], scan_id or "Not recorded")],
    ]
    story.append(Table(meta, colWidths=[70, PAGE_W - 2 * MARGIN - 70],
                       style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                         ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                         ("BOTTOMPADDING", (0, 0), (-1, -1), 3)])))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=0.5, color=LIGHT_LINE,
                            spaceBefore=2, spaceAfter=8))
    stats = [[_px(S["body"], f"<b><font size=16>{v}</font></b><br/><font color=\"#666677\" size=8>{k}</font>")
              for k, v in [(f"{assets}", "CRYPTOGRAPHIC ASSETS"),
                           (f"{ops}", "OPERATIONS")]],
             [_px(S["body"], f"<b><font size=16>{v}</font></b><br/><font color=\"#666677\" size=8>{k}</font>")
              for k, v in [(f"{findings}", "FINDINGS"),
                           (f"{high}", "HIGH RISK")]]]
    story.append(Table(stats, colWidths=[(PAGE_W - 2 * MARGIN) / 2] * 2,
                       style=TableStyle([("GRID", (0, 0), (-1, -1), 0.4, LIGHT_LINE),
                                         ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                         ("TOPPADDING", (0, 0), (-1, -1), 6),
                                         ("BOTTOMPADDING", (0, 0), (-1, -1), 6)])))
    story.append(Spacer(1, 6))
    story.append(_p(S["small"], "ECDAT v1.0"))
    story.append(PageBreak())
    return story


def _overview(r: dict) -> list:
    story: list = [_p(S["h1"], "1. Executive Summary"), _hr()]
    risk = r.get("risk", {}) if isinstance(r.get("risk"), dict) else {}
    try:
        score = float(risk.get("score", 0.0) or 0.0)
    except (TypeError, ValueError):
        score = 0.0
    level = _clean(risk.get("level", "none")).upper() or "NONE"
    summary = _clean(r.get("summary"))
    if summary:
        story.append(_p(S["body"], summary))
        story.append(Spacer(1, 4))

    assets = int(r.get("asset_count", 0) or 0)
    ops = int(r.get("operation_count", 0) or 0)
    findings = int(r.get("finding_count", 0) or 0)
    by_sev = r.get("by_severity", {}) if isinstance(r.get("by_severity"), dict) else {}
    high = int(by_sev.get("critical", 0) or 0) + int(by_sev.get("high", 0) or 0)
    medium = int(by_sev.get("medium", 0) or 0)
    story.append(_p(S["h2"], "Overall risk"))
    story.append(_px(S["body"], f"<b>{_xml_escape(level)}</b> &nbsp; Risk score: <b>{score:.1f} / 10</b>"))
    story.append(_p(S["h2"], "Counts"))
    bullets = [
        f"{assets} cryptographic assets",
        f"{ops} cryptographic operations",
        f"{findings} security findings ({high} high-risk, {medium} medium-risk)",
    ]
    story.extend(_bullets([_xml_escape(b) for b in bullets]))
    story.append(_p(S["h2"], "Severity breakdown"))
    order = ["critical", "high", "medium", "low", "info"]
    if not by_sev:
        story.append(_p(S["body"], "No findings recorded."))
    else:
        sev_line = " &nbsp; ".join(
            f"{_sev_tag(s)}: {int(by_sev.get(s, 0) or 0)}"
            for s in order if s in by_sev)
        story.append(_px(S["body"], sev_line))
    story.append(_p(S["h2"], "Top risk contributors"))
    top = [t for t in (r.get("top_risks", []) or []) if isinstance(t, dict)][:5]
    if not top:
        story.append(_p(S["body"], "No risk-scored operations."))
    else:
        items = []
        for t in top:
            algo = _clean(t.get("algorithm", "UNKNOWN"))
            try:
                sc = float(t.get("score", 0.0) or 0.0)
            except (TypeError, ValueError):
                sc = 0.0
            loc = _clean(t.get("file", ""))
            line = t.get("line", 0)
            try:
                loc = f"{loc}:{int(line)}" if loc and int(line) else loc
            except (TypeError, ValueError):
                pass
            items.append(f"{_sev_tag(_sev(t.get('severity', t.get('class'))))} "
                         f"<b>{_xml_escape(algo)}</b> ({sc:.1f})"
                         + (f" — {_xml_escape(loc)}" if loc else ""))
        story.extend(_bullets(items))
    return story


def _inventory(r: dict, content_w: float) -> list:
    story: list = [_p(S["h1"], "2. Cryptographic Inventory"), _hr(),
                   _p(S["small"], "What cryptography exists in this system? Every detected "
                                  "algorithm is listed — the table is never truncated.")]
    inv = [x for x in (r.get("inventory", []) or []) if isinstance(x, dict)]
    confirmed = [x for x in inv if x.get("confirmed")]
    caps = [x for x in inv if not x.get("confirmed")]
    if not confirmed:
        story.append(_p(S["body"], "No confirmed cryptographic use detected."))
    else:
        rows = []
        for row in confirmed:
            sev = _sev(row.get("risk", "info"))
            rows.append([
                _p(S["cell"], row.get("algorithm", "")),
                _p(S["cell"], row.get("type", "")),
                _p(S["cell"], str(row.get("confirmed_uses", row.get("uses", 0)))),
                _p(S["cell"], str(row.get("file_count", 0))),
                _px(S["cell"], _sev_tag(sev)),
                _p(S["cell_small"], (row.get("migration", "") or ""), ),
            ])
        story.append(_table(["Algorithm", "Type", "Uses", "Files", "Risk", "Migration guidance"],
                            rows, [86, 56, 32, 32, 78, content_w - 284]))
        story.append(Spacer(1, 8))
    if caps:
        names = ", ".join(_clean(x.get("algorithm", "")) for x in caps)
        story.append(Spacer(1, 6))
        story.append(_px(S["small"], f"<b>Declared capabilities without confirmed use "
                                     f"({len(caps)}):</b> {_xml_escape(names)}"))
    story.append(_p(S["h2"], "Operations summary (grouped)"))
    rollup = [x for x in (r.get("operations_rollup", []) or []) if isinstance(x, dict)]
    if not rollup:
        story.append(_p(S["body"], "No confirmed operations recorded."))
    else:
        rows = []
        for row in rollup:
            conf = row.get("max_confidence")
            conf_s = f"{float(conf) * 100:.0f}%" if isinstance(conf, (int, float)) else "-"
            try:
                score_s = f"{float(row.get('max_score', 0.0) or 0.0):.1f}"
            except (TypeError, ValueError):
                score_s = "-"
            rows.append([
                _p(S["cell"], row.get("algorithm", "")),
                _p(S["cell"], row.get("operation_type", "")),
                _p(S["cell"], f"{row.get('count', 0)} ({row.get('confirmed_count', 0)} confirmed)"),
                _p(S["cell"], str(row.get("file_count", 0))),
                _p(S["cell"], score_s),
                _p(S["cell"], conf_s),
            ])
        story.append(_table(["Algorithm", "Operation", "Occurrences", "Files", "Top score", "Top conf."],
                            rows, [110, 80, 110, 40, 60, 60]))
        story.append(Spacer(1, 8))
    return story


def _first_sentence(action: str) -> str:
    action = _clean(action)
    if not action:
        return ""
    parts = re.split(r"\.\s+", action, maxsplit=1)
    return (parts[0].strip() + ".") if len(parts) == 2 else action


def _migration(r: dict) -> list:
    story: list = [_p(S["h1"], "3. Migration Recommendations"), _hr(),
                   _p(S["small"], "One point per affected rule — e.g. 14 RSA findings "
                                  "produce a single migration point. Ordered by severity.")]
    actions = [a for a in (r.get("migration_actions", []) or []) if isinstance(a, dict)]
    if not actions:
        groups = r.get("migration_groups", {}) if isinstance(r.get("migration_groups"), dict) else {}
        for name in ("Immediate", "High priority", "Planned", "Informational"):
            for item in (groups.get(name, []) or []):
                if isinstance(item, dict):
                    actions.append(item)
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    actions.sort(key=lambda a: (rank.get(_sev(a.get("severity", "info")), 5),
                                _clean(a.get("title", ""))))
    if not actions:
        story.append(_p(S["body"], "No migration actions required."))
        return story
    items = []
    for rec in actions:
        sev = _sev(rec.get("severity", "info"))
        title = _clean(rec.get("title") or rec.get("rule_id") or "Migration action")
        try:
            count = int(rec.get("count", 1) or 1)
        except (TypeError, ValueError):
            count = 1
        files = rec.get("affected_files", []) or []
        n_files = len(files) if isinstance(files, list) else 0
        lead = _first_sentence(rec.get("action", "")) or title
        items.append(f"{_sev_tag(sev)} <b>{_xml_escape(title)}</b> — "
                     f"{_xml_escape(lead)} "
                     f"<font color=\"#666677\">(x{count} in {n_files} file(s))</font>")
    story.extend(_bullets(items))
    return story


def _findings(r: dict, content_w: float) -> list:
    story: list = [_p(S["h1"], "4. Findings Summary"), _hr(),
                   _p(S["small"], "One row per finding group (rule x severity) — covers every "
                                  "finding without growing per occurrence. Per-occurrence detail "
                                  "is in the HTML/CSV/JSON exports.")]
    groups = [g for g in (r.get("finding_groups", []) or []) if isinstance(g, dict)]
    if not groups:
        story.append(_p(S["body"], "No findings to summarize."))
        return story
    rows = []
    for g in groups:
        occs = [o for o in (g.get("occurrences", []) or []) if isinstance(o, dict)]
        top_loc = ""
        if occs:
            first = occs[0]
            top_loc = _clean(first.get("file", ""))
            try:
                ln = int(first.get("line", 0) or 0)
                if ln:
                    top_loc = f"{top_loc}:{ln}"
            except (TypeError, ValueError):
                pass
        rows.append([
            _px(S["cell"], _sev_tag(_sev(g.get("severity", "info")))),
            _p(S["cell"], g.get("rule_id", "")),
            _p(S["cell"], g.get("title", "")),
            _p(S["cell"], str(g.get("count", 0))),
            _p(S["cell"], str(g.get("file_count", 0))),
            _p(S["cell_small"], top_loc or "-"),
        ])
    story.append(_table(["Severity", "Rule", "Title", "Occ.", "Files", "Top location"],
                        rows, [78, 70, content_w - 318, 36, 36, 98]))
    story.append(Spacer(1, 8))
    return story


def _coverage(r: dict) -> list:
    story: list = [_p(S["h1"], "5. Scan Coverage"), _hr()]
    cov = r.get("coverage_summary", {}) if isinstance(r.get("coverage_summary"), dict) else {}
    method = r.get("methodology", {}) if isinstance(r.get("methodology"), dict) else {}
    lim = r.get("limitations", {}) if isinstance(r.get("limitations"), dict) else {}
    discovered = int(cov.get("files_discovered", r.get("files_scanned", 0)) or 0)
    analyzed = int(cov.get("files_analyzed", r.get("files_scanned", 0)) or 0)
    skipped = int(cov.get("files_skipped", 0) or 0)
    no_ev = int(cov.get("files_without_evidence", 0) or 0)
    profile = _clean(cov.get("profile") or method.get("profile") or "standard")
    elapsed = cov.get("elapsed_sec") or method.get("elapsed_sec") or "?"
    cache = "hit" if (cov.get("cache_hit") or method.get("cache_hit")) else "miss"
    story.append(_px(S["body"], f"<b>Coverage: {analyzed} / {discovered} files</b> "
                                f"(profile: {_xml_escape(profile)}; cache: {cache}; "
                                f"elapsed: {_xml_escape(str(elapsed))}s)"))
    story.append(_p(S["body"], f"Skipped: {skipped} file(s) before analysis; "
                               f"{no_ev} file(s) analyzed with no cryptographic evidence."))
    buckets = cov.get("skipped_by_bucket", {}) or {}
    if isinstance(buckets, dict) and buckets:
        story.append(KeepTogether([
            _p(S["h2"], "Skipped by reason"),
            *_bullets([_xml_escape(f"{reason}: {count}")
                       for reason, count in sorted(buckets.items(),
                                                   key=lambda kv: (-kv[1], kv[0]))[:10]]),
        ]))
    notes = []
    for key in ("unavailable_tools", "permission_gated", "failed_scanners"):
        vals = lim.get(key, []) or cov.get(key, []) or []
        if vals and isinstance(vals, list):
            notes.append(f"{key.replace('_', ' ').title()}: {', '.join(_clean(v) for v in vals)}")
    tools = method.get("tool_versions", {}) or {}
    if isinstance(tools, dict) and tools:
        notes.append("Detectors: " + ", ".join(
            f"{_clean(k)} {_clean(v)}" for k, v in sorted(tools.items())))
    status = method.get("scanner_status", {}) or {}
    if isinstance(status, dict) and status:
        notes.append("Scanner outcomes: " + ", ".join(
            f"{_clean(k)}: {_clean(v)}" for k, v in sorted(status.items())))
    notes.append(f"Risk source: {_clean(method.get('risk_source', ''))}; "
                 f"registry: {_clean(method.get('registry_version', ''))}; "
                 f"scan: {_clean(r.get('scan_id', ''))}")
    story.append(_p(S["h2"], "Methodology notes"))
    story.append(KeepTogether(_bullets([_xml_escape(n) for n in notes if n])))
    return story


# ─── Assembly ───────────────────────────────────────────────────────────
S: dict[str, ParagraphStyle] = {}


def _normalize(raw: bytes) -> bytes:
    """Pin dates + document ID so output is deterministic."""
    out = re.sub(rb"/CreationDate\s*\(D:[^)]*\)", b"/CreationDate (" + FIXED_DATE.encode() + b")", raw)
    out = re.sub(rb"/ModDate\s*\(D:[^)]*\)", b"/ModDate (" + FIXED_DATE.encode() + b")", out)
    out = re.sub(rb"/ID\s*\[[^\]]*\]", b"/ID [<" + FIXED_ID.encode() + b"><" + FIXED_ID.encode() + b">]", out)
    return out


def to_pdf_bytes(report: dict) -> bytes:
    """Render the report as concise PDF bytes (ReportLab Platypus)."""
    global S
    S = _styles()
    r = report if isinstance(report, dict) else {}
    content_w = PAGE_W - 2 * MARGIN

    story: list = []
    story.extend(_title_block(r))
    story.extend(_overview(r))
    story.extend(_inventory(r, content_w))
    story.extend(_migration(r))
    story.extend(_findings(r, content_w))
    story.extend(_coverage(r))

    buf = io.BytesIO()
    frame = Frame(MARGIN, MARGIN, content_w, PAGE_H - 2 * MARGIN, id="main")
    template = PageTemplate(id="page", frames=[frame], onPage=_cover_bg)
    doc = BaseDocTemplate(buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
                          topMargin=MARGIN, bottomMargin=MARGIN,
                          title=f"ECDAT Report: {_clean(r.get('scan_id', ''))}",
                          author="ECDAT", pageCompression=0)
    doc.addPageTemplates([template])
    doc.build(story)
    raw = buf.getvalue()
    if not raw.startswith(b"%PDF-1.4"):
        raw = b"%PDF-1.4\n" + raw.split(b"\n", 1)[1] if b"\n" in raw else raw
    return _normalize(raw)
