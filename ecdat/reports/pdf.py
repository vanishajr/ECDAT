"""ECDAT Professional PDF Report Renderer.

Premium, modern cybersecurity report with ECDAT visual identity:
- Light/off-white background, dark typography
- Subtle ECDAT blue (#1a3a5c) + purple (#4a2c6e) accents
- Clean, spacious layout with strong visual hierarchy
- Professional tables, headers/footers, page numbers
- Proper wrapping, page breaks, no clipping/overlapping
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass
from typing import Any

# ─── Page Geometry ──────────────────────────────────────────────────────
PAGE_W = 595.0
PAGE_H = 842.0
MARGIN = 50.0
CONTENT_W = PAGE_W - 2 * MARGIN
TOP_Y = PAGE_H - MARGIN
BOTTOM_Y = MARGIN

# ─── Color Palette (RGB 0-1) ────────────────────────────────────────────
@dataclass(frozen=True)
class Color:
    r: float; g: float; b: float
    def rgb(self) -> str: return f"{self.r:.3f} {self.g:.3f} {self.b:.3f}"

CLR = {
    "bg": Color(0.98, 0.985, 0.99),        # off-white background
    "text": Color(0.1, 0.1, 0.18),         # near-black
    "text_muted": Color(0.4, 0.4, 0.5),    # muted gray
    "primary": Color(0.1, 0.23, 0.36),     # ECDAT blue #1a3a5c
    "accent": Color(0.29, 0.17, 0.43),     # ECDAT purple #4a2c6e
    "line": Color(0.85, 0.87, 0.9),        # subtle lines
    "card_bg": Color(1.0, 1.0, 1.0),       # white cards
    "sev_crit": Color(0.86, 0.15, 0.15),   # critical
    "sev_high": Color(0.92, 0.35, 0.09),   # high
    "sev_med": Color(0.79, 0.54, 0.05),    # medium
    "sev_low": Color(0.09, 0.64, 0.29),    # low
    "sev_info": Color(0.15, 0.39, 0.75),   # info
}

SEV_COLOR = {
    "critical": CLR["sev_crit"], "high": CLR["sev_high"],
    "medium": CLR["sev_med"], "low": CLR["sev_low"], "info": CLR["sev_info"],
}

# ─── Font Helpers ───────────────────────────────────────────────────────
FONT = "Helvetica"
FONT_B = "Helvetica-Bold"
FONT_O = "Helvetica-Oblique"
FONT_BO = "Helvetica-BoldOblique"

def _esc(s: str) -> str:
    """Escape for PDF string literal."""
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

def _wrap(text: str, max_chars: int) -> list[str]:
    """Wrap text to max_chars, preserving word boundaries."""
    if not text:
        return [""]
    words = text.split()
    lines, cur = [], ""
    for w in words:
        if len(w) > max_chars:
            if cur:
                lines.append(cur); cur = ""
            for i in range(0, len(w), max_chars):
                lines.append(w[i:i+max_chars])
            continue
        cand = f"{cur} {w}".strip()
        if len(cand) <= max_chars:
            cur = cand
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines or [""]

# ─── Layout Primitives ──────────────────────────────────────────────────
@dataclass
class DrawCmd:
    """A drawing command for the content stream."""
    ops: str

class Canvas:
    """Accumulates PDF drawing commands for one page."""
    def __init__(self) -> None:
        self.cmds: list[DrawCmd] = []
        self.y = TOP_Y
        self.page_num = 1

    def add(self, ops: str) -> None:
        self.cmds.append(DrawCmd(ops))

    # --- Graphics State ---
    def save(self) -> None: self.add("q")
    def restore(self) -> None: self.add("Q")

    # --- Colors ---
    def set_fill(self, c: Color) -> None: self.add(f"{c.rgb()} rg")
    def set_stroke(self, c: Color) -> None: self.add(f"{c.rgb()} RG")

    # --- Rectangles ---
    def rect(self, x: float, y: float, w: float, h: float, fill: bool = True, stroke: bool = False) -> None:
        ops = f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re"
        if fill and stroke: ops += " B"
        elif fill: ops += " f"
        elif stroke: ops += " S"
        else: ops += " n"
        self.add(ops)

    def rounded_rect(self, x: float, y: float, w: float, h: float, r: float, fill: bool = True) -> None:
        # Approximate rounded rect with bezier curves
        k = 0.5522847498 * r
        ops = (
            f"{x+r:.2f} {y:.2f} m "
            f"{x+w-r:.2f} {y:.2f} l "
            f"{x+w-k:.2f} {y:.2f} {x+w:.2f} {y+k:.2f} {x+w:.2f} {y+r:.2f} c "
            f"{x+w:.2f} {y+h-r:.2f} l "
            f"{x+w:.2f} {y+h-k:.2f} {x+w-k:.2f} {y+h:.2f} {x+w-r:.2f} {y+h:.2f} c "
            f"{x+r:.2f} {y+h:.2f} l "
            f"{x+k:.2f} {y+h:.2f} {x:.2f} {y+h-k:.2f} {x:.2f} {y+h-r:.2f} c "
            f"{x:.2f} {y+r:.2f} l "
            f"{x:.2f} {y+k:.2f} {x+k:.2f} {y:.2f} {x+r:.2f} {y:.2f} c "
        )
        if fill: ops += " f"
        else: ops += " S"
        self.add(ops)

    # --- Lines ---
    def hline(self, x1: float, x2: float, y: float, w: float = 0.5) -> None:
        self.add(f"{w:.2f} w {x1:.2f} {y:.2f} m {x2:.2f} {y:.2f} l S")

    def vline(self, x: float, y1: float, y2: float, w: float = 0.5) -> None:
        self.add(f"{w:.2f} w {x:.2f} {y1:.2f} m {x:.2f} {y2:.2f} l S")

    # --- Text ---
    def text(self, x: float, y: float, text: str, font: str = FONT, size: float = 10, color: Color = CLR["text"]) -> None:
        self.set_fill(color)
        self.add(f"BT /{font} {size:.1f} Tf {x:.2f} {y:.2f} Td ({_esc(text)}) Tj ET")

    def text_wrap(self, x: float, y: float, text: str, width: float, font: str = FONT, size: float = 10,
                  color: Color = CLR["text"], leading: float = 1.3) -> float:
        """Draw wrapped text, return new y position."""
        chars_per_line = int(width / (size * 0.5))
        lines = _wrap(text, max(1, chars_per_line))
        self.set_fill(color)
        for i, line in enumerate(lines):
            self.add(f"BT /{font} {size:.1f} Tf {x:.2f} {y:.2f} Td ({_esc(line)}) Tj ET")
            y -= size * leading
        return y

    def text_right(self, x: float, y: float, text: str, font: str = FONT, size: float = 10, color: Color = CLR["text"]) -> None:
        self.set_fill(color)
        self.add(f"BT /{font} {size:.1f} Tf {x:.2f} {y:.2f} Td ({_esc(text)}) Tj ET")

    # --- Badge ---
    def badge(self, x: float, y: float, text: str, bg: Color, font_size: float = 7, padding: float = 4) -> tuple[float, float]:
        """Draw a rounded badge, return (width, height)."""
        tw = len(text) * font_size * 0.5 + 2 * padding
        th = font_size * 1.5
        self.save()
        self.set_fill(bg)
        self.rounded_rect(x, y - th + 2, tw, th, 3, fill=True)
        self.set_fill(Color(1, 1, 1))
        self.add(f"BT /{FONT_B} {font_size:.1f} Tf {x+padding:.2f} {y - th/2 - 1:.2f} Td ({_esc(text)}) Tj ET")
        self.restore()
        return tw, th

    # --- Table ---
    def table(self, x: float, y: float, col_widths: list[float], headers: list[str],
              rows: list[list[str]], font_size: float = 8,
              header_color: Color = CLR["primary"], alt_row: Color = Color(0.96, 0.97, 0.99),
              header_font: str = FONT_B, cell_font: str = FONT) -> float:
        """Draw a table, return new y position (bottom of table)."""
        row_h = font_size * 1.6
        # Header
        self.save()
        self.set_fill(header_color)
        self.rect(x, y - row_h, sum(col_widths), row_h, fill=True)
        self.set_fill(Color(1, 1, 1))
        cx = x
        for i, h in enumerate(headers):
            self.add(f"BT /{header_font} {font_size:.1f} Tf {cx+3:.2f} {y - row_h + 3:.2f} Td ({_esc(h)}) Tj ET")
            cx += col_widths[i]
        self.restore()
        y -= row_h
        # Rows
        for ri, row in enumerate(rows):
            if ri % 2 == 1:
                self.set_fill(alt_row)
                self.rect(x, y - row_h, sum(col_widths), row_h, fill=True)
            cx = x
            for ci, cell in enumerate(row):
                cw = col_widths[ci]
                cell_text = cell[:int(cw / (font_size * 0.5)) - 1]
                self.set_fill(CLR["text"])
                self.add(f"BT /{cell_font} {font_size:.1f} Tf {cx+3:.2f} {y - row_h + 3:.2f} Td ({_esc(cell_text)}) Tj ET")
                cx += cw
            y -= row_h
            # Grid line
            self.set_stroke(CLR["line"])
            self.hline(x, x + sum(col_widths), y, 0.3)
        # Outer border
        self.set_stroke(CLR["line"])
        self.rect(x, y, sum(col_widths), y + row_h * (len(rows) + 1) - y, stroke=True)
        return y

    def stream(self) -> bytes:
        return "\n".join(c.ops for c in self.cmds).encode("ascii")

# ─── Section Builder ────────────────────────────────────────────────────
class ReportBuilder:
    def __init__(self, report: dict):
        self.r = report
        self.pages: list[Canvas] = []
        self.current = Canvas()
        self.pages.append(self.current)

    def new_page(self) -> None:
        self.current = Canvas()
        self.current.page_num = len(self.pages) + 1
        self.pages.append(self.current)

    def need_space(self, h: float) -> None:
        if self.current.y - h < BOTTOM_Y + 20:
            self.new_page()

    def build(self) -> list[Canvas]:
        self._cover_page()
        self._executive_summary()
        self._severity_breakdown()
        self._priority_findings()
        self._crypto_inventory()
        self._affected_locations()
        self._migration_priorities()
        self._scan_coverage()
        self._methodology()
        return self.pages

    # ── Page Decoration ──
    def _decorate_page(self, c: Canvas, is_cover: bool = False) -> None:
        if is_cover:
            return
        # Header line
        c.save()
        c.set_stroke(CLR["primary"])
        c.hline(MARGIN, PAGE_W - MARGIN, PAGE_H - MARGIN + 10, 1.5)
        # Header text
        c.text(MARGIN, PAGE_H - MARGIN + 14, "ECDAT Cryptographic Risk Report", FONT_B, 8, CLR["primary"])
        c.text_right(PAGE_W - MARGIN, PAGE_H - MARGIN + 14, str(c.page_num), FONT, 8, CLR["text_muted"])
        c.restore()
        # Footer
        c.save()
        c.set_stroke(CLR["line"])
        c.hline(MARGIN, PAGE_W - MARGIN, MARGIN - 15, 0.5)
        c.text(MARGIN, MARGIN - 25, "CONFIDENTIAL - ECDAT Cryptographic Analysis", FONT_O, 7, CLR["text_muted"])
        c.text_right(PAGE_W - MARGIN, MARGIN - 25, f"Page {c.page_num}", FONT, 7, CLR["text_muted"])
        c.restore()

    # ── Cover Page ──
    def _cover_page(self) -> None:
        c = self.current
        # Background accent bar
        c.save()
        c.set_fill(CLR["primary"])
        c.rect(0, PAGE_H - 120, PAGE_W, 120, fill=True)
        # Purple accent line
        c.set_fill(CLR["accent"])
        c.rect(0, PAGE_H - 122, PAGE_W, 2, fill=True)
        c.restore()

        # ECDAT Logo/Wordmark
        c.text(MARGIN, PAGE_H - 90, "ECDAT", FONT_B, 36, Color(1, 1, 1))
        c.text(MARGIN, PAGE_H - 120, "CRYPTOGRAPHIC RISK REPORT", FONT, 14, Color(0.9, 0.9, 0.95))

        # Target info
        target = self.r.get("display_target", self.r.get("target", "Unknown Target"))
        scan_id = self.r.get("scan_id", "")
        started = self.r.get("started_at", "")[:10]
        finished = self.r.get("finished_at", "")[:10]
        status = self.r.get("status", "COMPLETE")

        c.text(MARGIN, PAGE_H - 180, f"Target: {target}", FONT, 14, CLR["text"])
        c.text(MARGIN, PAGE_H - 210, f"Scan ID: {scan_id}", FONT, 10, CLR["text_muted"])
        c.text(MARGIN, PAGE_H - 230, f"Period: {started} -> {finished}", FONT, 10, CLR["text_muted"])

        # Status badge
        risk = self.r.get("risk", {}) or {}
        risk_level = str(risk.get("level", "none")).upper()
        risk_score = risk.get("score", 0.0)
        badge_color = SEV_COLOR.get(risk_level.lower(), CLR["sev_info"])
        c.save()
        c.set_fill(badge_color)
        c.rounded_rect(MARGIN, PAGE_H - 280, 160, 30, 5, fill=True)
        c.set_fill(Color(1, 1, 1))
        c.add(f"BT /{FONT_B} 11 Tf {MARGIN+10:.2f} {PAGE_H - 270:.2f} Td ({_esc(f'Risk: {risk_level} ({risk_score}/10)')}) Tj ET")
        c.restore()

        # Divider
        c.save()
        c.set_stroke(CLR["line"])
        c.hline(MARGIN, PAGE_W - MARGIN, PAGE_H - 310, 0.5)
        c.restore()

        # Summary paragraph
        summary = self.r.get("summary", "")
        if summary:
            c.text_wrap(MARGIN, PAGE_H - 330, summary, CONTENT_W, FONT, 10, CLR["text"])

        self.new_page()

    # ── Executive Summary ──
    def _executive_summary(self) -> None:
        c = self.current
        self._section_title(c, "1", "Executive Summary")

        # Metric Cards Row
        risk = self.r.get("risk", {}) or {}
        cov = self.r.get("coverage_summary", {}) or {}
        cards = [
            ("Overall Risk", f"{str(risk.get('level', 'none')).upper()} ({risk.get('score', 0.0)}/10)", CLR["primary"]),
            ("Findings", str(self.r.get("finding_count", 0)), CLR["accent"]),
            ("Operations", str(self.r.get("operation_count", 0)), Color(0.15, 0.4, 0.3)),
            ("Assets", str(self.r.get("asset_count", 0)), Color(0.4, 0.25, 0.5)),
            ("Files", f"{cov.get('files_analyzed', self.r.get('files_scanned', 0))} / {cov.get('files_discovered', self.r.get('files_scanned', 0))}", Color(0.3, 0.35, 0.5)),
        ]
        self._metric_cards(c, cards)

        # Summary text
        summary = self.r.get("summary", "")
        if summary:
            c.y -= 10
            c.text(MARGIN, c.y, "Summary", FONT_B, 11, CLR["primary"])
            c.y -= 18
            c.y = c.text_wrap(MARGIN, c.y, summary, CONTENT_W, FONT, 10, CLR["text"])

        # Confirmed vs Capability
        groups = self.r.get("finding_groups", []) or []
        confirmed = sum(g.get("confirmed_count", 0) for g in groups)
        capability = sum(g.get("count", 0) - g.get("confirmed_count", 0) for g in groups)
        c.y -= 10
        c.text(MARGIN, c.y, f"Confirmed findings: {confirmed}   |   Declared capabilities (unconfirmed): {capability}", FONT, 9, CLR["text_muted"])

        self.need_space(40)

    def _metric_cards(self, c: Canvas, cards: list[tuple[str, str, Color]]) -> None:
        n = len(cards)
        card_w = (CONTENT_W - (n - 1) * 10) / n
        card_h = 55
        x = MARGIN
        for label, value, accent in cards:
            c.save()
            # Card background
            c.set_fill(CLR["card_bg"])
            c.rounded_rect(x, c.y - card_h, card_w, card_h, 6, fill=True)
            # Accent top bar
            c.set_fill(accent)
            c.rect(x, c.y - 4, card_w, 4, fill=True)
            # Value
            c.set_fill(CLR["text"])
            c.add(f"BT /{FONT_B} 20 Tf {x + card_w/2 - len(value)*5:.2f} {c.y - 32:.2f} Td ({_esc(value)}) Tj ET")
            # Label
            c.set_fill(CLR["text_muted"])
            c.add(f"BT /{FONT} 8 Tf {x + 8:.2f} {c.y - 48:.2f} Td ({_esc(label.upper())}) Tj ET")
            c.restore()
            x += card_w + 10
        c.y -= card_h + 15

    # ── Severity Breakdown ──
    def _severity_breakdown(self) -> None:
        c = self.current
        self.need_space(120)
        self._section_title(c, "2", "Severity Breakdown")

        by_sev = self.r.get("by_severity", {}) or {}
        if not by_sev:
            c.text(MARGIN, c.y, "No findings recorded.", FONT, 10, CLR["text_muted"])
            c.y -= 20
            return

        order = ["critical", "high", "medium", "low", "info"]
        total = sum(by_sev.values())
        # Bars
        bar_w = CONTENT_W * 0.6
        bar_h = 18
        for sev in order:
            count = by_sev.get(sev, 0)
            if count == 0:
                continue
            pct = count / total if total else 0
            c.text(MARGIN, c.y, sev.upper(), FONT_B, 9, SEV_COLOR.get(sev, CLR["text"]))
            c.text_right(MARGIN + 80, c.y, f"{count} ({pct*100:.0f}%)", FONT, 9, CLR["text_muted"])
            # Bar background
            c.save()
            c.set_fill(CLR["line"])
            c.rect(MARGIN + 90, c.y - 2, bar_w, bar_h, fill=True)
            # Bar fill
            c.set_fill(SEV_COLOR.get(sev, CLR["text"]))
            c.rect(MARGIN + 90, c.y - 2, bar_w * pct, bar_h, fill=True)
            c.restore()
            c.y -= bar_h + 8

        c.y -= 10

    # ── Priority Findings ──
    def _priority_findings(self) -> None:
        c = self.current
        self.need_space(150)
        self._section_title(c, "3", "Priority Findings")

        groups = self.r.get("finding_groups", []) or []
        confirmed_groups = [g for g in groups if g.get("confirmed")]

        if not confirmed_groups:
            c.text(MARGIN, c.y, "No confirmed findings.", FONT, 10, CLR["text_muted"])
            c.y -= 20
            return

        for gi, group in enumerate(confirmed_groups[:8]):
            self.need_space(80)
            first = group["occurrences"][0] if group["occurrences"] else {}
            where = f"{first.get('file', '')}:{first.get('line', '')}" if first else ""
            sev = group.get("severity", "info")
            sev_clr = SEV_COLOR.get(sev, CLR["text"])

            # Severity badge + title
            c.badge(MARGIN, c.y, sev.upper(), sev_clr, 8, 6)
            c.text(MARGIN + 55, c.y - 2, group.get("title", group.get("rule_id", "")), FONT_B, 11, CLR["text"])
            c.y -= 20

            # Meta line
            meta = f"{group.get('rule_id', '')}  *  {group.get('count', 0)} occurrence(s)  *  {group.get('file_count', 0)} file(s)"
            if where:
                meta += f"  *  Top: {where}"
            c.text(MARGIN, c.y, meta, FONT, 9, CLR["text_muted"])
            c.y -= 16

            # Evidence snippet
            if first.get("snippet"):
                c.save()
                c.set_fill(Color(0.95, 0.96, 0.98))
                c.rounded_rect(MARGIN, c.y - 40, CONTENT_W, 38, 4, fill=True)
                c.set_fill(CLR["text"])
                c.text_wrap(MARGIN + 6, c.y - 8, f"Evidence: {first['snippet'][:200]}", CONTENT_W - 12, FONT_O, 8, CLR["text"])
                c.restore()
                c.y -= 45

            # Divider
            if gi < len(confirmed_groups) - 1:
                c.save()
                c.set_stroke(CLR["line"])
                c.hline(MARGIN, PAGE_W - MARGIN, c.y, 0.3)
                c.restore()
                c.y -= 8

    # ── Cryptographic Inventory ──
    def _crypto_inventory(self) -> None:
        c = self.current
        self.need_space(100)
        self._section_title(c, "4", "Cryptographic Inventory (Confirmed Use)")

        inventory = [row for row in (self.r.get("inventory", []) or []) if row.get("confirmed")]

        if not inventory:
            c.text(MARGIN, c.y, "No confirmed cryptographic use detected.", FONT, 10, CLR["text_muted"])
            c.y -= 20
            return

        # Table
        headers = ["Algorithm", "Type", "Uses", "Files", "Risk", "Migration Guidance"]
        col_widths = [100, 70, 40, 40, 55, CONTENT_W - 305]
        rows = []
        for row in inventory[:25]:
            mig = (row.get("migration", "") or "").replace("\n", " ")[:80]
            rows.append([
                row.get("algorithm", "")[:28],
                row.get("type", "")[:18],
                str(row.get("confirmed_uses", 0)),
                str(row.get("file_count", 0)),
                row.get("risk", "")[:12],
                mig
            ])
        c.y = c.table(MARGIN, c.y, col_widths, headers, rows, font_size=7.5)

        if len(inventory) > 25:
            c.y -= 8
            c.text(MARGIN, c.y, f"... and {len(inventory) - 25} more (see HTML/JSON export)", FONT_O, 8, CLR["text_muted"])

        # Capabilities
        caps = [row for row in (self.r.get("inventory", []) or []) if not row.get("confirmed")]
        if caps:
            c.y -= 10
            c.text(MARGIN, c.y, f"Declared capabilities without confirmed use ({len(caps)}):", FONT_B, 9, CLR["text_muted"])
            c.y -= 14
            cap_names = ", ".join(r.get("algorithm", "") for r in caps[:15])
            c.y = c.text_wrap(MARGIN, c.y, cap_names + ("..." if len(caps) > 15 else ""), CONTENT_W, FONT, 8, CLR["text_muted"])

    # ── Affected Locations ──
    def _affected_locations(self) -> None:
        c = self.current
        self.need_space(100)
        self._section_title(c, "5", "Affected Locations")

        components = self.r.get("components", []) or []
        if not components:
            c.text(MARGIN, c.y, "No affected components.", FONT, 10, CLR["text_muted"])
            c.y -= 20
            return

        headers = ["Module", "Findings", "Files", "Top Severity", "Algorithms"]
        col_widths = [120, 55, 50, 70, CONTENT_W - 295]
        rows = []
        for comp in components[:15]:
            rows.append([
                comp.get("module", "")[:30],
                str(comp.get("findings", 0)),
                str(comp.get("file_count", 0)),
                comp.get("highest_severity", "").upper(),
                ", ".join(comp.get("algorithms", [])[:4])
            ])
        c.y = c.table(MARGIN, c.y, col_widths, headers, rows, font_size=7.5)

    # ── Migration Priorities ──
    def _migration_priorities(self) -> None:
        c = self.current
        self.need_space(100)
        self._section_title(c, "6", "Migration Priorities")

        mig_groups = self.r.get("migration_groups", {}) or {}
        mig_counts = self.r.get("migration_counts", {}) or {}

        if not any(mig_groups.values()):
            c.text(MARGIN, c.y, "No migration actions required.", FONT, 10, CLR["text_muted"])
            c.y -= 20
            return

        for name in ("Immediate", "High priority", "Planned", "Informational"):
            items = mig_groups.get(name, []) or []
            if not items:
                continue
            self.need_space(60)
            c.text(MARGIN, c.y, f"{name} ({mig_counts.get(name, len(items))})", FONT_B, 11, CLR["accent"])
            c.y -= 18
            for rec in items[:8]:
                self.need_space(35)
                sev = rec.get("severity", "info")
                c.badge(MARGIN, c.y, sev.upper(), SEV_COLOR.get(sev, CLR["text"]), 7, 5)
                c.text(MARGIN + 50, c.y - 2, rec.get("title", rec.get("rule_id", "")), FONT_B, 9, CLR["text"])
                c.y -= 14
                files = rec.get("affected_files", []) or []
                action = (rec.get("action", "") or "").split(".")[0][:100]
                c.text(MARGIN, c.y, f"x{rec.get('count', 1)} in {len(files)} file(s): {action}", FONT, 8, CLR["text_muted"])
                c.y -= 12
                if files:
                    file_list = ", ".join(files[:5]) + ("..." if len(files) > 5 else "")
                    c.text(MARGIN + 10, c.y, f"Files: {file_list}", FONT_O, 7, CLR["text_muted"])
                    c.y -= 12

    # ── Scan Coverage ──
    def _scan_coverage(self) -> None:
        c = self.current
        self.need_space(120)
        self._section_title(c, "7", "Scan Coverage & Methodology")

        cov = self.r.get("coverage_summary", {}) or {}
        lim = self.r.get("limitations", {}) or {}
        method = self.r.get("methodology", {}) or {}

        # Coverage stats
        c.text(MARGIN, c.y, f"Coverage: {cov.get('files_analyzed', self.r.get('files_scanned', 0))} / {cov.get('files_discovered', self.r.get('files_scanned', 0))} files", FONT_B, 10, CLR["text"])
        c.y -= 16
        c.text(MARGIN, c.y, f"Profile: {cov.get('profile', 'standard')}  |  Cache: {'hit' if cov.get('cache_hit') else 'miss'}  |  Elapsed: {method.get('elapsed_sec', '?')}s", FONT, 9, CLR["text_muted"])
        c.y -= 18

        c.text(MARGIN, c.y, f"Skipped: {cov.get('files_skipped', 0)}  |  No evidence: {cov.get('files_without_evidence', 0)}", FONT, 9, CLR["text_muted"])
        c.y -= 16

        # Skipped by bucket
        buckets = cov.get("skipped_by_bucket", {}) or {}
        if buckets:
            c.text(MARGIN, c.y, "Skipped by reason:", FONT_B, 9, CLR["text"])
            c.y -= 14
            for reason, count in sorted(buckets.items(), key=lambda x: -x[1])[:10]:
                c.text(MARGIN + 10, c.y, f"- {reason}: {count}", FONT, 8, CLR["text_muted"])
                c.y -= 12

        # Limitations
        for key in ("unavailable_tools", "permission_gated", "failed_scanners"):
            vals = lim.get(key, []) or []
            if vals:
                c.y -= 6
                c.text(MARGIN, c.y, f"{key.replace('_', ' ').title()}: {', '.join(map(str, vals))}", FONT, 8, CLR["text_muted"])
                c.y -= 12

        # Methodology
        c.y -= 10
        c.text(MARGIN, c.y, "Methodology", FONT_B, 11, CLR["primary"])
        c.y -= 16
        if method.get("risk_model"):
            c.y = c.text_wrap(MARGIN, c.y, method["risk_model"], CONTENT_W, FONT, 8, CLR["text"])
            c.y -= 8
        c.text(MARGIN, c.y, f"Risk source: {method.get('risk_source', '')}", FONT, 8, CLR["text_muted"])
        c.y -= 12
        c.text(MARGIN, c.y, f"Registry: {method.get('registry_version', '')}", FONT, 8, CLR["text_muted"])
        c.y -= 12

        tools = method.get("tool_versions", {}) or {}
        if tools:
            c.text(MARGIN, c.y, "Detectors:", FONT_B, 8, CLR["text"])
            c.y -= 12
            for k, v in sorted(tools.items()):
                c.text(MARGIN + 10, c.y, f"- {k} {v}", FONT, 8, CLR["text_muted"])
                c.y -= 11

        status = method.get("scanner_status", {}) or {}
        if status:
            c.y -= 4
            c.text(MARGIN, c.y, "Scanner outcomes:", FONT_B, 8, CLR["text"])
            c.y -= 12
            for k, v in sorted(status.items()):
                c.text(MARGIN + 10, c.y, f"- {k}: {v}", FONT, 8, CLR["text_muted"])
                c.y -= 11

    # ── Methodology Appendix ──
    def _methodology(self) -> None:
        # Already covered in scan_coverage
        pass

    # ── Helpers ──
    def _section_title(self, c: Canvas, num: str, title: str) -> None:
        c.save()
        # Number circle
        c.set_fill(CLR["primary"])
        cx = MARGIN + 14
        cy = c.y - 8
        c.add(f"{cx:.2f} {cy:.2f} 14 0 360 arc f")
        c.set_fill(Color(1, 1, 1))
        c.add(f"BT /{FONT_B} 11 Tf {cx-4:.2f} {cy-4:.2f} Td ({_esc(num)}) Tj ET")
        c.restore()
        # Title
        c.text(MARGIN + 35, c.y, title, FONT_B, 16, CLR["primary"])
        # Underline
        c.save()
        c.set_stroke(CLR["accent"])
        c.hline(MARGIN + 35, MARGIN + 35 + len(title) * 8, c.y - 4, 2)
        c.restore()
        c.y -= 24


# ─── PDF Assembly ───────────────────────────────────────────────────────
def _build_pdf(pages: list[Canvas]) -> bytes:
    """Assemble final PDF from page canvases."""
    objects: list[bytes] = []
    # Catalog
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    # Pages tree
    kids = " ".join(f"{4 + 3*i} 0 R" for i in range(len(pages)))
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode())
    # Font object (shared)
    font_obj_num = 3 + 3 * len(pages)
    # Page objects
    for i, c in enumerate(pages):
        page_obj = 4 + 3 * i
        content_obj = page_obj + 1
        # Page dict
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W:.1f} {PAGE_H:.1f}] "
            f"/Resources << /Font << /F1 {font_obj_num} 0 R /F2 {font_obj_num} 0 R >> >> "
            f"/Contents {content_obj} 0 R >>".encode()
        )
        # Content stream
        stream = c.stream()
        objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")
    # Font
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Oblique >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-BoldOblique >>")

    # Write PDF
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_at = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n".encode()
    pdf += b"0000000000 65535 f \n"
    for off in offsets:
        pdf += f"{off:010d} 00000 n \n".encode()
    pdf += (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R "
            f"/Producer (ECDAT Report) >>\nstartxref\n{xref_at}\n%%EOF\n").encode()
    return bytes(pdf).replace(b"\n", b"\r\n")


def to_pdf_bytes(report: dict) -> bytes:
    """Render the report as professional PDF bytes."""
    builder = ReportBuilder(report)
    pages = builder.build()
    # Add page decorations (headers/footers)
    for c in pages:
        builder._decorate_page(c, is_cover=(c is pages[0]))
    return _build_pdf(pages)