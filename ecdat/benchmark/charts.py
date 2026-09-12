"""Static benchmark chart renderers (Person 3 platform layer).

Presentation only, over the Task 20 canonical report model:

    Benchmark execution -> Canonical report (report.build_report)
        -> Chart data (this module: pure prep, None-preserving)
        -> Static SVG (this module: pure rendering, file writers)

No matplotlib: it is not a project dependency (stdlib +
jsonschema only), and silently adding a heavy binary dependency
for four bar charts would violate the project's minimal-
dependency policy. Static inline SVG needs no dependency, renders
headless everywhere, is byte-deterministic, works offline, and
embeds directly into future HTML/PDF layers. PNG output is left
for a future task if an imaging dependency is ever adopted.

Honesty rules (enforced, tested): unavailable values are NEVER
plotted as zero — the bar slot shows a dashed "n/a" marker and
the legend states grey means unavailable, not zero. TN=None
omits the TN bar for that group with the same marker. Titles
carry the report's own synthetic/mock flag; no superiority,
baseline, cache, or throughput content exists.
"""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from ecdat.benchmark.render import METRIC_COLUMNS

CHART_METRICS: tuple[str, ...] = ("precision", "recall", "f1")

_COLORS = {
    "precision": "#4472C4",
    "recall": "#ED7D31",
    "f1": "#70AD47",
    "tp": "#70AD47",
    "fp": "#C00000",
    "fn": "#ED7D31",
    "tn": "#4472C4",
    "evaluated": "#4472C4",
    "failed": "#C00000",
    "resource": "#595959",
}
_NA = "#BBBBBB"

_W, _LEFT, _RIGHT, _TOP = 680, 170, 24, 66
_BAR, _GAP = 13, 5
_FONT = "font-family='sans-serif'"


def _esc(value: object) -> str:
    return escape(str(value), {'"': "&quot;"})


def _mock_subtitle(report: dict) -> str:
    if report["synthetic"] or report["provider_type"] == "mock":
        return "Synthetic/mock benchmark — not a real ECDAT accuracy claim."
    return f"Provider: {report['provider']} (type: {report['provider_type']})."


# --- chart data (pure; report order kept; None preserved) ------------------------------


def group_metric_data(report: dict) -> dict:
    """Per-group precision/recall/F1 (None kept). Deterministic."""
    return {
        "metrics": list(CHART_METRICS),
        "groups": [{"group": g["group"],
                    "values": {m: g["metrics"][m] for m in CHART_METRICS}}
                   for g in report["groups"]],
    }


def confusion_data(report: dict) -> dict:
    """Per-group TP/FP/FN/TN (TN None kept). Deterministic."""
    return {
        "series": ["tp", "fp", "fn", "tn"],
        "groups": [{"group": g["group"],
                    "counts": {k: g["counts"][k]
                               for k in ("tp", "fp", "fn", "tn")}}
                   for g in report["groups"]],
    }


def status_data(report: dict) -> dict:
    """Per-group evaluated/failed plus totals. Deterministic."""
    groups = [{"group": g["group"], "evaluated": g["evaluated"],
               "failed": g["failed"]} for g in report["groups"]]
    return {
        "groups": groups,
        "totals": {"evaluated": sum(g["evaluated"] for g in groups),
                   "failed": sum(g["failed"] for g in groups)},
    }


def resource_data(report: dict) -> dict:
    """Only actually measured values (None dropped, never zeroed)."""
    perf = report["performance"]
    items = [{"label": "wall time", "value": perf["elapsed_s"], "unit": "s"}]
    if perf["cpu_s"] is not None:
        items.append({"label": "CPU time", "value": perf["cpu_s"],
                      "unit": "s"})
    if perf["peak_rss_bytes"] is not None:
        items.append({"label": "peak RSS", "value": perf["peak_rss_bytes"],
                      "unit": "bytes"})
    return {"items": items, "note": perf["resources_note"]}


# --- SVG rendering (pure; fixed layout; no timestamps) -----------------------------------


def _frame(title: str, subtitle: str, height: int) -> tuple[str, str]:
    head = (f"<svg xmlns='http://www.w3.org/2000/svg' width='{_W}' "
            f"height='{height}' role='img' aria-label='{_esc(title)}'>"
            f"<title>{_esc(title)}</title><desc>{_esc(subtitle)}</desc>"
            f"<text x='16' y='26' font-size='17' {_FONT} "
            f"font-weight='bold'>{_esc(title)}</text>"
            f"<text x='16' y='46' font-size='12' {_FONT} "
            f"fill='#555'>{_esc(subtitle)}</text>")
    return head, "</svg>"


def _bar(x: float, y: float, w: float, color: str, label: str) -> str:
    return (f"<rect x='{x:.1f}' y='{y:.1f}' width='{w:.1f}' "
            f"height='{_BAR}' fill='{color}'>"
            f"<title>{_esc(label)}</title></rect>"
            f"<text x='{x + w + 6:.1f}' y='{y + 11:.1f}' font-size='11' "
            f"{_FONT}>{_esc(label)}</text>")


def _na_slot(x: float, y: float, w: float, key: str) -> str:
    return (f"<rect x='{x:.1f}' y='{y:.1f}' width='{w:.1f}' "
            f"height='{_BAR}' fill='none' stroke='{_NA}' "
            f"stroke-dasharray='4,3'><title>{_esc(key)}: unavailable "
            f"(not zero)</title></rect>"
            f"<text x='{x + 4:.1f}' y='{y + 11:.1f}' font-size='11' "
            f"{_FONT} fill='#777'>n/a</text>")


def _legend(entries: list[tuple[str, str]], y: int) -> str:
    parts = []
    x = 16
    for color, name in entries:
        parts.append(
            f"<rect x='{x}' y='{y}' width='12' height='12' "
            f"fill='{color}'/><text x='{x + 16}' y='{y + 11}' "
            f"font-size='12' {_FONT}>{_esc(name)}</text>")
        x += 24 + 8 * (len(name) + 2)
    return "".join(parts)


def _grouped_inner(groups: list[str],
                   series: list[tuple[str, str]],
                   values: list[list[float | None]],
                   scale: float, unit: str = "") -> tuple[str, int]:
    """Chart body (axis + bars + legend); y origin at top of body."""
    n_series = len(series)
    row_h = n_series * (_BAR + _GAP) + 14
    plot_w = _W - _LEFT - _RIGHT
    parts = ""
    for gi, group in enumerate(groups):
        y0 = gi * row_h
        parts += (f"<text x='16' y='{y0 + 12:.1f}' font-size='12' "
                  f"{_FONT}>{_esc(group)}</text>")
        for si, (key, color) in enumerate(series):
            y = y0 + si * (_BAR + _GAP)
            value = values[gi][si]
            if value is None:
                parts += _na_slot(_LEFT, y, plot_w, key)
            else:
                w = plot_w * (value / scale) if scale > 0 else 0.0
                parts += _bar(_LEFT, y, w, color,
                              f"{value}{unit}" if unit else str(value))
    base = row_h * max(len(groups), 1)
    parts += (f"<line x1='{_LEFT}' y1='{base}' x2='{_W - _RIGHT}' "
              f"y2='{base}' stroke='#333'/>"
              f"<text x='{_LEFT}' y='{base + 16}' font-size='11' "
              f"{_FONT}>0</text>"
              f"<text x='{_W - _RIGHT - 60}' y='{base + 16}' "
              f"font-size='11' {_FONT}>{_esc(str(scale))}{_esc(unit)} "
              f"(max)</text>")
    parts += _legend([(c, k) for k, c in series] + [(_NA, "n/a = unavailable")],
                     base + 22)
    return parts, base + 44


def _grouped_svg(title: str, subtitle: str, groups: list[str],
                 series: list[tuple[str, str]],
                 values: list[list[float | None]],
                 scale: float, unit: str = "") -> str:
    """Horizontal grouped bars; None slots render as n/a markers."""
    body, content_h = _grouped_inner(groups, series, values, scale, unit)
    head, tail = _frame(title, subtitle, _TOP + content_h)
    return head + f"<g>{body}</g>" + tail


def render_group_metrics_svg(report: dict) -> str:
    """Grouped precision/recall/F1 bars on a fixed 0..1 scale."""
    data = group_metric_data(report)
    return _grouped_svg(
        "Benchmark group metrics", _mock_subtitle(report),
        [g["group"] for g in data["groups"]],
        [(m, _COLORS[m]) for m in data["metrics"]],
        [[g["values"][m] for m in data["metrics"]]
         for g in data["groups"]],
        scale=1.0)


def render_confusion_svg(report: dict) -> str:
    """Grouped TP/FP/FN/TN bars; TN=None slots show n/a, never 0."""
    data = confusion_data(report)
    present = [v for g in data["groups"] for v in g["counts"].values()
               if v is not None]
    scale = float(max(present)) if present else 1.0
    return _grouped_svg(
        "Benchmark confusion counts", _mock_subtitle(report),
        [g["group"] for g in data["groups"]],
        [(s, _COLORS[s]) for s in data["series"]],
        [[g["counts"][s] for s in data["series"]] for g in data["groups"]],
        scale=scale)


def render_status_svg(report: dict) -> str:
    """Evaluated vs failed bars per group (execution status, not metrics)."""
    data = status_data(report)
    present = [g["evaluated"] for g in data["groups"]] + \
              [g["failed"] for g in data["groups"]]
    scale = float(max(present)) if present else 1.0
    return _grouped_svg(
        "Benchmark case status", _mock_subtitle(report),
        [g["group"] for g in data["groups"]],
        [("evaluated", _COLORS["evaluated"]),
         ("failed", _COLORS["failed"])],
        [[g["evaluated"], g["failed"]] for g in data["groups"]],
        scale=scale)


def render_resources_svg(report: dict) -> str:
    """One unit scale per section, stacked; measured values only."""
    data = resource_data(report)
    units: list[str] = []
    for item in data["items"]:
        if item["unit"] not in units:
            units.append(item["unit"])
    blocks = []
    for unit in units:
        items = [i for i in data["items"] if i["unit"] == unit]
        scale = float(max(i["value"] for i in items))
        body, height = _grouped_inner(
            [i["label"] for i in items], [("value", _COLORS["resource"])],
            [[i["value"]] for i in items], scale=scale, unit=f" {unit}")
        blocks.append((f"Benchmark resources ({unit})", body, height))
    title = "Benchmark resources"
    total = sum(h for _, _, h in blocks) + 24 * (len(blocks) - 1)
    head, tail = _frame(title, data["note"], _TOP + total)
    parts = head
    y = _TOP
    for subtitle, body, height in blocks:
        parts += (f"<text x='16' y='{y - 8}' font-size='13' {_FONT} "
                  f"font-weight='bold'>{_esc(subtitle)}</text>"
                  f"<g transform='translate(0,{y})'>{body}</g>")
        y += height + 24
    return parts + tail


def render_all_svgs(report: dict) -> dict[str, str]:
    """All four charts keyed by deterministic section name."""
    return {
        "group-metrics": render_group_metrics_svg(report),
        "confusion": render_confusion_svg(report),
        "status": render_status_svg(report),
        "resources": render_resources_svg(report),
    }


def write_charts(report: dict, directory: str | Path) -> dict[str, str]:
    """Write chart SVGs; returns section -> path. Thin I/O wrapper."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    paths = {}
    for section, svg in render_all_svgs(report).items():
        path = out / f"{section}.svg"
        path.write_text(svg + "\n", encoding="utf-8")
        paths[section] = str(path)
    return paths
