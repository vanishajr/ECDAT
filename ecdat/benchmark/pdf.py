"""Benchmark PDF renderer (Person 3 platform layer).

Presentation only, over the Task 20 canonical report model using
the Task 22 chart-data functions:

    Benchmark execution -> Canonical report (report.build_report)
        -> Chart data (charts.*_data) -> Native PDF vectors (this module)

Follows the existing project PDF convention (`reports/pdf.py`):
stdlib-only raw PDF-1.4, Helvetica Type1, ASCII-only, fixed
producer metadata, no timestamps — deterministic bytes for the
same report. Multi-page flow (unlike the one-page scan summary)
so 23-case tables paginate with repeated headers.

Charts: SVG cannot embed in this stack (no rasterizer, and none
will be added — imaging libraries are out of scope). Instead the
same chart DATA backing the SVGs is drawn as native PDF vector
bars with identical unavailable semantics (dashed-grey "n/a",
never zero). No metrics are recomputed: every number comes from
the report (or chart-data views of it).
"""

from __future__ import annotations

from pathlib import Path

from ecdat.benchmark import charts as charts_mod

PRODUCER = "ECDAT benchmark PDF (mock)"
PAGE_W, PAGE_H = 595, 842
MARGIN = 48
CONTENT_W = PAGE_W - 2 * MARGIN
STEP = 14

_RGB = {
    "precision": (0x44 / 255, 0x72 / 255, 0xC4 / 255),
    "recall": (0xED / 255, 0x7D / 255, 0x31 / 255),
    "f1": (0x70 / 255, 0xAD / 255, 0x47 / 255),
    "tp": (0x70 / 255, 0xAD / 255, 0x47 / 255),
    "fp": (0xC0 / 255, 0, 0),
    "fn": (0xED / 255, 0x7D / 255, 0x31 / 255),
    "tn": (0x44 / 255, 0x72 / 255, 0xC4 / 255),
    "evaluated": (0x44 / 255, 0x72 / 255, 0xC4 / 255),
    "failed": (0xC0 / 255, 0, 0),
    "resource": (0x59 / 255, 0x59 / 255, 0x59 / 255),
}


def _clean(text: object, width: int = 100) -> str:
    s = str(text).encode("ascii", errors="replace").decode("ascii")
    s = s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return s[:width]


def _num(value: object) -> str:
    return "n/a" if value is None else str(value)


class _Doc:
    """Multi-page line/bar flow. All coordinates deterministic."""

    def __init__(self) -> None:
        self.pages: list[list[str]] = [[]]
        self.y = PAGE_H - MARGIN

    def _need(self, height: int) -> None:
        if self.y - height < MARGIN + 20:
            self.pages.append([])
            self.y = PAGE_H - MARGIN

    def text(self, size: int, text: str, x: int = MARGIN) -> None:
        self._need(STEP)
        self.pages[-1].append(
            f"BT /F1 {size} Tf {x} {self.y} Td ({_clean(text)}) Tj ET")
        self.y -= 20 if size > 12 else STEP

    def heading(self, text: str) -> None:
        self.y -= 6
        self.text(13, text)

    def bar(self, label: str, value: float | None, scale: float,
            color: str, suffix: str = "") -> None:
        """One labeled horizontal bar; None draws a grey n/a box."""
        self._need(STEP)
        y = self.y - 9
        max_w = CONTENT_W - 210
        x0 = MARGIN + 130
        self.pages[-1].append(
            f"BT /F1 9 Tf {MARGIN} {self.y} Td "
            f"({_clean(label, 22)}) Tj ET")
        if value is None:
            self.pages[-1].append(
                f"0.8 g {x0} {y} 60 9 re f 0 g "
                f"BT /F1 9 Tf {x0 + 64} {self.y} Td (n/a: unavailable) Tj ET")
        else:
            w = max_w * (value / scale) if scale > 0 else 0.0
            r, g, b = _RGB[color]
            self.pages[-1].append(
                f"{r:.3f} {g:.3f} {b:.3f} rg {x0} {y} {w:.1f} 9 re f 0 g "
                f"BT /F1 9 Tf {x0 + w + 5:.1f} {self.y} Td "
                f"({_clean(f'{value}{suffix}', 24)}) Tj ET")
        self.y -= STEP

    def finish(self) -> bytes:
        # Footer first (page numbers deterministic), then assemble.
        bodies = []
        total = len(self.pages)
        for i, ops in enumerate(self.pages, start=1):
            ops = list(ops)
            ops.append(
                f"BT /F1 9 Tf {MARGIN} 30 Td "
                f"(Page {i} of {total} - {PRODUCER}) Tj ET")
            stream = "\n".join(ops).encode("ascii")
            bodies.append(stream)
        objects: list[bytes] = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [" +
            b" ".join(f"{3 + 2 * i} 0 R".encode("ascii")
                      for i in range(total)) +
            b"] /Count " + str(total).encode("ascii") + b" >>",
        ]
        for stream in bodies:
            objects.append(
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                b"/Resources << /Font << /F1 "
                + str(len(objects) + 2).encode("ascii") +
                b" 0 R >> >> /Contents " +
                str(len(objects) + 1).encode("ascii") + b" 0 R >>")
            objects.append(b"<< /Length " + str(len(stream)).encode("ascii")
                           + b" >>\nstream\n" + stream + b"\nendstream")
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        pdf = bytearray(b"%PDF-1.4\n")
        offsets = []
        for i, body in enumerate(objects, start=1):
            offsets.append(len(pdf))
            pdf += f"{i} 0 obj\n".encode("ascii") + body + b"\nendobj\n"
        xref_at = len(pdf)
        pdf += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
        pdf += b"0000000000 65535 f \n"
        for off in offsets:
            pdf += f"{off:010d} 00000 n \n".encode("ascii")
        pdf += (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R "
                f"/Producer ({PRODUCER}) >>\nstartxref\n{xref_at}\n%%EOF\n"
                ).encode("ascii")
        return bytes(pdf)


def _metric_rows(doc: _Doc, metrics: dict) -> None:
    for key in ("tp", "fp", "tn", "fn", "precision", "recall", "f1",
                "accuracy", "fpr", "fnr", "specificity"):
        reason = (metrics.get("unavailable") or {}).get(key, "")
        doc.text(10, f"  {key}: {_num(metrics.get(key))}"
                     + (f"  [{reason}]" if reason else ""))


def render_pdf(report: dict) -> bytes:
    """Render the canonical report as deterministic PDF bytes. Pure."""
    doc = _Doc()
    # 1-3. Title / provider / synthetic warning.
    doc.text(18, f"ECDAT Benchmark Report: {report['suite_id']} "
                 f"v{report['suite_version']}")
    doc.text(10, f"Provider: {report['provider']} "
                 f"(type: {report['provider_type']})")
    doc.text(10, f"Run: {report['run_id']}  Engine: {report['engine']}")
    if report["synthetic"] or report["provider_type"] == "mock":
        doc.text(11, "WARNING: Synthetic/mock benchmark execution - "
                     "not a real ECDAT accuracy claim.")
    # 4. Selection.
    sel = report["selection"]
    doc.heading("Selection")
    doc.text(10, f"Scope: group={sel['group']} case_ids={sel['case_ids']}")
    doc.text(10, f"Resolved ({len(sel['resolved'])}): "
                 f"{', '.join(sel['resolved'][:12])}"
                 + (" ..." if len(sel["resolved"]) > 12 else ""))
    doc.text(10, f"Cases: {report['case_count']} total, "
                 f"{report['evaluated_n']} evaluated, "
                 f"{report['failed_n']} failed")
    # 5. Overall metrics.
    doc.heading("Overall metrics")
    _metric_rows(doc, report["overall"]["metrics"])
    # 6. Per-group table.
    doc.heading("Per-group results")
    for g in report["groups"]:
        doc.text(10, f"{g['group']}: cases={g['cases']} "
                     f"eval={g['evaluated']} fail={g['failed']} "
                     f"TP={g['counts']['tp']} FP={g['counts']['fp']} "
                     f"TN={_num(g['counts']['tn'])} FN={g['counts']['fn']} "
                     f"P={_num(g['metrics']['precision'])} "
                     f"R={_num(g['metrics']['recall'])} "
                     f"F1={_num(g['metrics']['f1'])} "
                     f"acc={_num(g['metrics']['accuracy'])}")
    # 7. Per-case results.
    doc.heading("Per-case results")
    for c in report["cases"]:
        if c["status"] == "failed":
            doc.text(10, f"{c['case_id']} [{c['group']}] FAILED: {c['error']}")
        else:
            doc.text(10, f"{c['case_id']} [{c['group']}] "
                         f"{c['title'][:60]}")
            doc.text(10, f"  predicted={c['predicted_n']} "
                         f"TP={c['counts']['tp']} FP={c['counts']['fp']} "
                         f"TN={_num(c['counts']['tn'])} "
                         f"FN={c['counts']['fn']} "
                         f"P={_num(c['metrics']['precision'])} "
                         f"R={_num(c['metrics']['recall'])} "
                         f"F1={_num(c['metrics']['f1'])}")
    # 8. Failures.
    doc.heading("Failures")
    if report["failures"]:
        for f in report["failures"]:
            doc.text(10, f"{f['case_id']} [{f['group']}]: {f['error']}")
    else:
        doc.text(10, "No failures.")
    # 9. Unavailable metrics.
    doc.heading("Unavailable metrics")
    overall_un = report["unavailable"]["overall"]
    by_group = report["unavailable"]["by_group"]
    if not overall_un and not by_group:
        doc.text(10, "None - all metrics computable.")
    for metric in sorted(overall_un):
        doc.text(10, f"overall {metric}: {overall_un[metric]}")
    for group in sorted(by_group):
        for metric in sorted(by_group[group]):
            doc.text(10, f"{group} {metric}: {by_group[group][metric]}")
    # 10. Performance (measured only).
    perf = report["performance"]
    doc.heading("Performance / resources (measured)")
    doc.text(10, f"Wall time: {perf['elapsed_s']}s")
    doc.text(10, f"CPU: {_num(perf['cpu_s'])}s")
    doc.text(10, f"Peak RSS: {_num(perf['peak_rss_bytes'])} bytes")
    doc.text(10, f"Note: {perf['resources_note']}")
    # 11. Charts (native vectors from Task 22 chart data).
    doc.heading("Charts (synthetic/mock - illustration only)")
    mdata = charts_mod.group_metric_data(report)
    doc.text(10, "Group precision/recall/F1 (n/a = unavailable):")
    for g in mdata["groups"]:
        for m in mdata["metrics"]:
            doc.bar(f"{g['group']} {m}", g["values"][m], 1.0, m)
    cdata = charts_mod.confusion_data(report)
    present = [v for g in cdata["groups"] for v in g["counts"].values()
               if v is not None]
    cscale = float(max(present)) if present else 1.0
    doc.text(10, "Confusion counts per group:")
    for g in cdata["groups"]:
        for s in cdata["series"]:
            doc.bar(f"{g['group']} {s.upper()}", g["counts"][s], cscale, s)
    sdata = charts_mod.status_data(report)
    spresent = [g["evaluated"] for g in sdata["groups"]] + \
               [g["failed"] for g in sdata["groups"]]
    sscale = float(max(spresent)) if spresent else 1.0
    doc.text(10, "Case status per group:")
    for g in sdata["groups"]:
        doc.bar(f"{g['group']} evaluated", g["evaluated"], sscale,
                "evaluated")
        if g["failed"]:
            doc.bar(f"{g['group']} failed", g["failed"], sscale, "failed")
    # 12. Disclaimer / reproducibility.
    doc.heading("Disclaimer / reproducibility")
    doc.text(10, report["note"])
    doc.text(10, "Logical content reproducible for identical suite + "
                 "provider + selection; run_id/timing vary per run.")
    return doc.finish()


def write_pdf(report: dict, path: str | Path) -> str:
    """Write PDF bytes; returns the path. Thin I/O wrapper."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(render_pdf(report))
    return str(out)
