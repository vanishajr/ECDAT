"""Minimal stdlib-only executive-summary PDF renderer (bytes).

Deliberately minimal: single page, Helvetica, ASCII-only, fixed
producer metadata and NO timestamps so output is deterministic.
Do NOT present this as a rich/typeset final PDF. Pure function.
"""

from __future__ import annotations

PRODUCER = "ECDAT minimal executive PDF (mock)"
MAX_LINES = 42


def _clean(text: object, width: int = 95) -> str:
    s = str(text).encode("ascii", errors="replace").decode("ascii")
    s = s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return s[:width]


def _lines(report: dict) -> list[tuple[int, str]]:
    r = report
    out: list[tuple[int, str]] = [
        (18, "ECDAT Executive Summary (minimal PDF)"),
        (11, f"Scan: {r['scan_id']}"),
        (11, f"Target: {r['target']}"),
        (
            11,
            f"Findings: {r['finding_count']} "
            f"(files scanned: {r['files_scanned']})",
        ),
        (11, f"Risk: {r['risk']['level']} ({r['risk']['score']}) [mock scoring]"),
        (11, "Severity: "
         + (", ".join(f"{k}={v}" for k, v in sorted(r["by_severity"].items()))
            or "none")),
        (11, "Top rules:"),
    ]
    for row in r["by_rule"][:8]:
        out.append((11, f"  {row['rule_id']} [{row['severity']}] x{row['count']}"))
    out.append((11, "Top files/services:"))
    for row in r["top_files"][:5]:
        out.append((11, f"  {row['file']} x{row['count']}"))
    out += [
        (11, "Migration: see recommend command (mock placeholder)."),
        (11, "Risk/migration are mock output pending Person 1 engine."),
    ]
    return out[:MAX_LINES]


def to_pdf_bytes(report: dict) -> bytes:
    """Render a deterministic one-page PDF. No I/O."""
    ops = []
    y = 800
    for size, text in _lines(report):
        ops.append(f"BT /F1 {size} Tf 72 {y} Td ({_clean(text)}) Tj ET")
        y -= 20 if size > 12 else 15
    stream = "\n".join(ops).encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n"
        + stream + b"\nendstream",
    ]
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
    pdf += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R "
        f"/Producer ({PRODUCER}) >>\nstartxref\n{xref_at}\n%%EOF\n"
    ).encode("ascii")
    return bytes(pdf)
