"""Stdlib-only ECDAT report PDF renderer (bytes).

Multi-section production report (Phase 12): executive summary, scan
scope and methodology, cryptographic inventory, high-priority
operations, quantum/classical risk analysis, migration roadmap,
evidence and traceability, coverage and limitations, appendix.
Derived from the same aggregate report dict as the HTML/console
renderers, so counts and P1 risk agree everywhere.

Deterministic: Helvetica, ASCII-only, fixed producer metadata, no
timestamps, stable section order. Never embeds finding snippets
(metadata only, no secret material). Pure function.
"""

from __future__ import annotations

PRODUCER = "ECDAT report"
PAGE_WIDTH = 595
PAGE_HEIGHT = 842
LEFT = 56
TOP = 800
BOTTOM = 56


def _clean(text: object, width: int = 100) -> str:
    s = str(text).encode("ascii", errors="replace").decode("ascii")
    s = s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return s[:width]


def _wrap(text: str, width: int = 100) -> list[str]:
    words = str(text).split()
    if not words:
        return [""]
    lines, current = [], ""
    for word in words:
        while len(word) > width:
            if current:
                lines.append(current)
                current = ""
            lines.append(word[:width])
            word = word[width:]
        candidate = f"{current} {word}".strip()
        if len(candidate) <= width:
            current = candidate
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def _sections(report: dict) -> list[tuple[int, str]]:
    """Ordered (size, text) lines; size 16/13 = headings, 10 = body."""
    r = report
    out: list[tuple[int, str]] = []
    risk = r.get("risk", {}) if isinstance(r.get("risk"), dict) else {}
    cov = r.get("coverage", {}) if isinstance(r.get("coverage"), dict) else {}
    lim = r.get("limitations", {}) if isinstance(
        r.get("limitations"), dict) else {}

    def h1(text: str) -> None:
        out.append((16, ""))
        out.append((16, text))

    def h2(text: str) -> None:
        out.append((13, ""))
        out.append((13, text))

    def body(text: str) -> None:
        for line in _wrap(text):
            out.append((10, line))

    def bullet(text: str) -> None:
        for i, line in enumerate(_wrap(text, 96)):
            out.append((10, ("- " if i == 0 else "  ") + line))

    # 1. Executive summary.
    out.append((18, "ECDAT Cryptographic Risk Report"))
    body(f"Scan: {r.get('scan_id', '')}")
    body(f"Target: {r.get('display_target', r.get('target', ''))}")
    body(f"Scanned: {r.get('started_at', '')} .. {r.get('finished_at', '')}")
    body(f"Operations: {r.get('operation_count', 0)} "
         f"(assets: {r.get('asset_count', 0)}, "
         f"evidence findings: {r.get('finding_count', 0)}, "
         f"files scanned: {r.get('files_scanned', 0)})")
    body(f"Overall risk posture: {risk.get('level', 'none')} "
         f"({risk.get('score', 0.0)}) from the P1 risk engine.")
    top_recs = (r.get("recommendations", []) or [])[:3]
    if top_recs:
        body("Top migration actions:")
        for rec in top_recs:
            bullet(f"{rec.get('rule_id', '')} [{rec.get('severity', '')}]: "
                   f"{rec.get('title', '')}")
    else:
        body("Top migration actions: none.")
    unavailable = lim.get("unavailable_tools", []) or []
    if unavailable:
        body(f"Important limitation: unavailable tools: "
             f"{', '.join(map(str, unavailable))}.")

    # 2. Scan scope and methodology.
    h1("2. Scan scope and methodology")
    body(f"Input: {r.get('display_target', r.get('target', ''))} "
         f"(profile: {cov.get('profile', 'standard')}).")
    tools = r.get("tool_versions", {}) or {}
    body("Detectors run: " + (", ".join(
        f"{k} {v}" for k, v in sorted(tools.items())) or "none recorded")
        + ". Missing detectors are disclosed under Coverage, never "
          "scored as zero findings.")
    artifact_counts = cov.get("artifact_counts", {}) or {}
    if artifact_counts:
        body("Artifacts: " + ", ".join(
            f"{k}={v}" for k, v in sorted(artifact_counts.items())))
    body(f"Cache: {'hit (repeated scan)' if cov.get('cache_hit') else 'miss'}; "
         f"escalation allowed: {cov.get('escalation_allowed', False)}; "
         f"elapsed: {cov.get('elapsed_sec', '?')}s.")
    if cov.get("permissions_required"):
        body("External surfaces required explicit permission and were not "
             "scanned: " + ", ".join(
                 map(str, cov["permissions_required"])) + ".")

    # 3. Cryptographic inventory summary.
    h1("3. Cryptographic inventory summary")
    algos = r.get("algorithms", {}) or {}
    if algos:
        for name, count in list(algos.items())[:12]:
            bullet(f"{name}: {count} operation(s)")
    else:
        body("No reconstructed operations.")
    usage = r.get("usage_states", {}) or {}
    if usage:
        body("Usage confidence: " + ", ".join(
            f"{k}={v}" for k, v in sorted(usage.items()))
            + ". Dependency-only capability stays ProvidedOnly until "
              "corroborated by use evidence.")

    # 4. High-priority operations/systems.
    h1("4. High-priority operations")
    top_ops = r.get("top_operations", []) or []
    if top_ops:
        for op in top_ops[:5]:
            bullet(f"{op.get('operation_type', '')} {op.get('canonical', '')} "
                   f"[{op.get('risk_class', '')}] "
                   f"usage={op.get('usage_state', '')} "
                   f"conf={op.get('confidence', '')} "
                   f"at {op.get('file', '')} "
                   f"({op.get('evidence_count', 0)} evidence signals)")
    else:
        body("No operations reconstructed.")

    # 5. Quantum/classical risk analysis.
    h1("5. Quantum/classical risk analysis")
    body(f"P1 posture: {risk.get('level', 'none')} "
         f"({risk.get('score', 0.0)}). Model: {risk.get('model', '')}"
         if risk.get("model") else
         f"P1 posture: {risk.get('level', 'none')} "
         f"({risk.get('score', 0.0)}).")
    by_sev = r.get("by_severity", {}) or {}
    if by_sev:
        body("Finding severity distribution (evidence volume, not risk): "
             + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items()))
             + ".")
    body("Unknown risk inputs stay unknown: the engine records explicit "
         "mid-range assumptions per operation instead of exaggerating "
         "risk. Per-operation assumptions are in the JSON/CIR exports.")

    # 6. Migration roadmap.
    h1("6. Migration roadmap")
    recs = r.get("recommendations", []) or []
    if recs:
        for rec in recs[:8]:
            bullet(f"{rec.get('rule_id', '')} [{rec.get('severity', '')}]: "
                   f"{rec.get('action', '')}")
    else:
        body("No migration actions.")

    # 7. Evidence and traceability.
    h1("7. Evidence and traceability")
    by_rule = r.get("by_rule", []) or []
    if by_rule:
        for row in by_rule[:8]:
            bullet(f"{row.get('rule_id', '')} [{row.get('severity', '')}] "
                   f"x{row.get('count', 0)}: {row.get('title', '')}")
    else:
        body("No findings.")
    body("Each operation above links to detector evidence (source API, "
         "binary, config, certificate, runtime, cloud) with confidence "
         "and usage state in the JSON/CIR exports and GUI evidence view. "
         "Finding snippets are redacted; private key material is never "
         "stored.")

    # 8. Coverage and limitations.
    h1("8. Coverage and limitations")
    status = cov.get("scanner_status", {}) or {}
    if status:
        for name in sorted(status):
            bullet(f"{name}: {status[name]}")
    else:
        body("Scanner status not recorded for this scan.")
    for key in ("unavailable_tools", "permission_gated", "failed_scanners"):
        values = lim.get(key, []) or []
        if values:
            bullet(f"{key}: " + ", ".join(map(str, values)))
    skipped = cov.get("skipped", []) or []
    if skipped:
        bullet(f"skipped artifacts: {len(skipped)} "
               "(see JSON export for reasons)")

    # 9. Appendix.
    h1("9. Appendix: operations detail")
    if top_ops:
        for op in top_ops:
            bullet(f"{op.get('operation_id', '')} "
                   f"{op.get('operation_type', '')} "
                   f"{op.get('canonical', '')} "
                   f"{op.get('usage_state', '')} "
                   f"{op.get('file', '')}")
    else:
        body("No operations. Machine-readable exports (JSON, CIR, CSV, "
             "SARIF, CBOM) carry the full result.")
    return out


def to_pdf_bytes(report: dict) -> bytes:
    """Render the multi-section report as deterministic PDF bytes."""
    pages: list[list[str]] = [[]]
    y = TOP
    for size, text in _sections(report):
        step = 22 if size >= 16 else (18 if size >= 13 else 13)
        if y - step < BOTTOM:
            pages.append([])
            y = TOP
        pages[-1].append(
            f"BT /F1 {size} Tf {LEFT} {y} Td ({_clean(text)}) Tj ET")
        y -= step
    # Paginate: contents object per page + page objects.
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [" + b" ".join(
            f"{3 + 2 * i} 0 R".encode("ascii")
            for i in range(len(pages))) + b"] "
        + f"/Count {len(pages)}".encode("ascii") + b" >>",
    ]
    font_no = 3 + 2 * len(pages)
    for i, ops in enumerate(pages):
        page_no = 3 + 2 * i
        stream = "\n".join(ops).encode("ascii")
        objects.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            b"/Resources << /Font << /F1 " + f"{font_no} 0 R".encode(
                "ascii") + b" >> >> /Contents " + f"{page_no + 1} 0 R".encode(
                    "ascii") + b" >>")
        objects.append(
            b"<< /Length " + str(len(stream)).encode("ascii")
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
    return bytes(pdf).replace(b"\n", b"\r\n")
