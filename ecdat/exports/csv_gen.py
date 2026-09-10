"""CSV export renderer. Pure function over a validated canonical doc."""

from __future__ import annotations

import csv
import io

HEADER = [
    "scan_id",
    "rule_id",
    "severity",
    "file",
    "line",
    "title",
    "confidence",
    "snippet",
    "target",
]


def to_csv(doc: dict) -> str:
    """Render one finding per row. No trailing newline (caller adds it)."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(HEADER)
    for f in doc["findings"]:
        conf = f.get("confidence")
        writer.writerow(
            [
                doc["scan_id"],
                f["rule_id"],
                f["severity"],
                f["file"],
                f["line"],
                f["title"],
                "" if conf is None else conf,
                f.get("snippet", ""),
                doc["target"],
            ]
        )
    return buf.getvalue().rstrip("\n")
