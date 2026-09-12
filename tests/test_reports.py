"""Tests for Task 8 reports (mock-first, stdlib only).

Report engine is pure: build_report(doc) over the preserved canonical
document, then one renderer per format. Tests drive main() for CLI
behavior plus the pure helpers directly. Golden files live in
tests/fixtures/reports/.
"""

import json
from html.parser import HTMLParser
from pathlib import Path

import pytest

from ecdat.cli import build_parser, main
from ecdat.commands import report_cmd
from ecdat.core.validate import load_json, validate
from ecdat.reports import aggregate, console, html, markdown, pdf
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore

GOLDENS = Path(__file__).parent / "fixtures" / "reports"
CANON = Path(__file__).parent / "fixtures" / "canonical"


def _db(tmp_path: Path) -> str:
    return str(tmp_path / "t.db")


def _seed_canonical(tmp_path: Path, fixture: str) -> str:
    """Store a canonical fixture verbatim; return its scan_id."""
    doc = validate(load_json(CANON / f"{fixture}.json"))
    conn = db.open_db(_db(tmp_path))
    try:
        sstore.insert_scan(conn, doc)
        fstore.insert_findings_for_scan(conn, doc)
    finally:
        conn.close()
    return doc["scan_id"]


def _report_stdout(scan_id, tmp_path, capsys, format="markdown"):
    args = ["report", scan_id, "--format", format, "--db", _db(tmp_path)]
    assert main(args) == 0
    out, _ = capsys.readouterr()
    return out


def _doc(fixture: str) -> dict:
    return validate(load_json(CANON / f"{fixture}.json"))


# --- aggregation --------------------------------------------------------


def test_aggregate_minimal():
    rep = aggregate.build_report(_doc("minimal"))
    assert rep["scan_id"] == "scan-minimal-001"
    assert rep["finding_count"] == 1 and rep["files_scanned"] == 1
    assert rep["by_severity"] == {"high": 1}
    assert rep["by_rule"] == [
        {"rule_id": "RSA-1024", "title": "Weak RSA key size (1024-bit)",
         "severity": "high", "count": 1}
    ]
    assert rep["top_files"] == [{"file": "samples/rsa_small.py", "count": 1}]
    assert rep["risk"]["score"] == 5 and rep["risk"]["level"] == "medium"
    assert [r["rule_id"] for r in rep["recommendations"]] == ["RSA-1024"]


def test_aggregate_multi():
    rep = aggregate.build_report(_doc("multi"))
    assert rep["by_severity"] == {"critical": 1, "high": 1, "low": 1, "medium": 1}
    assert [r["rule_id"] for r in rep["by_rule"]] == [
        "AES-ECB", "MD5-USAGE", "RSA-1024", "TLS-1.0"]
    assert rep["top_files"][0] == {"file": "samples/app/auth.py", "count": 2}
    assert rep["risk"] == {"score": 19, "level": "high",
                           "breakdown": {"critical": 1, "high": 1, "low": 1, "medium": 1},
                           "finding_count": 4}
    assert len(rep["recommendations"]) == 4


def test_aggregate_empty():
    rep = aggregate.build_report(_doc("empty"))
    assert rep["finding_count"] == 0
    assert rep["by_severity"] == {} and rep["by_rule"] == [] and rep["top_files"] == []
    assert rep["risk"]["level"] == "none" and rep["recommendations"] == []


# --- renderers ----------------------------------------------------------


def test_markdown_sections():
    out = markdown.to_markdown(aggregate.build_report(_doc("multi")))
    for section in ["## Executive Summary", "## Scan Information",
                    "## Findings by Severity", "## Findings by Rule",
                    "## Top Affected Files/Services", "## Risk Summary (mock)",
                    "## Migration Summary (mock placeholder)", "## Disclaimer",
                    "scan-multi-001", "AES-ECB", "mock"]:
        assert section in out


def test_console_sections():
    out = console.to_console(aggregate.build_report(_doc("minimal")))
    for part in ["ECDAT report: scan-minimal-001", "by severity:",
                 "by rule:", "top files/services:",
                 "migration (mock placeholder):", "RSA-1024"]:
        assert part in out


def test_html_structure_and_escaping():
    rep = aggregate.build_report(_doc("minimal"))
    out = html.to_html(rep)

    class Checker(HTMLParser):
        def error(self, message):
            raise AssertionError(message)

    Checker().feed(out)  # must parse without error
    assert "<title>ECDAT Report: scan-minimal-001</title>" in out
    assert "RSA-1024" in out and "mock" in out


def test_html_escapes_special_chars(tmp_path):
    doc = {
        "schema_version": "1.0", "scan_id": "scan-escape-001",
        "target": "t", "started_at": "2026-09-10T16:00:00Z",
        "finished_at": "2026-09-10T16:00:01Z",
        "tool_versions": {"ecdat": "0.1.0"},
        "findings": [{"rule_id": "X-1", "title": "<b>Bold</b> & \"quoted\"",
                      "severity": "low", "file": "a<b>.py", "line": 1,
                      "snippet": "<script>alert(1)</script>"}],
        "stats": {"files_scanned": 1, "findings_count": 1},
    }
    validate(doc)
    out = html.to_html(aggregate.build_report(doc))
    assert "<b>Bold</b>" not in out and "&lt;b&gt;Bold&lt;/b&gt;" in out
    assert "a<b>.py" not in out and "a&lt;b&gt;.py" in out


def test_pdf_structure():
    blob = pdf.to_pdf_bytes(aggregate.build_report(_doc("minimal")))
    assert blob.startswith(b"%PDF-1.4")
    assert b"scan-minimal-001" in blob
    assert b"mock" in blob
    assert blob.rstrip().endswith(b"%%EOF")


def test_pdf_deterministic():
    rep = aggregate.build_report(_doc("multi"))
    assert pdf.to_pdf_bytes(rep) == pdf.to_pdf_bytes(rep)


# --- CLI: stdout + files ------------------------------------------------


def test_report_default_is_markdown(tmp_path, capsys):
    scan_id = _seed_canonical(tmp_path, "minimal")
    assert main(["report", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert out.startswith("# ECDAT Report: scan-minimal-001")


@pytest.mark.parametrize("format", ["markdown", "console", "html"])
def test_report_stdout_formats(tmp_path, capsys, format):
    scan_id = _seed_canonical(tmp_path, "minimal")
    out = _report_stdout(scan_id, tmp_path, capsys, format)
    assert scan_id in out and "mock" in out


@pytest.mark.parametrize("format", ["markdown", "console", "html"])
def test_report_output_file(tmp_path, capsys, format):
    scan_id = _seed_canonical(tmp_path, "minimal")
    dest = tmp_path / f"rep.out"
    assert main(["report", scan_id, "--format", format,
                 "--output", str(dest), "--db", _db(tmp_path)]) == 0
    capsys.readouterr()
    assert scan_id in dest.read_text()


def test_report_pdf_output_file(tmp_path, capsys):
    scan_id = _seed_canonical(tmp_path, "minimal")
    dest = tmp_path / "rep.pdf"
    assert main(["report", scan_id, "--format", "pdf",
                 "--output", str(dest), "--db", _db(tmp_path)]) == 0
    capsys.readouterr()
    blob = dest.read_bytes()
    assert blob.startswith(b"%PDF-1.4") and scan_id.encode() in blob


def test_report_pdf_requires_output(tmp_path, capsys):
    scan_id = _seed_canonical(tmp_path, "minimal")
    rc = main(["report", scan_id, "--format", "pdf", "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "--output" in err


def test_report_unknown_scan(tmp_path, capsys):
    rc = main(["report", "bogus-id", "--db", _db(tmp_path)])
    assert rc == 1
    out, err = capsys.readouterr()
    assert "Traceback" not in out + err
    assert "not found" in err


def test_report_invalid_format_rejected():
    with pytest.raises(SystemExit) as exc:
        main(["report", "x", "--format", "bogus"])
    assert exc.value.code == 2


def test_render_unknown_format_rejected():
    with pytest.raises(ValueError):
        report_cmd.render({}, "bogus")


# --- goldens ------------------------------------------------------------


@pytest.mark.parametrize("suffix", ["md", "console.txt", "html"])
@pytest.mark.parametrize("fixture", ["minimal", "empty"])
def test_golden_text(tmp_path, capsys, suffix, fixture):
    scan_id = _seed_canonical(tmp_path, fixture)
    fmt = {"md": "markdown", "console.txt": "console", "html": "html"}[suffix]
    out = _report_stdout(scan_id, tmp_path, capsys, fmt)
    assert out == (GOLDENS / f"{fixture}.{suffix}").read_text()


@pytest.mark.parametrize("fixture", ["minimal", "empty"])
def test_golden_pdf(tmp_path, capsys, fixture):
    scan_id = _seed_canonical(tmp_path, fixture)
    dest = tmp_path / "r.pdf"
    assert main(["report", scan_id, "--format", "pdf",
                 "--output", str(dest), "--db", _db(tmp_path)]) == 0
    capsys.readouterr()
    assert dest.read_bytes() == (GOLDENS / f"{fixture}.pdf").read_bytes()


# --- leakage ------------------------------------------------------------


@pytest.mark.parametrize("format", ["markdown", "console", "html"])
def test_no_db_internals_or_key_markers(tmp_path, capsys, format):
    scan_id = _seed_canonical(tmp_path, "multi")
    out = _report_stdout(scan_id, tmp_path, capsys, format)
    assert "created_at" not in out and "raw_json" not in out
    assert "BEGIN" not in out and "PRIVATE KEY" not in out


def test_pdf_no_db_internals(tmp_path, capsys):
    scan_id = _seed_canonical(tmp_path, "multi")
    dest = tmp_path / "r.pdf"
    assert main(["report", scan_id, "--format", "pdf",
                 "--output", str(dest), "--db", _db(tmp_path)]) == 0
    capsys.readouterr()
    blob = dest.read_bytes()
    assert b"created_at" not in blob and b"raw_json" not in blob


# --- parser + regression ------------------------------------------------


def test_parser_dispatch_report():
    parser = build_parser()
    args = parser.parse_args(["report", "x"])
    assert args.func.__module__ == "ecdat.commands.report_cmd"
    assert args.format == "markdown" and args.output is None


def test_existing_commands_unchanged():
    parser = build_parser()
    assert parser.parse_args(["scan", "a.py"]).func.__module__ == "ecdat.commands.scan_cmd"
    assert parser.parse_args(["export", "x"]).func.__module__ == "ecdat.commands.export_cmd"
    assert parser.parse_args(["risk", "x"]).func.__module__ == "ecdat.commands.risk_cmd"


def test_scan_show_still_work(tmp_path, capsys):
    target = tmp_path / "a.py"
    target.write_text("x = 1\n")
    assert main(["scan", str(target), "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    scan_id = out.strip()
    assert main(["show", scan_id, "--db", _db(tmp_path)]) == 0
    out, _ = capsys.readouterr()
    assert scan_id in out
    out = _report_stdout(scan_id, tmp_path, capsys)
    assert scan_id in out and "mock" in out
