"""Tests for Task 23: benchmark PDF renderer.

Asserts structure (%PDF header/trailer/xref), section presence,
metric preservation incl. n/a honesty, failure/synthetic
handling, native vector bars, byte determinism for one report,
and the --pdf CLI. Hand-built fixture data where exactness
matters; stdlib only.
"""

import re

from ecdat.benchmark import execution as exec_mod
from ecdat.benchmark import pdf as pdf_mod
from ecdat.benchmark import report as report_mod
from ecdat.benchmark.predictions import MockPredictionProvider


def _report(**kwargs):
    run = exec_mod.run_suite(MockPredictionProvider(), **kwargs)
    return report_mod.build_report(run)


def _text(pdf: bytes) -> str:
    return pdf.decode("ascii")


# --- structure ------------------------------------------------------------------------


def test_pdf_header_trailer_xref():
    pdf = pdf_mod.render_pdf(_report(group="risk"))
    assert pdf.startswith(b"%PDF-1.4\n")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert b"\nxref\n" in pdf and b"startxref" in pdf
    assert len(pdf) > 2000


def test_pdf_multi_page_for_full_suite():
    pdf = pdf_mod.render_pdf(_report())
    match = re.search(rb"/Count (\d+)", pdf)
    assert match is not None
    assert int(match.group(1)) >= 2
    assert len(re.findall(rb"\d+ 0 obj", pdf)) >= 6


def test_pdf_sections_present():
    text = _text(pdf_mod.render_pdf(_report(group="config")))
    for section in ("Selection", "Overall metrics", "Per-group results",
                    "Per-case results", "Failures", "Unavailable metrics",
                    "Performance / resources", "Charts",
                    "Disclaimer / reproducibility"):
        assert section in text
    assert "config.tls.weak" in text
    assert "mock-predictions" in text


# --- metric preservation -----------------------------------------------------------------


def test_pdf_metrics_preserved_not_zeroed():
    text = _text(pdf_mod.render_pdf(_report(group="risk")))
    # Empty predictions: precision n/a (never 0), recall a real 0.0.
    assert "P=n/a" in text
    assert "R=0.0" in text
    assert "TP=0 FP=0" in text


def test_pdf_failures_and_unavailable_preserved():
    run = exec_mod.run_suite(
        MockPredictionProvider(errors={"risk.high.synthetic": "demo down"}),
        group="risk")
    text = _text(pdf_mod.render_pdf(report_mod.build_report(run)))
    assert "risk.high.synthetic" in text and "demo down" in text
    assert "FAILED" in text
    assert "no predicted positives" in text


def test_pdf_synthetic_warning():
    text = _text(pdf_mod.render_pdf(_report(group="binary")))
    assert "Synthetic/mock benchmark execution" in text
    assert "not a real ECDAT accuracy claim" in text


# --- native vector bars -----------------------------------------------------------------------


def test_pdf_contains_vector_bars_and_na_boxes():
    pdf = pdf_mod.render_pdf(_report(group="risk"))
    assert pdf.count(b" re f") >= 5  # filled bars + grey n/a boxes
    assert b"(n/a: unavailable)" in pdf
    assert b" rg " in pdf  # colored bar fills present


# --- determinism -------------------------------------------------------------------------------


def test_pdf_deterministic_for_same_report():
    report = _report(group="fusion")
    assert pdf_mod.render_pdf(report) == pdf_mod.render_pdf(report)


# --- file + CLI -------------------------------------------------------------------------------------


def test_write_pdf_file(tmp_path):
    dest = tmp_path / "bench.pdf"
    assert pdf_mod.write_pdf(_report(group="config"), dest) == str(dest)
    assert dest.read_bytes().startswith(b"%PDF-1.4")


def test_cli_pdf_option(tmp_path, capsys):
    from ecdat.benchmark import __main__ as bench_main
    dest = tmp_path / "suite.pdf"
    assert bench_main.main(
        ["suite-run", "--group", "risk", "--pdf", str(dest)]) == 0
    capsys.readouterr()
    assert dest.read_bytes().startswith(b"%PDF-1.4")
