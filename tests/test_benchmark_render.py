"""Tests for Task 21: benchmark HTML + CSV renderers.

Renderers consume hand-built Task 20 reports plus one real
run_suite->build_report pipeline check (proving no metric
recomputation). Hand-checkable literals; stdlib only.
"""

import csv
import io
import json

from ecdat.benchmark import execution as exec_mod
from ecdat.benchmark import render as render_mod
from ecdat.benchmark import report as report_mod
from ecdat.benchmark.predictions import MockPredictionProvider


def _run(group="risk"):
    return exec_mod.run_suite(MockPredictionProvider(), group=group)


def _report(group="risk"):
    return report_mod.build_report(_run(group))


def _evil_run():
    run = exec_mod.run_suite(MockPredictionProvider(), case_ids=[])
    evil = dict(run)
    evil["cases"] = [{
        "case_id": 'x"><script>alert(1)</script>',
        "group": "source", "status": "failed", "predicted": None,
        "error": 'bad & "quoted" <tag>', "counts": None,
        "metrics": None, "synthetic": True}]
    evil["case_count"] = 1
    evil["evaluated_n"] = 0
    evil["failed_n"] = 1
    return evil


# --- HTML ----------------------------------------------------------------------------


def test_html_sections_present():
    html = render_mod.render_html(_report())
    for section in ("Benchmark overview", "Provider / execution mode",
                    "Selection summary", "Overall metrics",
                    "Per-group results", "Per-case results", "Failures",
                    "Unavailable metrics", "Performance / resources",
                    "Disclaimer"):
        assert section in html
    assert html.startswith("<!DOCTYPE html>")
    assert "risk" in html and "mock-predictions" in html


def test_html_synthetic_warning():
    html = render_mod.render_html(_report())
    assert "Synthetic/mock benchmark execution" in html
    assert "not a real ECDAT accuracy claim" in html


def test_html_unavailable_not_zero():
    html = render_mod.render_html(_report())
    # Empty predictions: precision unavailable (n/a + reason), never 0.
    assert "no predicted positives" in html
    assert "<td>precision</td><td>n/a</td>" in html
    # Recall 0.0 is a REAL zero and must render as 0.0, not n/a.
    assert "<td>recall</td><td>0.0</td>" in html


def test_html_offline_self_contained():
    html = render_mod.render_html(_report()).lower()
    for banned in ("cdn", "http://", "https://", "<script", "@import"):
        assert banned not in html


def test_html_escaping():
    html = render_mod.render_html(report_mod.build_report(_evil_run()))
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "bad &amp; &quot;quoted&quot; &lt;tag&gt;" in html


def test_html_deterministic():
    report = _report()
    assert render_mod.render_html(report) == render_mod.render_html(report)


def test_html_ordering_follows_report():
    html = render_mod.render_html(
        report_mod.build_report(exec_mod.run_suite(MockPredictionProvider())))
    first_source = html.index("source.aes.direct")
    assert first_source < html.index("binary.crypto.symbol")
    assert html.index("binary.crypto.symbol") < html.index("risk.high.synthetic")


# --- CSV -------------------------------------------------------------------------------


def _parse(text):
    return list(csv.reader(io.StringIO(text)))


def test_csv_sections_valid_and_ordered():
    sections = render_mod.render_csv_sections(_report())
    assert sorted(sections) == ["cases", "failures", "groups", "overall"]
    groups = _parse(sections["groups"])
    assert groups[0] == ["group", "cases", "evaluated", "failed", "tp",
                         "fp", "tn", "fn", "precision", "recall", "f1",
                         "accuracy", "fpr", "fnr", "specificity",
                         "unavailable"]
    assert groups[1][0] == "risk"
    assert groups[1][1:4] == ["2", "2", "0"]


def test_csv_group_row_values():
    sections = render_mod.render_csv_sections(_report())
    row = _parse(sections["groups"])[1]
    # Empty predictions over risk: TP=0 FP=0 TN=2 FN=3, recall 0.0,
    # precision unavailable (empty cell + reason preserved).
    assert row[4:8] == ["0", "0", "2", "3"]
    assert row[8] == "" and "no predicted positives" in row[15]
    assert row[9] == "0.0"


def test_csv_case_and_failure_rows():
    sections = render_mod.render_csv_sections(_report())
    cases = _parse(sections["cases"])
    assert cases[0][:6] == ["case_id", "group", "title", "status",
                            "synthetic", "predicted_n"]
    assert cases[1][0] == "risk.high.synthetic"
    assert cases[1][4] == "true"
    failures = _parse(sections["failures"])
    assert failures[0] == ["case_id", "group", "error"]
    assert len(failures) == 1  # header only when no failures


def test_csv_failure_row_and_quoting():
    sections = render_mod.render_csv_sections(
        report_mod.build_report(_evil_run()))
    failures = _parse(sections["failures"])
    assert failures[1] == ['x"><script>alert(1)</script>', "source",
                           'bad & "quoted" <tag>']
    cases = _parse(sections["cases"])
    assert cases[1][3] == "failed"
    assert cases[1][6:10] == ["", "", "", ""]  # no fabricated counts


def test_csv_overall_and_determinism():
    sections = render_mod.render_csv_sections(_report())
    overall = _parse(sections["overall"])
    assert overall[0] == ["metric", "value", "unavailable_reason"]
    by_metric = {r[0]: r for r in overall[1:]}
    assert by_metric["tp"][:2] == ["tp", "0"]
    assert by_metric["precision"][1] == ""
    assert "no predicted positives" in by_metric["precision"][2]
    assert render_mod.render_csv_sections(_report()) == sections


def test_csv_none_never_zero():
    sections = render_mod.render_csv_sections(_report())
    for text in sections.values():
        for row in _parse(text)[1:]:
            assert "None" not in row


# --- integration ------------------------------------------------------------------------------


def test_renderers_consume_report_without_recompute():
    run = _run()
    report = report_mod.build_report(run)
    html = render_mod.render_html(report)
    sections = render_mod.render_csv_sections(report)
    assert str(run["totals"]["fn"]) in html
    assert str(run["aggregate"]["recall"]) in html
    assert "risk,2,2,0,0,0,2,3" in sections["groups"]
    assert report["synthetic"] is True
    assert json.loads(json.dumps(sections)) == sections  # serializable
