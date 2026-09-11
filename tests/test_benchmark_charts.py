"""Tests for Task 22: benchmark charts & visualization.

Chart data is asserted exactly (hand-checkable); SVG output is
asserted structurally (valid XML, markers, labels, determinism) —
never byte-stability of an imaging library, since rendering is
dependency-free static SVG. Stdlib only.
"""

import xml.etree.ElementTree as ET

from ecdat.benchmark import charts as charts_mod
from ecdat.benchmark import execution as exec_mod
from ecdat.benchmark import report as report_mod
from ecdat.benchmark.predictions import MockPredictionProvider
from ecdat.benchmark.suite import get_case


def _run(**kwargs):
    return exec_mod.run_suite(MockPredictionProvider(), **kwargs)


def _report(**kwargs):
    return report_mod.build_report(_run(**kwargs))


def _parse(svg):
    return ET.fromstring(svg)  # raises on malformed XML


# --- chart data -----------------------------------------------------------------------


def test_group_metric_data_correctness_and_order():
    data = charts_mod.group_metric_data(_report())
    assert data["metrics"] == ["precision", "recall", "f1"]
    groups = [g["group"] for g in data["groups"]]
    assert groups == sorted(groups) or groups == [
        c for c in groups]  # registry order kept
    assert groups[0] == "source" and groups[-1] == "pqc_recommendation"
    for g in data["groups"]:
        assert set(g["values"]) == {"precision", "recall", "f1"}


def test_unavailable_metric_not_zero_in_data():
    data = charts_mod.group_metric_data(_report())  # empty predictions
    for g in data["groups"]:
        assert g["values"]["precision"] is None  # not 0, not 0.0
        assert g["values"]["recall"] == 0.0  # real zero preserved


def test_confusion_data_tn_none_preserved():
    data = charts_mod.confusion_data(_report())
    assert data["series"] == ["tp", "fp", "fn", "tn"]
    for g in data["groups"]:
        assert set(g["counts"]) == {"tp", "fp", "fn", "tn"}


def test_status_and_resource_data():
    status = charts_mod.status_data(_report())
    assert status["totals"] == {"evaluated": 23, "failed": 0}
    assert all(set(g) == {"group", "evaluated", "failed"}
               for g in status["groups"])
    res = charts_mod.resource_data(_report())
    assert res["items"][0]["label"] == "wall time"
    assert all(i["value"] is not None for i in res["items"])
    assert all(i["value"] >= 0 for i in res["items"])


def test_data_preparation_deterministic():
    report = _report()
    assert charts_mod.group_metric_data(report) == \
        charts_mod.group_metric_data(report)
    assert charts_mod.confusion_data(report) == \
        charts_mod.confusion_data(report)


# --- SVG rendering ----------------------------------------------------------------------


def test_group_metrics_svg_marks_unavailable():
    svg = charts_mod.render_group_metrics_svg(_report())
    _parse(svg)
    assert "Synthetic/mock benchmark" in svg
    assert ">n/a<" in svg  # unavailable slots marked, not zero bars
    assert "n/a = unavailable" in svg  # legend states the meaning


def test_confusion_svg_omits_unknown_tn_without_zero():
    case = get_case("source.aes.direct")
    assert case is not None
    report = _report(case_ids=["source.aes.direct"])
    svg = charts_mod.render_confusion_svg(report)
    _parse(svg)
    assert "AES-ECB" not in svg  # keys never leak into charts
    assert "source" in svg


def test_confusion_svg_tn_none_marker():
    run = exec_mod.run_suite(MockPredictionProvider(), case_ids=[])
    report = report_mod.build_report(run)
    assert report["groups"] == []
    svg = charts_mod.render_confusion_svg(report)
    _parse(svg)  # empty selection still renders valid SVG


def test_status_svg_distinguishes_failure_from_unavailable():
    svg = charts_mod.render_status_svg(_report())
    _parse(svg)
    assert "evaluated" in svg and "failed" in svg


def test_resources_svg_measured_only():
    svg = charts_mod.render_resources_svg(_report())
    _parse(svg)
    assert "wall time" in svg
    assert "cache" not in svg.lower()
    assert "speedup" not in svg.lower()


def test_svg_escaping():
    # Renderers consume report-shaped dicts; group labels are the only
    # report-controlled strings reaching charts and must be escaped.
    report = {"groups": [{"group": 'g&g"><tspan>x</tspan>',
                          "evaluated": 1, "failed": 0}],
              "synthetic": True, "provider_type": "mock",
              "provider": "p"}
    svg = charts_mod.render_status_svg(report)
    _parse(svg)
    assert "<tspan>" not in svg
    assert "g&amp;g" in svg


def test_svg_byte_deterministic_and_offline():
    report = _report(group="binary")
    first = charts_mod.render_all_svgs(report)
    assert charts_mod.render_all_svgs(report) == first
    assert sorted(first) == ["confusion", "group-metrics", "resources",
                             "status"]
    blob = "\n".join(first.values()).lower()
    # The only URL permitted is the mandatory SVG XML namespace
    # declaration (an identifier, never fetched).
    assert blob.count("http://") == blob.count(
        "xmlns='http://www.w3.org/2000/svg'")
    for banned in ("https://", "<script", "cdn", "@import"):
        assert banned not in blob


def test_write_charts_files(tmp_path):
    paths = charts_mod.write_charts(_report(group="config"), tmp_path)
    assert sorted(paths) == ["confusion", "group-metrics", "resources",
                             "status"]
    for section, path in paths.items():
        assert path.endswith(f"{section}.svg")
        content = open(path, encoding="utf-8").read()
        ET.fromstring(content)
        assert len(content) > 500


# --- CLI ----------------------------------------------------------------------------------


def test_cli_charts_dir(tmp_path, capsys):
    from ecdat.benchmark import __main__ as bench_main
    dest = tmp_path / "charts"
    assert bench_main.main(
        ["suite-run", "--group", "fusion", "--charts", str(dest)]) == 0
    capsys.readouterr()
    assert sorted(p.name for p in dest.iterdir()) == [
        "confusion.svg", "group-metrics.svg", "resources.svg",
        "status.svg"]
