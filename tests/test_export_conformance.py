"""Export conformance acceptance (Task 28).

Proves cross-format consistency that per-format unit tests do not:
every format's finding counts agree with the canonical findings for
empty/minimal/multi scans, CycloneDX/SARIF envelopes are
structurally valid, all renders are deterministic, and report
outputs carry the scan identity plus mock labels. Stdlib only.
"""

import csv
import io
import json
import xml.etree.ElementTree as ET

from ecdat.cli import main
from ecdat.core.validate import load_json, validate

FORMATS = ("json", "csv", "cbom-json", "cbom-xml", "sarif")
CANON = ("empty", "minimal", "multi")
EXPECTED_COUNTS = {"empty": 0, "minimal": 1, "multi": 4}


def _seed(tmp_path, capsys, name):
    target = tmp_path / name
    if name == "app":
        target.mkdir(exist_ok=True)
        (target / "m.py").write_text("x = 1\n")
    else:
        target.write_text("x = 1\n")
    assert main(["scan", str(target), "--db", str(tmp_path / "c.db")]) == 0
    capsys.readouterr()  # drain scan_id print


def _export(tmp_path, capsys, scan_id, format):
    assert main(["export", scan_id, "--db", str(tmp_path / "c.db"),
                 "--format", format]) == 0
    out, _ = capsys.readouterr()
    return out


def _scan_id_for(tmp_path, fixture):
    return {"empty": "scan-empty-001", "minimal": "scan-minimal-001",
            "multi": "scan-multi-001"}[fixture]


def test_counts_agree_with_canonical_across_formats(tmp_path, capsys):
    _seed(tmp_path, capsys, "clean.py")
    _seed(tmp_path, capsys, "a.py")
    _seed(tmp_path, capsys, "app")
    for fixture in CANON:
        scan_id = _scan_id_for(tmp_path, fixture)
        n = EXPECTED_COUNTS[fixture]
        doc = json.loads(_export(tmp_path, capsys, scan_id, "json"))
        validate(doc)
        assert len(doc["findings"]) == n
        rows = list(csv.DictReader(io.StringIO(
            _export(tmp_path, capsys, scan_id, "csv"))))
        assert len(rows) == n
        cbom = json.loads(_export(tmp_path, capsys, scan_id, "cbom-json"))
        assert len(cbom["components"]) == n
        assert len(cbom["vulnerabilities"]) == n
        sarif = json.loads(_export(tmp_path, capsys, scan_id, "sarif"))
        assert len(sarif["runs"][0]["results"]) == n


def test_cyclonedx_envelope(tmp_path, capsys):
    _seed(tmp_path, capsys, "a.py")
    cbom = json.loads(_export(tmp_path, capsys, "scan-minimal-001",
                              "cbom-json"))
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"].startswith("1.")
    assert cbom["components"][0]["name"] == "RSA-1024"
    root = ET.fromstring(_export(tmp_path, capsys, "scan-minimal-001",
                                 "cbom-xml"))
    assert root.tag.endswith("bom")
    ns = {"c": "http://cyclonedx.org/schema/bom/1.6"}
    assert len(root.findall("./c:components/c:component", ns)) == 1


def test_sarif_rules_cover_findings(tmp_path, capsys):
    _seed(tmp_path, capsys, "app")
    sarif = json.loads(_export(tmp_path, capsys, "scan-multi-001", "sarif"))
    assert sarif["version"] == "2.1.0"
    assert {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]} == \
        {r["ruleId"] for r in sarif["runs"][0]["results"]}


def test_all_formats_deterministic(tmp_path, capsys):
    _seed(tmp_path, capsys, "app")
    for format in FORMATS:
        first = _export(tmp_path, capsys, "scan-multi-001", format)
        assert _export(tmp_path, capsys, "scan-multi-001", format) == first


def test_report_outputs_carry_scan_identity_and_mock(tmp_path, capsys):
    _seed(tmp_path, capsys, "a.py")
    assert main(["report", "scan-minimal-001", "--db",
                 str(tmp_path / "c.db"), "--format", "html"]) == 0
    out, _ = capsys.readouterr()
    assert out.startswith("<!DOCTYPE html>")
    assert "scan-minimal-001" in out and "mock" in out.lower()
    assert main(["report", "scan-minimal-001", "--db",
                 str(tmp_path / "c.db"), "--format", "markdown"]) == 0
    out, _ = capsys.readouterr()
    assert "scan-minimal-001" in out


def test_canonical_fixtures_validate():
    for fixture in CANON:
        validate(load_json(
            f"tests/fixtures/canonical/{fixture}.json"))
