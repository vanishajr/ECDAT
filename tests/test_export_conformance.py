"""Export conformance acceptance (unified backend).

Proves cross-format consistency that per-format unit tests do not:
every format's finding counts agree with the canonical findings for
real scans, CycloneDX/SARIF envelopes are structurally valid, all
renders are deterministic, and report outputs carry the scan identity.
"""

import csv
import io
import json
import xml.etree.ElementTree as ET

from ecdat.cli import main
from ecdat.core.validate import load_json, validate

FORMATS = ("json", "csv", "cbom-json", "cbom-xml", "sarif")
CANON = ("empty", "minimal", "multi")

CRYPTO_PY = "import hashlib\nh = hashlib.md5(b'ecdat-conformance').hexdigest()\n"


def _seed(tmp_path, capsys):
    target = tmp_path / "c.py"
    target.write_text(CRYPTO_PY)
    assert main(["scan", str(target), "--db", str(tmp_path / "c.db")]) == 0
    out, _ = capsys.readouterr()
    return out.strip()


def _export(tmp_path, capsys, scan_id, format):
    assert main(["export", scan_id, "--db", str(tmp_path / "c.db"),
                 "--format", format]) == 0
    out, _ = capsys.readouterr()
    return out


def test_counts_agree_with_canonical_across_formats(tmp_path, capsys):
    scan_id = _seed(tmp_path, capsys)
    doc = json.loads(_export(tmp_path, capsys, scan_id, "json"))
    validate(doc)
    n = len(doc["findings"])
    assert n >= 1
    rows = list(csv.DictReader(io.StringIO(
        _export(tmp_path, capsys, scan_id, "csv"))))
    assert len(rows) == n
    cbom = json.loads(_export(tmp_path, capsys, scan_id, "cbom-json"))
    assert len(cbom["components"]) == n
    assert len(cbom["vulnerabilities"]) == n
    sarif = json.loads(_export(tmp_path, capsys, scan_id, "sarif"))
    assert len(sarif["runs"][0]["results"]) == n


def test_cyclonedx_envelope(tmp_path, capsys):
    scan_id = _seed(tmp_path, capsys)
    cbom = json.loads(_export(tmp_path, capsys, scan_id, "cbom-json"))
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"].startswith("1.")
    assert cbom["components"][0]["type"] == "cryptographic-asset"
    root = ET.fromstring(_export(tmp_path, capsys, scan_id, "cbom-xml"))
    assert root.tag.endswith("bom")
    ns = {"c": "http://cyclonedx.org/schema/bom/1.6"}
    assert len(root.findall("./c:components/c:component", ns)) >= 1


def test_sarif_rules_cover_findings(tmp_path, capsys):
    scan_id = _seed(tmp_path, capsys)
    sarif = json.loads(_export(tmp_path, capsys, scan_id, "sarif"))
    assert sarif["version"] == "2.1.0"
    assert {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]} == \
        {r["ruleId"] for r in sarif["runs"][0]["results"]}


def test_all_formats_deterministic(tmp_path, capsys):
    scan_id = _seed(tmp_path, capsys)
    for format in FORMATS:
        first = _export(tmp_path, capsys, scan_id, format)
        assert _export(tmp_path, capsys, scan_id, format) == first


def test_report_outputs_carry_scan_identity(tmp_path, capsys):
    scan_id = _seed(tmp_path, capsys)
    assert main(["report", scan_id, "--db",
                 str(tmp_path / "c.db"), "--format", "html"]) == 0
    out, _ = capsys.readouterr()
    assert out.startswith("<!DOCTYPE html>")
    assert scan_id in out
    assert main(["report", scan_id, "--db",
                 str(tmp_path / "c.db"), "--format", "markdown"]) == 0
    out, _ = capsys.readouterr()
    assert scan_id in out


def test_canonical_fixtures_validate():
    for fixture in CANON:
        validate(load_json(
            f"tests/fixtures/canonical/{fixture}.json"))
