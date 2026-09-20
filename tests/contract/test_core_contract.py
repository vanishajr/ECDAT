"""Consumer-contract tests: CoreClient output accepted by P3.

Defines WHAT P3 ACCEPTS from the integrated client — never how analysis
implements it. A hand-built canonical doc feeds the real consumer chain
(validate -> store -> report -> renderers); malformed output is rejected
with existing errors and never stored or silently repaired.
"""

import copy
import json

import pytest
from jsonschema import ValidationError

from ecdat.commands import export_cmd, report_cmd
from ecdat.core.validate import validate
from ecdat.reports.aggregate import build_report
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore


def _valid_doc() -> dict:
    """Small hand-readable canonical doc; independent of detectors."""
    return {
        "schema_version": "1.0",
        "scan_id": "contract-001",
        "target": "contract/app.py",
        "started_at": "2026-09-10T16:00:00Z",
        "finished_at": "2026-09-10T16:00:01Z",
        "tool_versions": {"ecdat": "0.1.0"},
        "findings": [
            {"rule_id": "RSA-1024", "title": "Weak RSA key",
             "severity": "high", "file": "contract/app.py", "line": 7},
            {"rule_id": "TLS-1.0", "title": "Old TLS",
             "severity": "low", "file": "contract/app.py", "line": 3,
             "snippet": "ssl.PROTOCOL_TLSv1", "confidence": 0.8,
             "metadata": {"source": "contract-fixture"}},
        ],
        "stats": {"files_scanned": 1, "findings_count": 2},
    }


class _FakeClient:
    """Stands in for a future P1 client: returns exactly what built."""

    name = "fake-p1"

    def __init__(self, doc: dict):
        self._doc = doc

    def scan(self, target):  # noqa: ARG002
        return copy.deepcopy(self._doc)


def _consume(db_path: str, doc: dict) -> dict:
    """The real P3 consumer chain for one client-produced doc."""
    validate(doc)
    conn = db.open_db(db_path)
    try:
        sstore.insert_scan(conn, doc)
        fstore.insert_findings_for_scan(conn, doc)
        stored = sstore.get_scan_doc(conn, doc["scan_id"])
    finally:
        conn.close()
    assert stored is not None
    return stored


def test_valid_client_output_flows_to_reports(tmp_path):
    stored = _consume(str(tmp_path / "c.db"), _FakeClient(_valid_doc()).scan("x"))
    rep = build_report(stored)
    assert rep["finding_count"] == 2
    # Hand-built docs carry no CIR sidecar: risk stays unattributed
    # (never invented) while inventory/renderers still work.
    assert rep["risk"]["level"] == "none"
    assert rep["risk"]["risk_count"] == 0
    md = report_cmd.render(rep, "markdown")
    assert isinstance(md, str) and md.startswith("#")
    html = report_cmd.render(rep, "html")
    assert isinstance(html, str) and html.startswith("<!DOCTYPE html>")
    pdf = report_cmd.render(rep, "pdf")
    assert isinstance(pdf, bytes) and pdf.startswith(b"%PDF-1.4")
    console = report_cmd.render(rep, "console")
    assert isinstance(console, str) and console.splitlines()
    assert export_cmd.render(stored, "csv").splitlines()[0].startswith("scan_id,")
    assert json.loads(export_cmd.render(stored, "sarif"))["version"] == "2.1.0"


def test_serialization_deterministic():
    doc = _valid_doc()
    assert (json.dumps(doc, sort_keys=True) ==
            json.dumps(copy.deepcopy(doc), sort_keys=True))


@pytest.mark.parametrize("mutate", [
    lambda d: d["findings"].__setitem__(0, {k: v for k, v in d["findings"][0].items() if k != "severity"}),
    lambda d: d["findings"][0].__setitem__("severity", "CRITICAL"),
    lambda d: d["findings"][0].__setitem__("severity", "unknown"),
    lambda d: d["findings"][0].__setitem__("line", "7"),
    lambda d: d["findings"][0].__setitem__("line", True),
    lambda d: d["findings"][1].__setitem__("metadata", "oops"),
    lambda d: d.__setitem__("extra_top_level", 1),
    lambda d: d["findings"].append({"bogus": True}),
])
def test_malformed_client_output_rejected(tmp_path, mutate):
    doc = _valid_doc()
    mutate(doc)
    with pytest.raises(ValidationError):
        validate(doc)
    conn = db.open_db(str(tmp_path / "c.db"))
    try:
        assert sstore.count_scans(conn) == 0  # nothing stored before validate
    finally:
        conn.close()
