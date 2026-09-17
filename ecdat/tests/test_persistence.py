"""Phase 11 regression: unified persistence, exports, and CI behavior.

Proves GUI and CLI share one durable scan model and every export
derives from it:

- ScanRepository round-trips canonical + CIR + plan + diagnostics and
  serves scan history (newest first) with meta availability;
- v1/v2 databases migrate to v3 (scan_meta appears, old rows intact);
- same input through the orchestrator as cli/gui/ci callers yields the
  same scan_id and operation set (presentation may differ, truth may not);
- json/csv/cbom-json/cbom-xml/sarif exports derive from the stored doc
  and agree on finding counts/IDs; SARIF locations are stable;
- CI gates the real pipeline result and reports limitations instead of
  a silent green gate.
"""

from __future__ import annotations

import json
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path

from ecdat.commands import ci_cmd, export_cmd
from ecdat.core.orchestrator import ScanRequest, get_orchestrator
from ecdat.store import db
from ecdat.store.repository import ScanRepository


def _scan_target(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    root.mkdir(exist_ok=True)
    (root / "app.py").write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "def f(k, n, d):\n    return AESGCM(k).encrypt(n, d, None)\n")
    return root


def _stored_result(tmp_path: Path, db_name: str = "t.db"):
    target = _scan_target(tmp_path)
    result = get_orchestrator().scan(
        ScanRequest(target=str(target), scanners=["source"],
                    caller="phase11-persist"))
    repo = ScanRepository(tmp_path / db_name)
    try:
        scan_id = repo.save_scan(result.canonical, result.cir,
                                 result.plan.as_dict(), result.diagnostics)
    finally:
        repo.close()
    return scan_id, result


def test_repository_round_trip_and_history(tmp_path):
    scan_id, result = _stored_result(tmp_path)
    repo = ScanRepository(tmp_path / "t.db")
    try:
        payload = repo.get_payload(scan_id)
        assert payload is not None
        assert payload["canonical"]["scan_id"] == scan_id
        assert payload["cir"]["scan_id"] == scan_id
        assert payload["plan"]["target"].endswith("app")
        assert isinstance(payload["diagnostics"], dict)
        assert payload["diagnostics"]["registry_version"]
        history = repo.list_scans()
        assert [h["id"] for h in history] == [scan_id]
        assert history[0]["has_plan"] is True
        assert history[0]["has_diagnostics"] is True
        assert repo.count_scans() == 1
        assert repo.get_payload("scan:0000000000000000") is None
    finally:
        repo.close()


def test_repository_replace_semantics(tmp_path):
    scan_id, result = _stored_result(tmp_path)
    repo = ScanRepository(tmp_path / "t.db")
    try:
        # GUI re-scans overwrite; plain double-stores stay loud.
        again = repo.save_scan(result.canonical, result.cir,
                               result.plan.as_dict(), result.diagnostics,
                               replace=True)
        assert again == scan_id
        assert repo.count_scans() == 1
        try:
            repo.save_scan(result.canonical, result.cir)
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("double store without replace must fail")
    finally:
        repo.close()


def test_schema_migrates_v1_to_v3(tmp_path):
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(path))
    conn.execute(
        "CREATE TABLE scans (id TEXT PRIMARY KEY, target TEXT NOT NULL,"
        " started_at TEXT NOT NULL, finished_at TEXT NOT NULL,"
        " raw_json TEXT NOT NULL, created_at TEXT NOT NULL)")
    conn.execute(
        "CREATE TABLE findings (id INTEGER PRIMARY KEY,"
        " scan_id TEXT NOT NULL, rule_id TEXT NOT NULL,"
        " severity TEXT NOT NULL, file TEXT NOT NULL, line INTEGER NOT NULL,"
        " title TEXT NOT NULL, confidence REAL)")
    conn.execute(
        "INSERT INTO scans (id, target, started_at, finished_at,"
        " raw_json, created_at) VALUES ('scan:old', 't', 'a', 'b', '{}', 'c')")
    conn.execute("PRAGMA user_version = 1;")
    conn.commit()
    conn.close()
    conn = db.open_db(path)
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(scans)")]
        assert "cir_json" in cols  # v2 migration applied
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert "scan_meta" in tables  # v3 migration applied
        row = conn.execute(
            "SELECT id FROM scans WHERE id='scan:old'").fetchone()
        assert row is not None  # legacy rows preserved
    finally:
        conn.close()


def test_cli_gui_ci_same_truth(tmp_path):
    target = _scan_target(tmp_path)
    results = {}
    for caller in ("cli-scan", "gui", "ci"):
        results[caller] = get_orchestrator().scan(
            ScanRequest(target=str(target), scanners=["source"],
                        caller=caller))
    ids = {r.scan_id for r in results.values()}
    assert len(ids) == 1, f"callers must share one scan_id: {ids}"
    op_sets = [{o["operation_id"] for o in r.cir["operations"]}
               for r in results.values()]
    assert op_sets[0] == op_sets[1] == op_sets[2]


def test_exports_agree_with_stored_doc(tmp_path):
    scan_id, result = _stored_result(tmp_path)
    repo = ScanRepository(tmp_path / "t.db")
    try:
        doc = repo.get_payload(scan_id)["canonical"]
    finally:
        repo.close()
    expected = len(doc["findings"])
    by_format = {}
    for fmt in ("json", "csv", "cbom-json", "cbom-xml", "sarif"):
        by_format[fmt] = export_cmd.render(doc, fmt)
    assert json.loads(by_format["json"])["scan_id"] == scan_id
    csv_lines = by_format["csv"].splitlines()
    assert len(csv_lines) == expected + 1  # header + one row per finding
    cbom = json.loads(by_format["cbom-json"])
    assert cbom["metadata"]["component"]["bom-ref"] == scan_id
    assert len(cbom["components"]) == expected
    ET.fromstring(by_format["cbom-xml"])  # well-formed XML
    sarif = json.loads(by_format["sarif"])
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == expected
    # Stable locations: uri == file, line passes through verbatim.
    for entry, finding in zip(sarif["runs"][0]["results"],
                              doc["findings"]):
        loc = entry["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == finding["file"]
        assert loc["region"]["startLine"] == finding["line"]


def test_ci_gates_real_result_with_limitations(tmp_path):
    target = _scan_target(tmp_path)
    result = get_orchestrator().scan(
        ScanRequest(target=str(target), scanners=["source"], caller="ci"))
    cir, doc = result.as_tuple()
    gated = ci_cmd.build_result(str(target), doc, "critical",
                                None, {"score": 1.0, "level": "low"},
                                result.diagnostics)
    assert gated["scan_id"] == doc["scan_id"]
    assert gated["finding_count"] == len(doc["findings"])
    assert set(gated["limitations"]) == {
        "unavailable_tools", "permission_gated",
        "failed_scanners", "cache_hit"}
    assert gated["verdict"] in ("pass", "fail")
    lines = ci_cmd._summary_lines(gated)
    assert any(str(doc["scan_id"]) in line for line in lines)
