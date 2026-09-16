"""Three-way integration tests: P2 discovery -> CIR -> P1 analysis -> P3.

Covers the P3-owned pipeline, normalization, storage sidecar, real
branches of risk/migration/graph/reports, CLI/GUI over real data, and
REAL-mode failure semantics (loud errors, never mock fallback).
Requires pydantic/pyyaml/cryptography (real-path deps); skipped
otherwise so the mock suite stays stdlib-only.
"""

from __future__ import annotations

import json
import re
import socket
import sys
import types
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    __import__("importlib").util.find_spec("pydantic") is None,
    reason="real pipeline needs pydantic",
)

from ecdat.adapters import normalize as norm
from ecdat.adapters import scanner_policy as policy
from ecdat.adapters.pipeline import RealScanError, run_real_scan
from ecdat.core.client import RealCoreClient, get_client
from ecdat.core.validate import validate as validate_canonical
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore

RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _crypto_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        "h = hashlib.md5(b'x').hexdigest()\n"
    )
    (proj / "requirements.txt").write_text("cryptography>=42.0\n")
    return proj


def _dep_only_project(tmp_path: Path) -> Path:
    proj = tmp_path / "deponly"
    proj.mkdir()
    (proj / "requirements.txt").write_text("cryptography>=42.0\n")
    return proj


def _scan_fixture(tmp_path: Path):
    proj = _crypto_project(tmp_path)
    return run_real_scan(str(proj)), proj


def _complete_job(svc, target: str) -> dict:
    """Drive a GUI job to its terminal snapshot (asserts completion)."""
    job = svc.submit(target)
    done = None
    for _ in range(5):
        done = svc.status(job["job_id"])
        if done is not None and done["status"] == "completed":
            break
    assert done is not None and done["status"] == "completed"
    return done


# --- CIR validation ------------------------------------------------------


def test_cir_validates_against_p1_schema(tmp_path):
    from ecdat.core import cir_validate as cv

    (cir, _doc), _proj = _scan_fixture(tmp_path)
    assert cv.validate_cir(cir) is cir or cv.validate_cir(cir) == cir


def test_cir_validation_rejects_garbage():
    from ecdat.core import cir_validate as cv

    with pytest.raises(Exception):
        cv.validate_cir({})
    with pytest.raises(Exception):
        cv.validate_cir({"cir_version": "9.9"})


# --- P2 -> P1 handoff ------------------------------------------------------


def test_enrich_adds_wire_risks_and_recommendations(tmp_path):
    from ecdat.core import api as papi

    (cir, _doc), _proj = _scan_fixture(tmp_path)
    assert cir["risks"], "expected P1 wire risks"
    assert cir["recommendations"], "expected P1 wire recommendations"
    risk = cir["risks"][0]
    assert set(risk) >= {"risk_id", "class", "title", "confidence",
                         "operation_id", "score"}
    assert risk["class"] in ("Critical", "High", "Medium", "Low",
                             "Informational")
    assert 0 <= risk["score"] <= 10
    rec = cir["recommendations"][0]
    assert set(rec) >= {"recommendation_id", "title", "priority",
                        "asset_ids", "pqc_target"}


def test_canonical_conversion_content(tmp_path):
    (_cir, doc), _proj = _scan_fixture(tmp_path)
    validate_canonical(doc)
    by_rule = {f["rule_id"]: f for f in doc["findings"]}
    assert "RSA-1024" in by_rule and "MD5" in by_rule
    for finding in doc["findings"]:
        assert {"rule_id", "title", "severity", "file", "line"} <= set(finding)
        assert finding["severity"] in ("info", "low", "medium", "high",
                                       "critical")
        assert isinstance(finding["line"], int) and finding["line"] >= 0
    assert doc["stats"]["findings_count"] == len(doc["findings"])


def test_api_scan_not_used_by_pipeline(tmp_path):
    # The integrated path must not call P1's self-scanning api.scan()
    # (which would scan the target a second time).
    import ecdat.adapters.pipeline as pipe_mod

    assert "api.scan(" not in open(pipe_mod.__file__).read().replace(
        "run_real_scan(", "")


# --- deterministic IDs / timestamps / files_scanned ------------------------


def test_deterministic_scan_id_format_and_rerun(tmp_path):
    proj = _crypto_project(tmp_path)
    (_c1, d1) = run_real_scan(str(proj))
    (_c2, d2) = run_real_scan(str(proj))
    assert d1["scan_id"] == d2["scan_id"]
    assert re.match(r"^scan:[0-9a-f]{16}$", d1["scan_id"])
    assert "uuid" not in d1["scan_id"]


def test_scan_id_unit():
    sid = norm.deterministic_scan_id("t", "2026.09.11", {"a": "1"}, ["op:1"])
    assert re.match(r"^scan:[0-9a-f]{16}$", sid)
    assert norm.deterministic_scan_id("t", "2026.09.11", {"a": "1"},
                                      ["op:1"]) == sid
    assert norm.deterministic_scan_id("other", "2026.09.11", {"a": "1"},
                                      ["op:1"]) != sid


def test_timestamps_valid_rfc3339(tmp_path):
    (cir, doc), _proj = _scan_fixture(tmp_path)
    for value in (cir["started_at"], cir["finished_at"],
                  doc["started_at"], doc["finished_at"]):
        assert RFC3339.match(value), value


def test_timestamp_normalization_units():
    assert norm.to_rfc3339("2026-09-15T10:00:00+00:00Z") == "2026-09-15T10:00:00Z"
    assert norm.to_rfc3339("2026-09-15T10:00:00Z") == "2026-09-15T10:00:00Z"
    assert norm.to_rfc3339("2026-09-15T10:00:00+00:00") == "2026-09-15T10:00:00Z"
    from datetime import datetime, timezone

    assert norm.to_rfc3339(
        datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc)
    ) == "2026-09-15T10:00:00Z"
    with pytest.raises(ValueError):
        norm.to_rfc3339("not-a-time")
    with pytest.raises(ValueError):
        norm.to_rfc3339("")


def test_files_scanned_derived(tmp_path):
    (cir, doc), _proj = _scan_fixture(tmp_path)
    assert doc["stats"]["files_scanned"] == 2
    assert set(norm.files_from_cir(cir)) == {
        str(_proj / "app.py"), str(_proj / "requirements.txt")}


# --- asset-only findings ----------------------------------------------------


def test_dependency_only_assets_preserved(tmp_path):
    proj = _dep_only_project(tmp_path)
    cir, doc = run_real_scan(str(proj))
    validate_canonical(doc)
    asset_only = [f for f in doc["findings"]
                  if f.get("metadata", {}).get("asset_only") is True]
    assert asset_only, "dependency-only asset vanished from canonical"
    finding = asset_only[0]
    assert finding["severity"] == "info"
    assert finding["metadata"]["usage_state"] == "ProvidedOnly"
    assert finding["metadata"]["cir_asset_id"].startswith("ast:")
    assert "requirements.txt" in finding["file"]


# --- risk integration -------------------------------------------------------


def test_service_risk_summary_real_branch(tmp_path):
    from ecdat.gui.service import GuiService

    proj = _crypto_project(tmp_path)
    svc = GuiService(tmp_path / "r.db", client=RealCoreClient())
    done = _complete_job(svc, str(proj))
    assert done["mock"] is False
    assert done["mock"] is False
    risk = svc.risk_summary(done["scan_id"])
    assert risk is not None and risk["mock"] is False
    assert risk["source"].startswith("p1-risk")
    assert "mock" not in risk["model"].lower()
    assert risk["level"] in ("critical", "high", "medium", "low", "info",
                             "none")
    assert set(risk["severity_counts"]) == {"critical", "high", "medium",
                                            "low", "info"}


def test_mock_risk_branch_unchanged(tmp_path):
    from ecdat.gui.service import GuiService

    svc = GuiService(tmp_path / "m.db")
    done = _complete_job(svc, "samples/rsa_small.py")
    risk = svc.risk_summary(done["scan_id"])
    assert risk["mock"] is True
    assert "mock" in risk["model"].lower()


# --- migration integration --------------------------------------------------


def test_migration_items_match_contract(tmp_path):
    from ecdat.adapters import migration_adapter as ma

    (cir, _doc), _proj = _scan_fixture(tmp_path)
    plan = ma.to_real_plan("s", "t", cir)
    assert plan["mock"] is False
    assert plan["item_count"] == len(plan["items"]) >= 1
    allowed = {"rule_id", "severity", "title", "action", "refs", "count",
               "affected_files", "graph_node_ids", "status"}
    forbidden = {"timeline", "effort", "priority", "confidence", "phase",
                 "pqc_target", "migration_sequence", "migration_state",
                 "sequencing", "owner"}
    seen: set[str] = set()

    def collect(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                seen.add(k)
                collect(v)
        elif isinstance(obj, list):
            for v in obj:
                collect(v)

    collect(plan)
    assert seen.isdisjoint(forbidden)
    for item in plan["items"]:
        assert set(item) == allowed
        assert item["severity"] in ("critical", "high", "medium", "low",
                                    "info")
        assert item["affected_files"], "real items must name evidence files"


def test_service_migration_plan_real_branch(tmp_path):
    from ecdat.gui.service import GuiService

    proj = _crypto_project(tmp_path)
    svc = GuiService(tmp_path / "mg.db", client=RealCoreClient())
    done = _complete_job(svc, str(proj))
    plan = svc.migration_plan(done["scan_id"])
    assert plan is not None and plan["mock"] is False
    assert any("ML-KEM" in i["title"] or "SHA" in i["title"]
               for i in plan["items"])


# --- graph integration ------------------------------------------------------


def test_service_graph_for_scan_real(tmp_path):
    from ecdat.gui.graph import to_frontend_graph
    from ecdat.gui.service import GuiService

    proj = _crypto_project(tmp_path)
    svc = GuiService(tmp_path / "g.db", client=RealCoreClient())
    done = _complete_job(svc, str(proj))
    graph = svc.graph_for_scan(done["scan_id"])
    assert graph is not None
    assert graph["mock"] is False
    assert graph["dataset"] == "cir-scan"
    # to_frontend_graph already validated types/edges; spot-check content.
    types = {n["type"] for n in graph["nodes"]}
    assert types <= {"Endpoint", "Service", "Container", "Library",
                     "CryptoOperation", "CryptoAsset", "CertificateKey",
                     "CloudResource"}
    assert "File" not in types, "file nodes must be folded, not rendered"
    assert any("location_file" in n.get("metadata", {})
               for n in graph["nodes"])
    assert graph["trace_paths"] == []
    # Mock scans have no CIR graph.
    mock_svc = GuiService(tmp_path / "g2.db")
    mjob = mock_svc.submit("samples/rsa_small.py")
    mdone = None
    for _ in range(5):
        mdone = mock_svc.status(mjob["job_id"])
        if mdone and mdone["status"] == "completed":
            break
    assert mock_svc.graph_for_scan(mdone["scan_id"]) is None
    # Default mock dataset still served.
    assert mock_svc.graph()["mock"] is True


def test_graph_adapter_unknown_kind_rejected():
    from ecdat.adapters import graph_adapter as ga

    cir = {"assets": [], "operations": [],
           "graph": {"nodes": [{"id": "x", "kind": "warp-drive"}],
                     "edges": []}}
    with pytest.raises(ValueError):
        ga.adapt_cir_graph(cir, [])


def test_graph_adapter_unknown_relationship_rejected():
    from ecdat.adapters import graph_adapter as ga

    cir = {"assets": [], "operations": [],
           "graph": {"nodes": [
               {"id": "a", "kind": "asset"},
               {"id": "b", "kind": "library"}],
               "edges": [{"from": "a", "to": "b",
                          "relationship": "teleports"}]}}
    with pytest.raises(ValueError):
        ga.adapt_cir_graph(cir, [])


# --- storage ----------------------------------------------------------------


def test_cir_sidecar_round_trip(tmp_path):
    (cir, doc), _proj = _scan_fixture(tmp_path)
    conn = db.open_db(tmp_path / "s.db")
    try:
        sstore.insert_scan(conn, doc, cir)
        fstore.insert_findings_for_scan(conn, doc)
        back = sstore.get_scan_cir(conn, doc["scan_id"])
        assert back == cir
        assert sstore.get_scan_doc(conn, doc["scan_id"])["scan_id"] == \
            doc["scan_id"]
    finally:
        conn.close()


def test_mock_scans_have_null_sidecar(tmp_path):
    from ecdat.core.client import MockCoreClient

    doc = MockCoreClient().scan(tmp_path / "x.py")
    conn = db.open_db(tmp_path / "m.db")
    try:
        sstore.insert_scan(conn, doc)
        assert sstore.get_scan_cir(conn, doc["scan_id"]) is None
        assert sstore.get_scan_cir(conn, "nope") is None
    finally:
        conn.close()


def test_schema_v2_migrates_v1_db(tmp_path):
    from ecdat.store import db as dbmod

    assert dbmod.SCHEMA_VERSION == 2
    conn = dbmod.connect(tmp_path / "old.db")
    try:
        conn.executescript(
            "CREATE TABLE scans (id TEXT PRIMARY KEY, target TEXT NOT NULL,"
            " started_at TEXT NOT NULL, finished_at TEXT NOT NULL,"
            " raw_json TEXT NOT NULL, created_at TEXT NOT NULL);"
            "CREATE TABLE findings (id INTEGER PRIMARY KEY,"
            " scan_id TEXT NOT NULL, rule_id TEXT NOT NULL,"
            " severity TEXT NOT NULL, file TEXT NOT NULL, line INTEGER NOT NULL,"
            " title TEXT NOT NULL, confidence REAL);")
        conn.execute(
            "INSERT INTO scans (id, target, started_at, finished_at,"
            " raw_json, created_at) VALUES (?,?,?,?,?,?)",
            ("s1", "t", "a", "b", "{}", "c"))
        conn.commit()
        dbmod.init_schema(conn)
        row = conn.execute("SELECT cir_json FROM scans WHERE id='s1'").fetchone()
        assert row["cir_json"] is None
    finally:
        conn.close()


# --- REAL failure semantics -------------------------------------------------


def test_real_scan_missing_target_loud():
    with pytest.raises(RealScanError) as exc:
        run_real_scan("/nonexistent/target-xyz")
    assert "does not exist" in str(exc.value)


def test_real_scan_unknown_scanners_loud(tmp_path):
    proj = _crypto_project(tmp_path)
    with pytest.raises(RealScanError) as exc:
        run_real_scan(str(proj), scanners=["bogus-scanner"])
    assert "unknown scanner" in str(exc.value)


def test_real_scan_empty_target_loud():
    with pytest.raises(RealScanError):
        run_real_scan("   ")


def test_gui_job_failure_never_yields_mock(tmp_path):
    from ecdat.gui.service import GuiService

    svc = GuiService(tmp_path / "f.db", client=RealCoreClient(
        scanners=["bogus-scanner"]))
    job = svc.submit(str(tmp_path))
    snap = None
    for _ in range(5):
        snap = svc.status(job["job_id"])
        if snap is not None and snap["status"] in ("completed", "failed"):
            break
    assert snap is not None
    assert snap["status"] == "failed"
    assert "scan_id" not in snap
    assert snap["error"]


def test_no_mock_fallback_in_pipeline_source():
    import ecdat.adapters.pipeline as pipe_mod

    src = open(pipe_mod.__file__).read()
    assert "MockCoreClient" not in src
    assert "get_client(\"mock\")" not in src
    assert "RealScanError" in src


# --- scanner policy ---------------------------------------------------------


def test_default_allowlist_is_network_free():
    assert list(policy.DEFAULT_SCANNERS) == ["source", "dependency",
                                             "binary", "config",
                                             "certificate"]
    assert policy.resolve_scanners() == list(policy.DEFAULT_SCANNERS)


def test_explicit_and_opt_in_selection():
    assert policy.resolve_scanners(["source"]) == ["source"]
    assert "cloud" in policy.resolve_scanners(allow_cloud=True)
    assert "runtime" in policy.resolve_scanners(allow_runtime=True)
    assert "container" in policy.resolve_scanners(allow_container=True)
    assert "cloud" not in policy.resolve_scanners()
    with pytest.raises(ValueError):
        policy.resolve_scanners(["nope"])
    with pytest.raises(ValueError):
        policy.resolve_scanners([])


def test_zero_network_default_scan(tmp_path):
    proj = _crypto_project(tmp_path)
    real_connect = socket.socket.connect
    real_create = socket.create_connection
    attempts: list = []

    def _deny(*a, **k):
        attempts.append((a, k))
        raise RuntimeError("network blocked for test")

    socket.socket.connect = _deny
    socket.create_connection = _deny
    try:
        _cir, doc = run_real_scan(str(proj))
    finally:
        socket.socket.connect = real_connect
        socket.create_connection = real_create
    assert not attempts
    assert doc["findings"]


def test_python310_tomllib_fallback(monkeypatch):
    import importlib

    fake = types.ModuleType("tomli")
    fake.loads = lambda s: {}
    fake.load = lambda f: {}
    monkeypatch.setitem(sys.modules, "tomllib", None)
    monkeypatch.setitem(sys.modules, "tomli", fake)
    for name in [m for m in list(sys.modules)
                 if m.startswith("ecdat.scanners.dependency")]:
        del sys.modules[name]
    try:
        mod = importlib.import_module("ecdat.scanners.dependency.scanner")
        assert mod.tomllib is fake
    finally:
        for name in [m for m in list(sys.modules)
                     if m.startswith("ecdat.scanners.dependency")]:
            del sys.modules[name]
        monkeypatch.undo()


# --- end-to-end CLI + GUI ---------------------------------------------------


def test_cli_scan_real_end_to_end(tmp_path, capsys):
    from ecdat.cli import main

    proj = _crypto_project(tmp_path)
    db_path = str(tmp_path / "e2e.db")
    cir_out = str(tmp_path / "cir.json")
    rc = main(["scan", str(proj), "--db", db_path, "--real",
               "--cir-out", cir_out])
    assert rc == 0
    out, err = capsys.readouterr()
    assert re.match(r"^scan:[0-9a-f]{16}$", out.strip())
    assert "Traceback" not in err
    saved = json.loads(Path(cir_out).read_text())
    assert saved["scan_id"] == out.strip()
    conn = db.open_db(db_path)
    try:
        assert sstore.get_scan_cir(conn, out.strip()) == saved
    finally:
        conn.close()
    # Deterministic rerun reports the stored scan instead of duplicating.
    rc = main(["scan", str(proj), "--db", db_path, "--real"])
    assert rc == 1
    _out, err = capsys.readouterr()
    assert "already exists" in err


def test_gui_api_over_real_scan(tmp_path):
    from ecdat.gui.service import GuiService

    proj = _crypto_project(tmp_path)
    svc = GuiService(tmp_path / "api.db", client=RealCoreClient())
    done = _complete_job(svc, str(proj))
    sid = done["scan_id"]
    inv = svc.inventory(sid)
    assert inv and inv["finding_count"] >= 2
    detail = svc.finding_detail(sid, 0)
    assert detail and detail["finding"]["rule_id"]
    assets = svc.assets(sid)
    assert assets and assets["asset_count"] >= 1
    assert svc.migration_plan(sid)["mock"] is False
    assert svc.report_summary(sid)["mock"] is False
    assert svc.graph_for_scan(sid)["mock"] is False


def test_get_client_modes():
    assert isinstance(get_client("mock").scan, object)
    real = get_client("real")
    assert isinstance(real, RealCoreClient)
    with pytest.raises(ValueError):
        get_client("bogus")


def test_real_finding_detail_uses_actual_usage_state(tmp_path):
    from ecdat.gui.service import GuiService

    proj = _crypto_project(tmp_path)
    svc = GuiService(tmp_path / "fd.db", client=RealCoreClient())
    done = _complete_job(svc, str(proj))
    detail = svc.finding_detail(done["scan_id"], 0)
    assert detail is not None
    expected_state = str(
        detail["finding"].get("metadata", {}).get("usage_state"))
    assert expected_state
    assert detail["provenance"]["status"] == f"{expected_state} (real)"
    assert detail["mock"] is False


def test_real_finding_detail_wording_not_mock(tmp_path):
    from ecdat.gui.service import GuiService

    proj = _crypto_project(tmp_path)
    svc = GuiService(tmp_path / "fdw.db", client=RealCoreClient())
    done = _complete_job(svc, str(proj))
    detail = svc.finding_detail(done["scan_id"], 0)
    assert detail is not None
    assert "mock fixture" not in detail["provenance"]["note"]
    assert "pending Person 1" not in detail["redaction"]["capability"]
    assert "pending Person 1" not in detail["redaction"]["reason"]
    assert detail["redaction"]["applied"] is False


def test_real_inventory_and_assets_not_mock(tmp_path):
    from ecdat.gui.service import GuiService

    proj = _crypto_project(tmp_path)
    svc = GuiService(tmp_path / "im.db", client=RealCoreClient())
    done = _complete_job(svc, str(proj))
    inv = svc.inventory(done["scan_id"])
    assert inv is not None and inv["mock"] is False
    assets = svc.assets(done["scan_id"])
    assert assets is not None and assets["mock"] is False


def test_mock_inventory_assets_detail_still_mock(tmp_path):
    from ecdat.gui.service import GuiService

    svc = GuiService(tmp_path / "imm.db")
    done = _complete_job(svc, "samples/rsa_small.py")
    inv = svc.inventory(done["scan_id"])
    assert inv is not None and inv["mock"] is True
    assets = svc.assets(done["scan_id"])
    assert assets is not None and assets["mock"] is True
    detail = svc.finding_detail(done["scan_id"], 0)
    assert detail is not None and detail["mock"] is True
    assert detail["provenance"]["status"] == "ProvidedOnly (mock)"
