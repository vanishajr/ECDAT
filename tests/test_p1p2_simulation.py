"""Task 33 P1/P2 real-data simulation (TEST DATA ONLY).

Deterministic fixtures representing realistic future P1/P2 payloads.
These are NOT real crypto discovery and must never be presented as such.
They exist only to validate Person 3 seams against the established
contracts (canonical v1, GraphProvider, MigrationProvider, risk helpers).

Labeling: `sim_*` filenames + this docstring. Fixture JSON bodies carry
no extra keys because canonical v1 sets `additionalProperties: false`.
"""

import copy
import json
from pathlib import Path

from ecdat.commands.recommend_cmd import recommend_for_findings
from ecdat.commands.risk_cmd import WEIGHTS, risk_from_findings
from ecdat.core.validate import validate
from ecdat.Backup_GUI.graph import NODE_TYPES, RELATIONS, to_frontend_graph
from ecdat.Backup_GUI.migration import (
    STATUS_PLACEHOLDER,
    MockMigrationProvider,
    to_frontend_plan,
)
from ecdat.Backup_GUI.service import GuiService
from ecdat.store import db
from ecdat.store import findings as fstore
from ecdat.store import scans as sstore

FIX = Path(__file__).parent / "fixtures" / "p1p2"

# Fields the migration contract forbids P3's own output to invent
# (mirrors tests/contract/test_migration_contract.py).
FORBIDDEN_MIGRATION_KEYS = {"timeline", "effort", "priority", "confidence",
                            "phase", "pqc_target", "migration_sequence",
                            "migration_state", "sequencing", "owner"}
MIGRATION_ITEM_FIELDS = {"rule_id", "severity", "title", "action", "refs",
                         "count", "affected_files", "graph_node_ids",
                         "status"}


def _load(name: str) -> dict:
    with (FIX / name).open("r", encoding="utf-8") as fh:
        doc = json.load(fh)
    assert isinstance(doc, dict)
    return doc


def _all_keys(obj, acc):
    if isinstance(obj, dict):
        for k, v in obj.items():
            acc.add(k)
            _all_keys(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            _all_keys(v, acc)
    return acc


class _FakeP1Client:
    """Stands in for a future P1 CoreClient returning the sim payload."""

    name = "fake-p1-sim"

    def __init__(self, doc: dict):
        self._doc = doc

    def scan(self, target):  # noqa: ARG002
        return copy.deepcopy(self._doc)


class _FakeP1Graph:
    """Stands in for a future P1 CIR provider serving the sim graph."""

    name = "fake-p1-cir-sim"

    def __init__(self, raw: dict):
        self._raw = raw

    def get_graph(self) -> dict:
        return to_frontend_graph(copy.deepcopy(self._raw))


def _consume(db_path, doc: dict) -> dict:
    """Real P3 consumer chain: validate -> store -> read back."""
    validate(doc)
    conn = db.open_db(str(db_path))
    try:
        sstore.insert_scan(conn, doc)
        fstore.insert_findings_for_scan(conn, doc)
        stored = sstore.get_scan_doc(conn, doc["scan_id"])
    finally:
        conn.close()
    assert stored is not None
    return stored


def _svc_with_sim(tmp_path, name="sim_core.json", graph_raw=None):
    doc = _load(name)
    svc = GuiService(str(tmp_path / "sim.db"))
    stored = _consume(str(tmp_path / "sim.db"), _FakeP1Client(doc).scan("x"))
    if graph_raw is not None:
        svc.graph_provider = _FakeP1Graph(graph_raw)
    return svc, stored, doc


# --- §2 fixtures -------------------------------------------------------------


def test_sim_core_fixture_validates_against_canonical_v1():
    doc = _load("sim_core.json")
    assert validate(doc) is doc
    assert len(doc["findings"]) == 9
    assert {f["severity"] for f in doc["findings"]} == {
        "critical", "high", "medium", "low", "info"}
    files = {f["file"] for f in doc["findings"]}
    assert len(files) >= 7  # multiple files/targets
    assert sum(1 for f in doc["findings"]
               if f["rule_id"] == "RSA-1024") == 2  # same rule, two files
    assert any(len(f["title"]) > 80 for f in doc["findings"])  # long titles
    assert any(len(f["file"]) > 60 for f in doc["findings"])  # long paths
    assert any(len(f.get("metadata", {})) >= 3
               for f in doc["findings"])  # rich metadata


def test_sim_partial_and_single_fixtures_validate():
    partial = _load("sim_core_partial.json")
    assert validate(partial) is partial
    bare = partial["findings"][0]
    assert set(bare) == {"rule_id", "title", "severity", "file", "line"}
    single = _load("sim_core_single.json")
    assert validate(single) is single
    assert len(single["findings"]) == 1


def test_sim_graph_covers_types_relations_and_edge_cases():
    raw = _load("sim_graph.json")
    graph = to_frontend_graph(raw)
    assert {n["type"] for n in graph["nodes"]} == set(NODE_TYPES)
    assert {e["type"] for e in graph["edges"]} == set(RELATIONS)
    assert {n["risk"] for n in graph["nodes"]} >= {
        "critical", "high", "medium", "low", "info", "none"}
    ids = {n["id"] for n in graph["nodes"]}
    assert "isolated-audit-sidecar" in ids
    assert to_frontend_graph(raw) == graph  # deterministic
    empty = to_frontend_graph(_load("sim_graph_no_edges.json"))
    assert empty["node_count"] == 3 and empty["edge_count"] == 0


# --- §4 full UI data flow ----------------------------------------------------


def test_full_ui_data_flow_over_sim_payload(tmp_path):
    svc, stored, doc = _svc_with_sim(tmp_path)
    scan_id = doc["scan_id"]
    inv = svc.inventory(scan_id)
    assert inv is not None and inv["finding_count"] == 9
    risk = svc.risk_summary(scan_id)
    assert risk is not None
    assert (risk["score"], risk["level"]) == (33, "critical")
    for i in range(9):
        det = svc.finding_detail(scan_id, i)
        assert det is not None and det["index"] == i
        assert det["finding"]["rule_id"] == doc["findings"][i]["rule_id"]
    assets = svc.assets(scan_id)
    assert assets is not None and assets["asset_count"] == 9
    plan = svc.migration_plan(scan_id)
    assert plan is not None and plan["item_count"] == 8
    summary = svc.report_summary(scan_id)
    assert summary is not None and summary["finding_count"] == 9
    assert summary["risk"] == {"score": 33, "level": "critical"}
    for fmt in ("html", "pdf", "csv", "json", "sarif"):
        artifact = svc.report_artifact(scan_id, fmt)
        assert artifact is not None and len(artifact[2]) > 0


# --- §5 finding robustness ---------------------------------------------------


def test_finding_filtering_counts_and_long_fields(tmp_path):
    svc, stored, doc = _svc_with_sim(tmp_path)
    scan_id = doc["scan_id"]
    assert svc.inventory(scan_id, severity="high")["finding_count"] == 3
    assert svc.inventory(scan_id, severity="critical")["finding_count"] == 1
    assert svc.inventory(scan_id, rule="RSA-1024")["finding_count"] == 2
    assert svc.inventory(scan_id, rule="NOPE")["finding_count"] == 0
    tls = svc.finding_detail(scan_id, 4)
    assert tls is not None
    assert tls["finding"]["file"] == (
        "services/edge/legacy_gateway/conf/very/long/nested/directory/"
        "legacy_tls_listener.conf")
    assert "Legacy TLS 1.0" in tls["finding"]["title"]
    assert tls["metadata_keys"] == ["protocol"]
    assert svc.inventory(scan_id)["finding_count"] == \
        svc.risk_summary(scan_id)["finding_count"] == \
        svc.report_summary(scan_id)["finding_count"] == 9


# --- §6 graph contract robustness --------------------------------------------


def test_sim_graph_flows_through_service_unchanged(tmp_path):
    raw = _load("sim_graph.json")
    svc = GuiService(str(tmp_path / "g.db"), graph_provider=_FakeP1Graph(raw))
    graph = svc.graph()
    assert graph == to_frontend_graph(raw)  # passed through, not reshaped
    assert "mock" not in graph  # P3 does not force mock flags on P1 data
    by_id = {n["id"]: n for n in graph["nodes"]}
    assert by_id["billing-cert-longlabel"]["label"].startswith(
        "legacy-billing-invoice-signing-key")
    for trace in graph["trace_paths"]:
        for nid in trace["node_ids"]:
            assert nid in by_id


# --- §7 risk / recommendation robustness -------------------------------------


def test_sim_risk_values_reach_ui_unaltered(tmp_path):
    svc, stored, doc = _svc_with_sim(tmp_path)
    expected = risk_from_findings(doc["findings"])
    assert (expected["score"], expected["level"]) == (33, "critical")
    assert expected == risk_from_findings(doc["findings"])  # deterministic
    summary = svc.risk_summary(doc["scan_id"])
    assert summary is not None
    assert summary["score"] == expected["score"]
    assert summary["level"] == expected["level"]
    assert summary["breakdown"] == expected["breakdown"]
    assert set(summary["severity_counts"]) == {
        "critical", "high", "medium", "low", "info"}  # zero-filled
    recs = recommend_for_findings(doc["findings"])
    assert [r["rule_id"] for r in recs] == sorted(
        {f["rule_id"] for f in doc["findings"]})
    known = next(r for r in recs if r["rule_id"] == "RSA-1024")
    assert known["refs"]  # mapped rule keeps its refs
    fallback = next(r for r in recs if r["rule_id"] == "DES-USAGE")
    assert fallback["refs"] == []  # unknown rule: fallback, no invented refs
    assert fallback["count"] == 1


# --- §8 migration robustness (contract fields only) ---------------------------


def test_sim_migration_uses_contract_fields_only(tmp_path):
    svc, stored, doc = _svc_with_sim(tmp_path)
    plan = to_frontend_plan(
        doc["scan_id"], doc["target"],
        [{k: f[k] for k in ("rule_id", "title", "severity", "file", "line")
          if k in f} for f in doc["findings"]])
    assert plan["item_count"] == 8
    assert plan["mock"] is True
    assert _all_keys(plan, set()).isdisjoint(FORBIDDEN_MIGRATION_KEYS)
    for item in plan["items"]:
        assert set(item) == MIGRATION_ITEM_FIELDS
        assert item["status"] == STATUS_PLACEHOLDER
    # Triage order is heaviest-first (existing Task 6 weights), not a sequence.
    severities = [i["severity"] for i in plan["items"]]
    assert severities[0] == "critical"
    assert severities.index("info") > severities.index("low")
    rsa = next(i for i in plan["items"] if i["rule_id"] == "RSA-1024")
    assert rsa["count"] == 2
    assert sorted(rsa["affected_files"]) == [
        "services/billing/legacy/invoice_signer.py",
        "services/payments/api/auth_tokens.py"]
    # Blockers/owner/effort/priority are NOT in the contract: must be absent.
    assert "owner" not in rsa and "effort" not in rsa
    mock_plan = MockMigrationProvider().get_plan(
        doc["scan_id"], doc["target"], [])
    assert mock_plan["items"] == [] and mock_plan["item_count"] == 0


# --- §9 cross-view consistency -------------------------------------------------


def test_cross_view_consistency_for_sim_scan(tmp_path):
    svc, stored, doc = _svc_with_sim(
        tmp_path, graph_raw=_load("sim_graph.json"))
    scan_id = doc["scan_id"]
    inv = svc.inventory(scan_id)
    risk = svc.risk_summary(scan_id)
    summary = svc.report_summary(scan_id)
    assert inv is not None and risk is not None and summary is not None
    assert inv["finding_count"] == risk["finding_count"] == \
        summary["finding_count"] == 9
    assert inv["severity_counts"].get("high", 0) == \
        risk["severity_counts"]["high"] == 3
    first = svc.finding_detail(scan_id, 0)
    assert first is not None
    assert first["finding"]["rule_id"] == inv["findings"][0]["rule_id"]
    assert svc.inventory(scan_id, rule="RSA-1024")["finding_count"] == 2
    assert next(r["count"] for r in risk["by_rule"]
                if r["rule_id"] == "RSA-1024") == 2
    plan = svc.migration_plan(scan_id)
    assert plan is not None
    assert plan["scan_id"] == scan_id and plan["target"] == doc["target"]
    graph = svc.graph()
    # Legitimate semantic difference: sim graph is provider topology,
    # not scan data — rule overlap is advisory, never an equality claim.
    graph_rules = {n.get("rule_id") for n in graph["nodes"]
                   if n.get("rule_id")}
    scan_rules = {f["rule_id"] for f in doc["findings"]}
    assert graph_rules & scan_rules >= {"RSA-1024", "MD5-USAGE", "AES-ECB"}


# --- §10 empty + partial payloads ----------------------------------------------


def test_partial_and_empty_payloads_degrade_gracefully(tmp_path):
    svc, stored, doc = _svc_with_sim(tmp_path, name="sim_core_partial.json")
    scan_id = doc["scan_id"]
    bare = svc.finding_detail(scan_id, 0)
    assert bare is not None
    assert bare["evidence_available"] == {
        "snippet": False, "confidence": False, "metadata": False}
    assert bare["missing_evidence"] == ["confidence", "metadata", "snippet"]
    assert bare["metadata_keys"] == []
    assert svc.inventory(scan_id)["finding_count"] == 3
    payload = {"inventory": svc.inventory(scan_id),
               "risk": svc.risk_summary(scan_id),
               "detail": bare,
               "migration": svc.migration_plan(scan_id)}
    blob = json.dumps(payload, allow_nan=False)
    assert "undefined" not in blob
    assert "NaN" not in blob
    assert '"null"' not in blob
    empty_doc = json.load(open(
        Path(__file__).parent / "fixtures" / "canonical" / "empty.json"))
    _consume(str(tmp_path / "empty.db"), empty_doc)
    esvc = GuiService(str(tmp_path / "empty.db"))
    eid = empty_doc["scan_id"]
    assert esvc.inventory(eid)["finding_count"] == 0
    zero_risk = esvc.risk_summary(eid)
    assert zero_risk is not None
    assert (zero_risk["score"], zero_risk["level"]) == (0, "none")
    zero_plan = esvc.migration_plan(eid)
    assert zero_plan is not None and zero_plan["items"] == []
    assert esvc.report_summary(eid)["finding_count"] == 0
    _, single, _ = _svc_with_sim(tmp_path, name="sim_core_single.json")
    assert single["scan_id"] == "sim-p1p2-single-001"
