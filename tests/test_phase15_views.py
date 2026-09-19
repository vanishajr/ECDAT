"""Phase 15 tests: report-quality projection views (additive).

Views project existing structures; build_report() behaviour is pinned by
a backward-compatibility test.
"""

from __future__ import annotations

from ecdat.reports.aggregate import (
    build_report,
    coverage_view,
    evidence_view,
    findings_view,
    inventory_view,
    migration_view,
    risk_details_view,
)


def _cir() -> dict:
    return {
        "assets": [
            {"asset_id": "a1", "canonical": "AES-256-GCM",
             "usage_state": "Possible"},
        ],
        "operations": [
            {"operation_id": "op1", "operation_type": "encrypt",
             "asset_id": "a1", "confidence": 0.9,
             "location": {"file": "app/crypto.py", "line": 10},
             "risk_inputs": {"usage_state": "Confirmed"},
             "evidence": [{"kind": "call", "confidence": 0.9,
                           "snippet": "encrypt(data)",
                           "scanner": "source", "detail": "call"}]},
            {"operation_id": "op2", "operation_type": "hash",
             "asset_id": "a1", "confidence": 0.4,
             "location": {"file": "app/other.py", "line": 3},
             "risk_inputs": {"usage_state": "Possible"},
             "evidence": []},
        ],
    }


def _risks() -> list[dict]:
    return [
        {"operation_id": "op1", "class": "High", "score": 7.5,
         "confidence": 0.9, "title": "AES-256-GCM use",
         "description": "confirmed use"},
        {"operation_id": "op2", "class": "Low", "score": 2.0,
         "confidence": 0.4, "title": "AES-256-GCM mention",
         "description": "capability"},
    ]


def test_inventory_view_projects_cir():
    rows = inventory_view(_cir())
    assert len(rows) == 1
    row = rows[0]
    assert row["algorithm"] == "AES-256-GCM"
    assert row["uses"] == 2
    assert row["confirmed_uses"] == 1
    assert row["capability_uses"] == 1
    assert inventory_view(None) == []
    assert inventory_view({}) == []


def test_findings_view_only_actionable():
    rows = findings_view(_cir(), _risks())
    assert [r["operation_id"] for r in rows] == ["op1"]  # op2 not confirmed
    assert rows[0]["risk_class"] == "High"
    assert findings_view(_cir(), []) == []
    assert findings_view(None, _risks()) == []


def test_migration_view_dedupes_and_joins():
    recs = [
        {"rule_key": "k", "rule_id": "r", "severity": "high",
         "title": "Migrate X", "action": "Do X",
         "count": 1, "affected_files": ["app/crypto.py"],
         "graph_node_ids": [], "refs": []},
        {"rule_key": "k", "rule_id": "r", "severity": "high",
         "title": "Migrate X", "action": "Do X",
         "count": 1, "affected_files": ["app/crypto.py"],
         "graph_node_ids": [], "refs": []},
    ]
    rows = migration_view(_cir(), recs)
    assert len(rows) == 1  # duplicates merged
    assert rows[0]["count"] == 2
    assert migration_view(None, []) == []


def test_evidence_and_risk_views():
    op = _cir()["operations"][0]
    signals = evidence_view(op)
    assert len(signals) == 1
    assert signals[0]["snippet"] == "encrypt(data)"
    assert evidence_view(None) == []
    assert evidence_view({"operation_id": "x"}) == []
    details = risk_details_view(_risks()[0])
    assert details["class"] == "High"
    assert details["severity"] == "high"
    assert details["operation_id"] == "op1"
    fallback = risk_details_view(None)
    assert fallback["class"] == "Informational"


def test_coverage_view_accepts_shapes():
    shaped = coverage_view({"plan": {"profile": "standard", "scanners": []},
                            "diagnostics": {"cache_hit": True}})
    assert shaped["profile"] == "standard"
    assert shaped["cache_hit"] is True
    assert coverage_view(None)["profile"] == "standard"


def test_build_report_backward_compat():
    doc = {"scan_id": "s1", "target": "proj", "findings": [],
           "stats": {"files_scanned": 0}, "tool_versions": {}}
    report = build_report(doc)
    for key in ("scan_id", "finding_count", "inventory", "finding_groups",
                "migration_actions", "coverage_summary", "top_operations"):
        assert key in report
    assert report["finding_count"] == 0
    assert report["status"] == "COMPLETE"
