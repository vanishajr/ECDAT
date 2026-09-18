"""Task 32 workflow-cohesion regression tests (frontend-only, static page).

Asserts the Scan -> Discovery -> Risk -> Graph -> Migration -> Report
connections exist in index_page() without changing detection, contracts,
exports, or report generation.
"""

from ecdat.Backup_GUI.server import index_page


def test_workflow_rail_present():
    out = index_page()
    assert 'aria-label="Analysis workflow"' in out
    for step in ('data-wf="scan"', 'data-wf="discovery"', 'data-wf="risk"',
                 'data-wf="graph"', 'data-wf="migration"', 'data-wf="report"'):
        assert step in out
    for anchor in ("#sec-scan", "#sec-inventory", "#sec-risk",
                   "#sec-graph", "#sec-migration", "#sec-reports"):
        assert anchor in out


def test_scan_done_next_steps_present():
    out = index_page()
    for token in ("scanDone", "scanDoneInv", "scanDoneRisk",
                  "View crypto inventory", "Open risk dashboard"):
        assert token in out


def test_risk_graph_migration_bridges_present():
    out = index_page()
    for token in ("riskGraphBridge", "riskGraphBtn", "riskMigBtn",
                  "Open dependency graph", "Open migration triage",
                  "scan-independent mock topology"):
        assert token in out
    # Honest rule-level graph marker hook (no fake finding-to-node mapping).
    assert "annotateRiskRules" in out
    assert "graphRuleSet" in out


def test_finding_evidence_hierarchy_present():
    out = index_page()
    for token in ("Why it matters", "Evidence", "Where", "What",
                  "Open risk dashboard (", "Show rule in inventory"):
        assert token in out


def test_migration_reports_workflow_close_the_loop():
    out = index_page()
    for token in ("migrationRisk", "migRepBtn", "Export via Reports",
                  "repMigBtn", "repGraphBtn", "Review migration triage",
                  "Final output of the workflow"):
        assert token in out
    assert "innerHTML" not in out
