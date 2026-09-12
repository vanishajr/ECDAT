"""Consumer-contract tests: risk/recommendation outputs accepted by P3.

Defines WHAT service/report/GUI layers accept from the Task 6
helpers (mock scoring today, real P1 engine later): field shapes,
the closed severity vocabulary, deterministic structure, and the
honest unknown-severity rule (weight 0, preserved in breakdown —
never upgraded, never dropped). Proves compatibility, never
correctness.
"""

from ecdat.commands.recommend_cmd import recommend_for_findings
from ecdat.commands.risk_cmd import WEIGHTS, level_for, risk_from_findings
from ecdat.gui.service import GuiService
from ecdat.reports.aggregate import build_report

SEVERITIES = ("critical", "high", "medium", "low", "info")


def _findings():
    return [
        {"rule_id": "RSA-1024", "title": "Weak RSA", "severity": "high",
         "file": "a.py", "line": 1},
        {"rule_id": "RSA-1024", "title": "Weak RSA", "severity": "high",
         "file": "b.py", "line": 2},
        {"rule_id": "TLS-1.0", "title": "Old TLS", "severity": "low",
         "file": "a.py", "line": 3},
    ]


def test_risk_shape_levels_and_determinism():
    first = risk_from_findings(_findings())
    assert first == risk_from_findings(_findings())
    assert set(first) == {"score", "level", "breakdown", "finding_count"}
    assert first["score"] == 2 * WEIGHTS["high"] + WEIGHTS["low"]
    assert first["level"] == level_for(first["score"])
    assert first["breakdown"] == {"high": 2, "low": 1}
    assert first["finding_count"] == 3
    assert set(WEIGHTS) == set(SEVERITIES)


def test_unknown_severity_never_fabricated():
    res = risk_from_findings([{"severity": "quantum"}])
    assert res["score"] == 0  # unknown weight, not a guess
    assert res["breakdown"] == {"quantum": 1}  # preserved, not dropped
    assert res["level"] == "none"


def test_recommendation_shape_and_determinism():
    first = recommend_for_findings(_findings())
    assert first == recommend_for_findings(_findings())
    assert [r["rule_id"] for r in first] == ["RSA-1024", "TLS-1.0"]
    for rec in first:
        assert set(rec) == {"rule_id", "severity", "title", "action",
                            "refs", "count"}
        assert rec["severity"] in SEVERITIES
        assert isinstance(rec["refs"], list)
    assert first[0]["count"] == 2  # deduplicated, counted honestly


def test_service_and_report_consume_risk_output(tmp_path):
    svc = GuiService(tmp_path / "r.db")
    job = svc.submit("x.py")
    snap = None
    for _ in range(5):
        snap = svc.status(job["job_id"])
        if snap is not None and snap["status"] == "completed":
            break
    assert snap is not None and snap["scan_id"] is not None
    summary = svc.risk_summary(snap["scan_id"])
    assert summary is not None
    assert set(summary) >= {"score", "level", "breakdown",
                            "severity_counts", "by_rule", "model", "mock"}
    assert summary["mock"] is True
    assert set(summary["severity_counts"]) == set(SEVERITIES)  # zero-filled
