"""Consumer-contract tests: MigrationProvider output accepted by P3.

Defines WHAT the GUI accepts from any MigrationProvider (strict
mock recombination today, real P1 intelligence later): the
get_plan() envelope, the item fields P3 actually renders, and the
explicit placeholder status. A fake P1-style provider injected
into GuiService must flow through; fabricated PQC fields
(timeline/effort/phases/owners) are rejected from P3's own mock
output. Mock semantics stay explicit throughout.
"""

from ecdat.Backup_GUI.migration import (
    STATUS_PLACEHOLDER,
    MigrationProvider,
    MockMigrationProvider,
    to_frontend_plan,
)
from ecdat.Backup_GUI.service import GuiService

FORBIDDEN = {"timeline", "effort", "priority", "confidence", "phase",
             "pqc_target", "migration_sequence", "migration_state",
             "sequencing", "owner"}

ITEM_FIELDS = {"rule_id", "severity", "title", "action", "refs", "count",
               "affected_files", "graph_node_ids", "status"}


def _findings():
    return [
        {"rule_id": "RSA-1024", "title": "Weak RSA", "severity": "high",
         "file": "a.py", "line": 1},
        {"rule_id": "TLS-1.0", "title": "Old TLS", "severity": "low",
         "file": "b.py", "line": 2},
    ]


def _all_keys(obj, acc):
    if isinstance(obj, dict):
        for k, v in obj.items():
            acc.add(k)
            _all_keys(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            _all_keys(v, acc)
    return acc


class _FakeP1Migration:
    """Stands in for a future P1 migration-intelligence provider."""

    name = "fake-p1-migration"

    def get_plan(self, scan_id: str, target: str,
                 findings: list[dict]) -> dict:
        return {"plan_version": "1", "scan_id": scan_id, "target": target,
                "item_count": len(findings), "items": [],
                "mock": False, "note": "fake P1 envelope"}


def test_mock_conforms_and_marks_placeholder():
    provider = MockMigrationProvider()
    assert isinstance(provider, MigrationProvider)
    assert provider.name == "mock-migration"
    plan = to_frontend_plan("s", "t", _findings())
    assert plan["mock"] is True
    assert plan["item_count"] == 2
    for item in plan["items"]:
        assert set(item) == ITEM_FIELDS
        assert item["status"] == STATUS_PLACEHOLDER
        assert "migration state" in item["status"].lower() or \
            "no migration state" in item["status"]
    assert _all_keys(plan, set()).isdisjoint(FORBIDDEN)


def test_fake_p1_provider_flows_through_service(tmp_path):
    svc = GuiService(tmp_path / "m.db",
                     migration_provider=_FakeP1Migration())
    job = svc.submit("x.py")
    snap = None
    for _ in range(5):
        snap = svc.status(job["job_id"])
        if snap is not None and snap["status"] == "completed":
            break
    assert snap is not None and snap["scan_id"] is not None
    plan = svc.migration_plan(snap["scan_id"])
    assert plan is not None
    assert plan["mock"] is False  # P3 does not force mock flags on P1 data
    assert plan["note"] == "fake P1 envelope"


def test_unknown_scan_stays_none(tmp_path):
    svc = GuiService(tmp_path / "m.db")
    assert svc.migration_plan("bogus-id") is None
