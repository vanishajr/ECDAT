"""Migration Planner data layer (Person 3 platform layer).

Separation rule (same as `graph.py`): the UI consumes only
`to_frontend_plan()` output, so the mock provider below can later be
replaced by real Person 1 migration intelligence without rewriting
the UI or service:

    UI (server.py) -> GuiService.migration_plan() -> MigrationProvider
        MockMigrationProvider today (strict recombination, no new data)
        Person 1 provider later (same envelope, real intelligence)

Strict recombination ONLY. This module combines:
- `recommend_for_findings()` items (rule_id/severity/title/action/refs/count),
- canonical findings (affected files),
- existing mock-graph rule cross-links (graph node ids).

It invents NOTHING: no PQC targets, timelines, effort, phases,
priorities, confidence, sequencing, or migration state. Item ordering
is severity triage (heaviest first, via the existing Task 6 WEIGHTS),
explicitly labeled as triage — NOT a migration sequence.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ecdat.commands.recommend_cmd import recommend_for_findings
from ecdat.commands.risk_cmd import WEIGHTS
from ecdat.Backup_GUI.graph import build_mock_graph

STATUS_PLACEHOLDER = "not started (mock — v1 tracks no migration state)"

TRIAGE_LABEL = (
    "Triage by current finding severity only (heaviest first, using the "
    "existing Task 6 severity weights). This is NOT a migration sequence: "
    "canonical v1 contains no ordering, dependency, or phasing data."
)

NOT_INCLUDED = (
    "PQC target selection; migration timelines; effort estimates; phased "
    "sequencing; migration confidence; real migration state. All await "
    "Person 1 migration intelligence."
)

_MOCK_NOTE = (
    "Mock/placeholder migration plan: strict recombination of existing "
    "Task 6 recommendations, affected files, and mock-graph rule links. "
    "No new migration data was created."
)


def _rule_to_graph_nodes() -> dict[str, list[str]]:
    """rule_id -> sorted mock-graph node ids, derived from graph dataset."""
    mapping: dict[str, list[str]] = {}
    for node in build_mock_graph()["nodes"]:
        rule = node.get("rule_id")
        if rule:
            mapping.setdefault(str(rule), []).append(str(node["id"]))
    return {rule: sorted(ids) for rule, ids in mapping.items()}


def build_mock_items(findings: list[dict]) -> list[dict]:
    """Pure transform: recommendations + affected files + graph links."""
    node_map = _rule_to_graph_nodes()
    files_for_rule: dict[str, set[str]] = {}
    for f in findings:
        files_for_rule.setdefault(str(f["rule_id"]), set()).add(str(f["file"]))
    items = []
    for rec in recommend_for_findings(findings):
        rule = str(rec["rule_id"])
        items.append({
            "rule_id": rule,
            "severity": str(rec["severity"]),
            "title": str(rec["title"]),
            "action": str(rec["action"]),
            "refs": list(rec["refs"]),
            "count": int(rec["count"]),
            "affected_files": sorted(files_for_rule.get(rule, ())),
            "graph_node_ids": node_map.get(rule, []),
            "status": STATUS_PLACEHOLDER,
        })
    items.sort(key=lambda i: (-WEIGHTS.get(str(i["severity"]), 0), str(i["rule_id"])))
    return items


def to_frontend_plan(scan_id: str, target: str, findings: list[dict]) -> dict:
    """Wrap items in the stable frontend envelope."""
    items = build_mock_items(findings)
    return {
        "plan_version": "1",
        "scan_id": scan_id,
        "target": target,
        "item_count": len(items),
        "items": items,
        "triage_label": TRIAGE_LABEL,
        "not_included": NOT_INCLUDED,
        "mock": True,
        "dataset": "mock-migration",
        "note": _MOCK_NOTE,
        "source": "recommend_for_findings + canonical findings + mock-graph links",
    }


@runtime_checkable
class MigrationProvider(Protocol):
    """Future Person 1 migration-intelligence providers implement this."""

    name: str

    def get_plan(self, scan_id: str, target: str, findings: list[dict]) -> dict:
        """Return a frontend-ready migration plan envelope."""
        ...


class MockMigrationProvider:
    """Strict-recombination mock provider. Placeholder only."""

    name = "mock-migration"

    def get_plan(self, scan_id: str, target: str, findings: list[dict]) -> dict:
        return to_frontend_plan(scan_id, target, findings)
