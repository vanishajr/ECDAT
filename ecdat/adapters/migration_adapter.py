"""P1 recommendations -> P3 migration envelope (Person 3 platform layer).

Uses P1's INTERNAL recommendation records (rule_key, reason, refs,
target_algorithms, priority, replacement_score) joined with the wire
recommendations (pqc_target) by operation ID. Items are per-operation
(no grouping inventions, no sequencing claims).

Item keys are EXACTLY the P3 migration contract fields
(rule_id, severity, title, action, refs, count, affected_files,
graph_node_ids, status) — the forbidden list (timeline, effort,
priority, confidence, phase, pqc_target, migration_sequence,
migration_state, sequencing, owner) never appears as keys. PQC targets
surface inside title/action text only, when genuinely supplied by P1.
"""

from __future__ import annotations

REAL_STATUS = "identified — migration not started (v1 tracks no migration state)"

REAL_TRIAGE_LABEL = (
    "Ordered by P1 recommendation priority (Critical first), then "
    "replacement score. This is triage order, NOT a migration sequence: "
    "canonical v1 contains no ordering, dependency, or phasing data."
)

REAL_NOT_INCLUDED = (
    "Migration timelines; effort estimates; phased sequencing; migration "
    "confidence; real migration state; owners. All await future "
    "migration intelligence."
)

_REAL_NOTE = (
    "Real migration triage from P1 recommendation records over the "
    "stored CIR: one item per cryptographic operation. No new migration "
    "data was created."
)

_PRIORITY_TO_SEVERITY = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}


def build_real_items(cir: dict) -> list[dict]:
    """Per-operation migration items from a stored enriched CIR."""
    from ecdat.core import recommend as _recommend

    internal = _recommend.recommend_cir(cir)
    # P1 wire recommendations carry asset_ids but no operation_id, so the
    # join to internal records (for pqc_target) goes through shared
    # asset IDs from the same CIR — never through invented keys.
    wire_by_asset: dict[str, dict] = {}
    for rec in cir.get("recommendations", []) or []:
        if not isinstance(rec, dict):
            continue
        for aid in rec.get("asset_ids", []) or []:
            wire_by_asset.setdefault(str(aid), rec)
    ops_by_id: dict[str, dict] = {}
    for op in cir.get("operations", []) or []:
        if isinstance(op, dict) and op.get("operation_id"):
            ops_by_id[str(op["operation_id"])] = op
    assets_by_id: dict[str, dict] = {}
    for asset in cir.get("assets", []) or []:
        if isinstance(asset, dict) and asset.get("asset_id"):
            assets_by_id[str(asset["asset_id"])] = asset

    items = []
    for rec in internal:
        if not isinstance(rec, dict):
            continue
        op_id = str(rec.get("operation_id", ""))
        op = ops_by_id.get(op_id, {})
        asset = assets_by_id.get(str(op.get("asset_id", "")), {})
        wire: dict = {}
        for aid in rec.get("asset_ids", []) or []:
            hit = wire_by_asset.get(str(aid))
            if hit is not None:
                wire = hit
                break
        canonical = str(asset.get("canonical", "UNKNOWN"))
        pqc_target = str(wire.get("pqc_target") or "")
        title = (f"Migrate {canonical} to {pqc_target}"
                 if pqc_target else f"Migrate {canonical}")
        files: list[str] = []
        for holder in (op, asset):
            loc = holder.get("location") if isinstance(holder, dict) else None
            if isinstance(loc, dict) and loc.get("file"):
                path = str(loc["file"])
                if path not in files:
                    files.append(path)
        node_ids = [i for i in (op_id, str(op.get("asset_id", ""))) if i]
        items.append({
            "rule_id": _rule_id_for_item(asset, canonical),
            "severity": _PRIORITY_TO_SEVERITY.get(
                str(rec.get("priority", "Informational")), "info"),
            "title": title[:300],
            "action": str(rec.get("reason", "")),
            "refs": [str(r) for r in (rec.get("refs") or [])],
            "count": 1,
            "affected_files": files,
            "graph_node_ids": node_ids,
            "status": REAL_STATUS,
        })
    return items


def _rule_id_for_item(asset: dict, canonical: str) -> str:
    from ecdat.core.api import _rule_id_for  # noqa: PLC2701

    return _rule_id_for(
        canonical, asset.get("key_size"),
        asset.get("mode", ""), asset.get("protocol", ""))


def to_real_plan(scan_id: str, target: str, cir: dict) -> dict:
    """Wrap real items in the stable P3 frontend envelope."""
    items = build_real_items(cir)
    return {
        "plan_version": "1",
        "scan_id": scan_id,
        "target": target,
        "item_count": len(items),
        "items": items,
        "triage_label": REAL_TRIAGE_LABEL,
        "not_included": REAL_NOT_INCLUDED,
        "mock": False,
        "dataset": "p1-migration",
        "note": _REAL_NOTE,
        "source": "recommend_cir (internal) + CIR operations over stored CIR",
    }
