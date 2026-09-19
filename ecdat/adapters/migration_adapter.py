"""P1 recommendations -> P3 migration envelope (Person 3 platform layer).

Uses P1's INTERNAL recommendation records (rule_key, reason, refs,
target_algorithms, priority, replacement_score) joined with the wire
recommendations (pqc_target) by operation ID. Items are per-operation
(no grouping inventions, no sequencing claims).

Item keys are EXACTLY the P3 migration contract fields
(rule_id, severity, title, action, refs, count, affected_files,
graph_node_ids, status) — the forbidden list (timeline,
migration_sequence, migration_state, sequencing, owner) never appears
as keys. PQC targets surface inside title/action text only, when
genuinely supplied by P1.

Structured P1 detail (rule_key, priority, target_algorithms,
migration_pattern, compatibility, effort, latency_cost_class,
blockers, why_text) is additionally passed through verbatim from the
internal recommendation record so UIs can render structured cards
without parsing prose. All values are P1-calculated; nothing new is
computed here.
"""

from __future__ import annotations

import os
import re

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


def _display_path(target: str, path: str) -> str:
    """Repo-relative display path (mirrors reports.aggregate.display_path)."""
    try:
        text = str(path or "")
        base = str(target or "")
        if not text or not base:
            return text
        norm_text = os.path.normcase(os.path.normpath(text))
        norm_base = os.path.normcase(os.path.normpath(base))
        if norm_text == norm_base:
            return os.path.basename(text.rstrip("/\\")) or text
        if norm_text.startswith(norm_base.rstrip("/\\") + os.sep):
            return os.path.relpath(text, base).replace(os.sep, "/")
        return text
    except Exception:
        return str(path or "")


def _display_action(reason: str, canonical: str, target: str) -> str:
    """Presentation hygiene over the real P1 reason text.

    The recommendation body (targets, rationale, effort, blockers,
    scores) stays verbatim; only the internal ``[op:...]`` id is
    dropped from the lead and absolute scan-target prefixes are
    rewritten repo-relative. Pure; never raises.
    """
    try:
        text = str(reason or "")
        text = re.sub(r"^\s*" + re.escape(canonical) + r"\s*\[[^\]]*\]",
                      canonical, text, count=1)
        if target:
            for match in set(re.findall(r" at (\S+?)(?=[,.)]| -> |$)",
                                        text)):
                rel = _display_path(str(target), match)
                if rel != match:
                    text = text.replace(f" at {match}", f" at {rel}")
        return text
    except Exception:
        return str(reason or "")


def build_real_items(cir: dict, target: str = "") -> list[dict]:
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
                path = _display_path(target, str(loc["file"])) if target else str(
                    loc["file"])
                if path not in files:
                    files.append(path)
        node_ids = [i for i in (op_id, str(op.get("asset_id", ""))) if i]
        # Structured P1 detail, passed through verbatim (see module
        # docstring). Missing keys degrade to ""/[] — never invented.
        rule_key = str(rec.get("rule_key", "") or "")
        why_text = ""
        try:
            from ecdat.core.recommend import RECOMMENDATIONS as _RECS
            template = _RECS.get(rule_key, {})
            why_text = str(template.get("reason", "") or "")
        except Exception:
            why_text = ""
        items.append({
            "rule_id": _rule_id_for_item(asset, canonical),
            "severity": _PRIORITY_TO_SEVERITY.get(
                str(rec.get("priority", "Informational")), "info"),
            "title": title[:300],
            "action": _display_action(str(rec.get("reason", "")),
                                      canonical, target),
            "refs": [str(r) for r in (rec.get("refs") or [])],
            "count": 1,
            "affected_files": files,
            "graph_node_ids": node_ids,
            "status": REAL_STATUS,
            "rule_key": rule_key,
            "priority": str(rec.get("priority", "") or ""),
            "target_algorithms": [str(t) for t in
                                  (rec.get("target_algorithms", []) or [])],
            "migration_pattern": str(rec.get("migration_pattern", "") or ""),
            "compatibility": str(rec.get("compatibility", "") or ""),
            "effort": str(rec.get("effort", "") or ""),
            "latency_cost_class": str(
                rec.get("latency_cost_class", "") or ""),
            "blockers": [str(b) for b in (rec.get("blockers", []) or [])],
            "why_text": why_text,
        })
    return items


def _rule_id_for_item(asset: dict, canonical: str) -> str:
    from ecdat.core.api import _rule_id_for  # noqa: PLC2701

    return _rule_id_for(
        canonical, asset.get("key_size"),
        asset.get("mode", ""), asset.get("protocol", ""))


def to_real_plan(scan_id: str, target: str, cir: dict) -> dict:
    """Wrap real items in the stable P3 frontend envelope."""
    items = build_real_items(cir, target)
    return {
        "plan_version": "1",
        "scan_id": scan_id,
        "target": target,
        "item_count": len(items),
        "items": items,
        "triage_label": REAL_TRIAGE_LABEL,
        "not_included": REAL_NOT_INCLUDED,
        "dataset": "p1-migration",
        "note": _REAL_NOTE,
        "source": "recommend_cir (internal) + CIR operations over stored CIR",
    }
