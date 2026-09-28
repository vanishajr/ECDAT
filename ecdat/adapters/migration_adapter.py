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
without parsing prose.

Two additive planning aids ARE computed here (clearly labelled, never
presented as commitments):

- estimate_days {min, max} + estimate_basis: a rough planning range
  derived from P1's effort label (S/M/L), affected-file fan-out, and
  blocker count. A heuristic for triage sizing, not a commitment.
- app_group: the code-boundary bucket (first two repo-relative path
  segments) the item belongs to, plus an app_groups envelope summary.
  Triage grouping only — still NOT a migration sequence.
"""

from __future__ import annotations

import math
import os
import re

REAL_STATUS = "identified — migration not started (v1 tracks no migration state)"

REAL_TRIAGE_LABEL = (
    "Ordered by P1 recommendation priority (Critical first), then "
    "replacement score. This is triage order, NOT a migration sequence: "
    "canonical v1 contains no ordering, dependency, or phasing data."
)

REAL_NOT_INCLUDED = (
    "Migration timelines; phased sequencing; migration confidence; real "
    "migration state; owners. Rough per-item day ranges (estimate_days) "
    "are planning aids, not commitments. All await future migration "
    "intelligence."
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

_PRIORITY_RANK = {
    "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4,
}

# Rough planning ranges (person-days) per P1 effort label. Heuristic for
# triage sizing only: base range, widened by file fan-out and blockers.
_EFFORT_DAY_RANGES = {"S": (1, 2), "M": (3, 7), "L": (10, 20)}
_EFFORT_DAY_DEFAULT = (2, 5)


def estimate_days(effort: object, file_count: int = 1,
                  blockers: list | tuple | None = None,
                  pattern: object = "") -> tuple[int, int, str]:
    """Rough (min, max) person-day range + human-readable basis.

    Pure; never raises (degrades to the default range). Hybrid patterns
    (dual-stack transition work) widen the top end; each blocker widens
    it by a day (cap +5). This is a planning aid, not a commitment —
    callers must present estimate_basis alongside the numbers.
    """
    try:
        base = _EFFORT_DAY_RANGES.get(str(effort or "").strip().upper(),
                                      _EFFORT_DAY_DEFAULT)
    except Exception:
        base = _EFFORT_DAY_DEFAULT
    try:
        files = max(1, int(file_count))
    except (TypeError, ValueError):
        files = 1
    try:
        n_blockers = len(list(blockers or []))
    except TypeError:
        n_blockers = 0
    fanout = min(3.0, 1.0 + 0.25 * (files - 1))
    low = max(1, int(math.ceil(base[0] * fanout)))
    high = int(math.ceil(base[1] * fanout))
    hybrid = "hybrid" in str(pattern or "").lower()
    if hybrid:
        high += 3
    high = min(40, high + min(5, max(0, n_blockers)))
    high = max(high, low)
    basis = (f"P1 effort {str(effort or '?').strip().upper() or '?'} "
             f"over {files} file(s)")
    if hybrid:
        basis += "; hybrid transition"
    if n_blockers:
        basis += f"; +{min(5, n_blockers)}d for {n_blockers} blocker(s)"
    return low, high, basis


def app_group_for(files: list | tuple | None) -> str:
    """Code-boundary bucket for an item from its affected files.

    First repo-relative path wins: 3+ segments -> top two
    (``services/payments/vault.py`` -> ``services/payments``); 2 segments
    -> the top directory (``src/a.py`` -> ``src``); anything shallower or
    unparseable -> ``(root)``. Pure; never raises.
    """
    try:
        first = ""
        for candidate in (files or []):
            text = str(candidate or "").strip().replace("\\", "/")
            if text:
                first = text
                break
        parts = [p for p in first.strip("/").split("/") if p not in ("", ".")]
        if len(parts) >= 3:
            return f"{parts[0]}/{parts[1]}"
        if len(parts) == 2:
            return parts[0]
        return "(root)"
    except Exception:
        return "(root)"


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
        effort_label = str(rec.get("effort", "") or "")
        blocker_list = [str(b) for b in (rec.get("blockers", []) or [])]
        pattern = str(rec.get("migration_pattern", "") or "")
        est_min, est_max, est_basis = estimate_days(
            effort_label, len(files), blocker_list, pattern)
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
            "migration_pattern": pattern,
            "compatibility": str(rec.get("compatibility", "") or ""),
            "effort": effort_label,
            "latency_cost_class": str(
                rec.get("latency_cost_class", "") or ""),
            "blockers": blocker_list,
            "why_text": why_text,
            "estimate_days": {"min": est_min, "max": est_max},
            "estimate_basis": est_basis,
            "app_group": app_group_for(files),
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
        "app_groups": summarize_app_groups(items),
        "triage_label": REAL_TRIAGE_LABEL,
        "not_included": REAL_NOT_INCLUDED,
        "dataset": "p1-migration",
        "note": _REAL_NOTE,
        "source": "recommend_cir (internal) + CIR operations over stored CIR",
    }


def summarize_app_groups(items: list[dict]) -> list[dict]:
    """Boundary buckets over migration items (triage grouping, not phases).

    Groups by ``app_group``; each entry carries item count, the highest
    P1 priority inside, and the summed estimate range. Group order is
    highest-priority-first, then group name — the same triage semantics
    as the item list, never a migration sequence. Pure; never raises.
    """
    try:
        buckets: dict[str, dict] = {}
        for item in items or []:
            if not isinstance(item, dict):
                continue
            group = str(item.get("app_group", "") or "(root)")
            entry = buckets.setdefault(group, {
                "group": group, "item_count": 0,
                "top_priority": "Informational",
                "est_min_days": 0, "est_max_days": 0,
            })
            entry["item_count"] += 1
            rank = _PRIORITY_RANK.get(str(item.get("priority", "")), 4)
            top = _PRIORITY_RANK.get(str(entry["top_priority"]), 4)
            if rank < top:
                entry["top_priority"] = str(item.get("priority", "")
                                            or "Informational")
            est = item.get("estimate_days") or {}
            try:
                entry["est_min_days"] += int(est.get("min", 0) or 0)
                entry["est_max_days"] += int(est.get("max", 0) or 0)
            except (TypeError, ValueError):
                pass
        return sorted(
            buckets.values(),
            key=lambda e: (_PRIORITY_RANK.get(str(e["top_priority"]), 4),
                           str(e["group"])))
    except Exception:
        return []
