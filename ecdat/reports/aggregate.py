"""Pure aggregation of canonical scan data and P1 analysis output."""

from __future__ import annotations

import os

TOP_FILES_LIMIT = 5
TOP_OPERATIONS_LIMIT = 10


def display_path(target: str, path: str) -> str:
    """Repo-relative display path (Phase 12: no temp absolute paths).

    Paths under the scan target render relative to it; anything else
    renders unchanged. Never raises.
    """
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


def _usage_of(operation: dict) -> str:
    try:
        inputs = operation.get("risk_inputs")
        if isinstance(inputs, dict) and inputs.get("usage_state"):
            return str(inputs["usage_state"])
    except Exception:
        pass
    return str(operation.get("usage_state", "Possible") or "Possible")


def coverage_payload(plan: dict | None,
                     diagnostics: dict | None) -> dict:
    """Coverage/diagnostics view for reports and the GUI (Phase 12).

    Scanners run/skipped/failed, unavailable tools, artifacts by type,
    cache state, escalation, and stage timing from the stored plan +
    diagnostics. Pure; never raises.
    """
    plan = plan if isinstance(plan, dict) else {}
    diagnostics = diagnostics if isinstance(diagnostics, dict) else {}
    try:
        scanner_status = dict(diagnostics.get("scanner_status", {}) or {})
    except Exception:
        scanner_status = {}
    try:
        artifact_counts = dict(
            plan.get("artifact_counts", {}) or
            diagnostics.get("artifact_counts", {}) or {})
    except Exception:
        artifact_counts = {}
    try:
        skipped = list(plan.get("skipped", []) or [])
    except Exception:
        skipped = []
    escalation = diagnostics.get("escalation", {}) or {}
    try:
        binary_stages = dict(diagnostics.get("binary_stages", {}) or {})
    except Exception:
        binary_stages = {}
    return {
        "profile": str(plan.get("profile", "standard") or "standard"),
        "scanners": sorted(plan.get("scanners", []) or []),
        "scanner_status": scanner_status,
        "unavailable": sorted(plan.get("unavailable", []) or []),
        "artifacts_total": int(plan.get("artifacts_total", 0) or 0),
        "artifact_counts": artifact_counts,
        "surfaces": sorted(plan.get("surfaces", []) or []),
        "skipped": skipped,
        "permissions_required": sorted(
            plan.get("permissions_required", []) or []),
        "escalation_allowed": bool(plan.get("escalation_allowed", False)),
        "escalation": escalation if isinstance(escalation, dict) else {},
        "binary_stages": binary_stages,
        "cache_hit": bool(diagnostics.get("cache_hit", False)),
        "cache_key": str(diagnostics.get("cache_key", "") or ""),
        "elapsed_sec": diagnostics.get("elapsed_sec"),
        "registry_version": str(
            diagnostics.get("registry_version", "") or ""),
    }


def _operations_summary(cir: dict | None, risks: list[dict]) -> tuple[list, dict, dict]:
    """Top operations + usage-state counts + algorithm counts from CIR."""
    if not isinstance(cir, dict):
        return [], {}, {}
    class_by_op = {}
    for record in risks or []:
        if isinstance(record, dict) and record.get("operation_id"):
            class_by_op[str(record["operation_id"])] = str(
                record.get("class", "Informational"))
    assets_by_id = {}
    for asset in cir.get("assets", []) or []:
        if isinstance(asset, dict) and asset.get("asset_id"):
            assets_by_id[str(asset["asset_id"])] = asset
    usage_counts: dict[str, int] = {}
    algo_counts: dict[str, int] = {}
    rows = []
    for op in cir.get("operations", []) or []:
        if not isinstance(op, dict):
            continue
        asset = assets_by_id.get(str(op.get("asset_id", "")), {})
        canonical = str(asset.get("canonical", "UNKNOWN"))
        usage = _usage_of(op)
        usage_counts[usage] = usage_counts.get(usage, 0) + 1
        algo_counts[canonical] = algo_counts.get(canonical, 0) + 1
        try:
            location = op.get("location") or {}
            file_name = str(location.get("file", "") or "")
        except Exception:
            file_name = ""
        try:
            evidence_count = len(op.get("evidence", []) or [])
        except Exception:
            evidence_count = 0
        rows.append({
            "operation_id": str(op.get("operation_id", "")),
            "operation_type": str(op.get("operation_type", "")),
            "canonical": canonical,
            "usage_state": usage,
            "confidence": op.get("confidence"),
            "file": file_name,
            "evidence_count": evidence_count,
            "risk_class": class_by_op.get(str(op.get("operation_id", "")),
                                          "Informational"),
        })
    rows.sort(key=lambda r: (
        {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
         "Informational": 4}.get(r["risk_class"], 5),
        -(r["confidence"] or 0.0)
        if isinstance(r["confidence"], (int, float)) else 0.0,
        r["operation_id"]))
    return (rows[:TOP_OPERATIONS_LIMIT],
            dict(sorted(usage_counts.items())),
            dict(sorted(algo_counts.items(), key=lambda kv: (-kv[1], kv[0]))))


def build_report(doc: dict, real_risk: dict,
                 recommendations: list[dict] | None = None,
                 cir: dict | None = None,
                 limitations: dict | None = None,
                 coverage: dict | None = None) -> dict:
    findings = doc["findings"]
    severity_counts: dict[str, int] = {}
    rule_counts: dict[str, dict] = {}
    file_counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding["severity"])
        rule_id = str(finding["rule_id"])
        file_name = str(finding["file"])
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        file_counts[file_name] = file_counts.get(file_name, 0) + 1
        row = rule_counts.setdefault(rule_id, {
            "rule_id": rule_id, "title": str(finding["title"]),
            "severity": severity, "count": 0,
        })
        row["count"] += 1
    target = str(doc["target"])
    top_files = [{"file": display_path(target, name), "count": count}
                 for name, count in sorted(
                     file_counts.items(),
                     key=lambda item: (-item[1], item[0]))[:TOP_FILES_LIMIT]]
    risks = (cir.get("risks", []) or []) if isinstance(cir, dict) else []
    top_operations, usage_states, algorithms = _operations_summary(cir, risks)
    return {
        "scan_id": doc["scan_id"], "target": target,
        "display_target": display_path(target, target),
        "started_at": doc["started_at"], "finished_at": doc["finished_at"],
        "tool_versions": dict(doc["tool_versions"]),
        "finding_count": len(findings), "files_scanned": doc["stats"]["files_scanned"],
        "by_severity": dict(sorted(severity_counts.items())),
        "by_rule": sorted(rule_counts.values(), key=lambda r: (-r["count"], r["rule_id"])),
        "top_files": top_files,
        "risk": dict(real_risk), "real_risk": dict(real_risk),
        "recommendations": list(recommendations or []),
        # Phase 12 operation/evidence-centric delivery (default empty so
        # older callers keep working byte-for-byte on the base keys).
        "operation_count": len((cir.get("operations", []) or [])
                               if isinstance(cir, dict) else []),
        "asset_count": len((cir.get("assets", []) or [])
                           if isinstance(cir, dict) else []),
        "top_operations": top_operations,
        "usage_states": usage_states,
        "algorithms": algorithms,
        "limitations": dict(limitations or {}),
        "coverage": dict(coverage or {}),
    }
