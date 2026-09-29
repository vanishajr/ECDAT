"""Pure aggregation of canonical scan data and P1 analysis output."""

from __future__ import annotations

import os
import re
from datetime import datetime

TOP_FILES_LIMIT = 5
TOP_OPERATIONS_LIMIT = 10

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
RISK_ORDER = ("Critical", "High", "Medium", "Low", "Informational")

# Single display label shared by every section: the measured P1 risk
# class when the finding carries one, else the finding severity.
# This guarantees one finding never reads High in one section and
# Medium/Low in another. Pure presentation mapping, no rescoring.
_RISK_CLASS_TO_SEVERITY = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}

# Usage states that constitute demonstrated cryptographic use (vs
# declared dependencies / config capabilities with no confirmed use).
CONFIRMED_USAGE = ("Confirmed", "Probable")

# Presentation-only triage mapping over the real P1 priority/severity.
# No new data: Critical -> Immediate, High -> High priority,
# Medium -> Planned, Low/Informational -> Informational.
MIGRATION_GROUPS = (
    ("Immediate", ("critical",)),
    ("High priority", ("high",)),
    ("Planned", ("medium",)),
    ("Informational", ("low", "info")),
)


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


def _unified_severity(finding: dict) -> str:
    """One label per finding for every report section.

    Prefers the measured P1 risk class from finding metadata; falls
    back to the stored finding severity. Never raises.
    """
    try:
        meta = finding.get("metadata")
        if isinstance(meta, dict):
            cls = str(meta.get("risk_class", "") or "")
            if cls in _RISK_CLASS_TO_SEVERITY:
                return _RISK_CLASS_TO_SEVERITY[cls]
        return str(finding.get("severity", "info") or "info").lower()
    except Exception:
        return "info"


def _is_confirmed_usage(usage_state: str) -> bool:
    """Demonstrated use vs declared capability (dependency/config)."""
    try:
        return str(usage_state or "") in CONFIRMED_USAGE
    except Exception:
        return False


def _scrub_snippet(snippet: str, limit: int = 500) -> str:
    """Defensive redaction for report display (scanners already redact).

    Masks PEM blocks and secret-looking assignments; code context
    stays intact. Pure; never raises, never invents content.
    """
    try:
        text = " ".join(str(snippet or "").split())
        text = re.sub(r"-----BEGIN [A-Z0-9 ]*-----.*?-----END [A-Z0-9 ]*-----",
                      "[REDACTED-PEM-BLOCK]", text)
        text = re.sub(r"(?i)(secret|password|passwd|api[_-]?key|token)\s*[:=]\s*\S+",
                      r"\1=[REDACTED]", text)
        return text[:limit]
    except Exception:
        return ""


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


def _operations_summary(cir: dict | None, risks: list[dict],
                        target: str = "") -> tuple[list, dict, dict]:
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
        location = op.get("location")
        if not isinstance(location, dict):
            location = {}
        file_name = ""
        line_no = 0
        try:
            file_name = display_path(
                target, str(location.get("file", "") or "")) if target else str(
                location.get("file", "") or "")
        except Exception:
            file_name = ""
        try:
            line_no = int(location.get("line", 0) or 0)
        except (TypeError, ValueError):
            line_no = 0
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
            "line": max(0, line_no),
            "evidence_count": evidence_count,
            "risk_class": class_by_op.get(str(op.get("operation_id", "")),
                                          "Informational"),
        })
    # Collapse exact duplicates (same algorithm + type + location, e.g.
    # reported by more than one scanner): keep the strongest signal and
    # count merged occurrences instead of listing the same entry twice.
    merged: dict[tuple, dict] = {}
    for row in rows:
        key = (row["canonical"], row["operation_type"],
               row["file"], row["line"])
        slot = merged.get(key)
        if slot is None:
            row["occurrences"] = 1
            merged[key] = row
            continue
        slot["occurrences"] += 1
        slot["evidence_count"] += row["evidence_count"]
        for field in ("confidence",):
            try:
                if row[field] is not None and (
                        slot[field] is None or row[field] > slot[field]):
                    slot[field] = row[field]
            except Exception:
                pass
        old_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
                    "Informational": 4}.get(slot["risk_class"], 5)
        new_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
                    "Informational": 4}.get(row["risk_class"], 5)
        if new_rank < old_rank:
            slot["risk_class"] = row["risk_class"]
            slot["operation_id"] = row["operation_id"]
    rows = list(merged.values())
    rows.sort(key=lambda r: (
        {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
         "Informational": 4}.get(r["risk_class"], 5),
        -(r["confidence"] or 0.0)
        if isinstance(r["confidence"], (int, float)) else 0.0,
        r["operation_id"]))
    return (rows[:TOP_OPERATIONS_LIMIT],
            dict(sorted(usage_counts.items())),
            dict(sorted(algo_counts.items(), key=lambda kv: (-kv[1], kv[0]))))


def _operations_rollup(cir: dict | None, risks: list[dict],
                       target: str = "") -> list[dict]:
    """Grouped operations summary: one row per (algorithm, operation type).

    Unlike ``_operations_summary`` (top-N detail rows), the rollup is
    never truncated: row count scales with distinct algorithm/type
    combinations (dozens at most), so concise PDF tables can cover
    every operation without growing with the finding count. Pure;
    never raises.
    """
    try:
        if not isinstance(cir, dict):
            return []
        class_by_op: dict[str, str] = {}
        score_by_op: dict[str, float] = {}
        for record in risks or []:
            if isinstance(record, dict) and record.get("operation_id"):
                op_id = str(record["operation_id"])
                class_by_op[op_id] = str(record.get("class", "Informational"))
                try:
                    score_by_op[op_id] = float(record.get("score", 0.0) or 0.0)
                except (TypeError, ValueError):
                    score_by_op[op_id] = 0.0
        assets_by_id: dict[str, dict] = {}
        for asset in cir.get("assets", []) or []:
            if isinstance(asset, dict) and asset.get("asset_id"):
                assets_by_id[str(asset["asset_id"])] = asset
        rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
                "Informational": 4}
        grouped: dict[tuple, dict] = {}
        for op in cir.get("operations", []) or []:
            if not isinstance(op, dict):
                continue
            asset = assets_by_id.get(str(op.get("asset_id", "")), {})
            canonical = str(asset.get("canonical", "UNKNOWN"))
            otype = str(op.get("operation_type", "") or "operation")
            key = (canonical, otype)
            row = grouped.setdefault(key, {
                "algorithm": canonical, "operation_type": otype,
                "count": 0, "confirmed_count": 0, "files": set(),
                "risk_class": "Informational", "max_score": 0.0,
                "max_confidence": None,
            })
            row["count"] += 1
            if _is_confirmed_usage(_usage_of(op)):
                row["confirmed_count"] += 1
            try:
                location = op.get("location") or {}
                raw = str(location.get("file", "") or "")
            except Exception:
                raw = ""
            if raw:
                try:
                    row["files"].add(display_path(target, raw) if target else raw)
                except Exception:
                    pass
            op_id = str(op.get("operation_id", "") or "")
            cls = class_by_op.get(op_id, "Informational")
            if rank.get(cls, 5) < rank.get(row["risk_class"], 5):
                row["risk_class"] = cls
            score = score_by_op.get(op_id, 0.0)
            if score > row["max_score"]:
                row["max_score"] = score
            conf = op.get("confidence")
            if isinstance(conf, (int, float)):
                if row["max_confidence"] is None or conf > row["max_confidence"]:
                    row["max_confidence"] = conf
        rows = []
        for row in grouped.values():
            rows.append({
                "algorithm": row["algorithm"],
                "operation_type": row["operation_type"],
                "count": row["count"],
                "confirmed_count": row["confirmed_count"],
                "file_count": len(row["files"]),
                "risk_class": row["risk_class"],
                "severity": _RISK_CLASS_TO_SEVERITY.get(row["risk_class"], "info"),
                "max_score": row["max_score"],
                "max_confidence": row["max_confidence"],
            })
        rows.sort(key=lambda r: (rank.get(r["risk_class"], 5),
                                 -r["count"], r["algorithm"]))
        return rows
    except Exception:
        return []


def _parse_time(value: object) -> datetime | None:
    try:
        text = str(value or "").strip().replace("Z", "+00:00")
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _duration_sec(doc: dict) -> float | None:
    start = _parse_time(doc.get("started_at"))
    end = _parse_time(doc.get("finished_at"))
    if start is None or end is None:
        return None
    try:
        return max(0.0, (end - start).total_seconds())
    except Exception:
        return None


def _project_name(target: str, display_target: str) -> str:
    """Judge-facing project name: repo-relative display target, no tmp paths."""
    label = str(display_target or target or "unknown")
    label = label.replace("\\", "/").rstrip("/")
    return label.split("/")[-1] or label


def _algo_type(canonical: str, operation_types: list[str]) -> str:
    """Broad crypto family derived from names ECDAT already recorded."""
    upper = str(canonical or "UNKNOWN").upper().replace("_", "-")
    ops = {str(t or "").upper() for t in operation_types}
    if upper.startswith(("ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "HQC",
                         "MLKEM", "MLDSA", "KYBER", "DILITHIUM")):
        return "Post-quantum"
    if "HYBRID" in upper or "+" in upper:
        return "Hybrid"
    if "TLS" in upper or "SSL" in upper or ops == {"TLS"}:
        return "Protocol"
    if upper in ("X.509", "X-509", "KMS") or "CERT" in upper:
        return "Certificate"
    if upper.startswith(("MD5", "SHA", "BLAKE", "HMAC", "POLY1305")):
        return "Hash"
    if upper.startswith(("PBKDF", "BCRYPT", "SCRYPT", "ARGON", "HKDF")):
        return "KDF"
    if upper.startswith(("RSA", "DSA", "DH", "ECDH", "ECDSA", "ED",
                         "X25519", "X448", "ELGAMAL")):
        return "Asymmetric"
    if upper.startswith(("AES", "CHACHA", "DES", "3DES", "RC4", "BLOWFISH")):
        return "Symmetric"
    if ops & {"KEYEXCHANGE", "SIGN", "VERIFY"}:
        return "Asymmetric"
    if "HASH" in ops:
        return "Hash"
    if "KDF" in ops:
        return "KDF"
    if "ENCRYPT" in ops or "DECRYPT" in ops:
        return "Symmetric"
    return "Other"


def _finding_groups(doc: dict, target: str) -> list[dict]:
    """Group raw findings by (rule, unified severity), repo-relative.

    The group label is the measured P1 risk class when the finding
    carries one, else the finding severity — so one finding never
    reads High in one section and Medium/Low in another. Each
    occurrence records whether it is demonstrated use (Confirmed /
    Probable) or a declared capability / dependency without confirmed
    use, plus a defensively scrubbed evidence snippet.
    """
    groups: dict[tuple, dict] = {}
    for finding in doc.get("findings", []) or []:
        if not isinstance(finding, dict):
            continue
        rule_id = str(finding.get("rule_id", "UNKNOWN"))
        severity = _unified_severity(finding)
        key = (rule_id, severity)
        group = groups.setdefault(key, {
            "rule_id": rule_id, "severity": severity,
            "title": str(finding.get("title", rule_id)),
            "count": 0, "confirmed_count": 0,
            "files": {}, "usage_states": set(), "occurrences": [],
        })
        group["count"] += 1
        if group["title"] == rule_id and finding.get("title"):
            group["title"] = str(finding["title"])
        raw_file = str(finding.get("file", "unknown"))
        shown = display_path(target, raw_file)
        try:
            line = int(finding.get("line", 0) or 0)
        except (TypeError, ValueError):
            line = 0
        group["files"][shown] = group["files"].get(shown, 0) + 1
        meta = finding.get("metadata") if isinstance(
            finding.get("metadata"), dict) else {}
        usage_state = str(meta.get("usage_state", "") or "")
        group["usage_states"].add(usage_state or "unknown")
        confirmed = _is_confirmed_usage(usage_state)
        if confirmed:
            group["confirmed_count"] += 1
        group["occurrences"].append({
            "file": shown,
            "line": max(0, line),
            "severity": severity,
            "confirmed": confirmed,
            "confidence": finding.get("confidence"),
            "snippet": _scrub_snippet(str(finding.get("snippet", "") or "")),
            "algorithm": str(meta.get("canonical_name", "") or ""),
            "usage_state": usage_state,
            "risk_class": str(meta.get("risk_class", "") or ""),
            "risk_score": meta.get("risk_score"),
            "rule_id": rule_id,
            "scanner": str(meta.get("scanner", "") or ""),
            "op_id": str(meta.get("cir_op_id", "") or ""),
        })
    ranked = sorted(
        groups.values(),
        key=lambda g: (SEVERITY_ORDER.index(g["severity"])
                       if g["severity"] in SEVERITY_ORDER else 9,
                       -g["count"], g["rule_id"]))
    for group in ranked:
        group["file_count"] = len(group["files"])
        group["confirmed"] = group["confirmed_count"] > 0
        group["usage_states"] = sorted(group["usage_states"])
        group["files"] = [{"file": name, "count": count}
                          for name, count in sorted(
                              group["files"].items(),
                              key=lambda item: (-item[1], item[0]))]
        group["occurrences"].sort(key=lambda o: (o["file"], o["line"]))
    return ranked


def _crypto_inventory(cir: dict | None, risks: list[dict],
                      recommendations: list[dict] | None,
                      target: str) -> list[dict]:
    """Per-algorithm inventory from CIR operations + real risk/migration."""
    if not isinstance(cir, dict):
        return []
    class_by_op = {}
    for record in risks or []:
        if isinstance(record, dict) and record.get("operation_id"):
            class_by_op[str(record["operation_id"])] = str(
                record.get("class", "Informational"))
    assets_by_id = {}
    for asset in cir.get("assets", []) or []:
        if isinstance(asset, dict) and asset.get("asset_id"):
            assets_by_id[str(asset["asset_id"])] = asset
    # Real migration text keyed by canonical name (first real item wins;
    # triage order already reflects P1 priority).
    migration_by_canon: dict[str, str] = {}
    for item in recommendations or []:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "") or "")
        canon = ""
        if title.startswith("Migrate "):
            rest = title[len("Migrate "):]
            canon = rest.split(" to ")[0].strip()
        if canon and canon not in migration_by_canon:
            action = str(item.get("action", "") or "")
            migration_by_canon[canon] = action or title
    rows: dict[str, dict] = {}
    for op in cir.get("operations", []) or []:
        if not isinstance(op, dict):
            continue
        asset = assets_by_id.get(str(op.get("asset_id", "")), {})
        canonical = str(asset.get("canonical", "UNKNOWN"))
        row = rows.setdefault(canonical, {
            "algorithm": canonical, "type": "Other", "uses": 0,
            "confirmed_uses": 0, "capability_uses": 0,
            "files": {}, "operation_types": set(),
            "risk": "Informational", "migration": "",
        })
        row["uses"] += 1
        if _is_confirmed_usage(_usage_of(op)):
            row["confirmed_uses"] += 1
        else:
            row["capability_uses"] += 1
        row["operation_types"].add(str(op.get("operation_type", "")))
        try:
            location = op.get("location") or {}
            raw = str(location.get("file", "") or "")
        except Exception:
            raw = ""
        if raw:
            shown = display_path(target, raw)
            row["files"][shown] = row["files"].get(shown, 0) + 1
        cls = class_by_op.get(str(op.get("operation_id", "")),
                              "Informational")
        cls_rank = RISK_ORDER.index(cls) if cls in RISK_ORDER else 9
        cur_rank = (RISK_ORDER.index(row["risk"])
                    if row["risk"] in RISK_ORDER else 9)
        if cls_rank < cur_rank:
            row["risk"] = cls
    # Assets with no operation still count as inventory. They are
    # declared capabilities (dependencies, config references) unless
    # the asset itself records Confirmed/Probable use.
    for asset in cir.get("assets", []) or []:
        if not isinstance(asset, dict):
            continue
        canonical = str(asset.get("canonical", "UNKNOWN"))
        if canonical not in rows:
            asset_confirmed = _is_confirmed_usage(
                str(asset.get("usage_state", "") or ""))
            rows[canonical] = {
                "algorithm": canonical, "type": "Other", "uses": 0,
                "confirmed_uses": 1 if asset_confirmed else 0,
                "capability_uses": 0 if asset_confirmed else 1,
                "files": {}, "operation_types": set(),
                "risk": "Informational", "migration": "",
            }
            try:
                loc = asset.get("location") or {}
                raw = str(loc.get("file", "") or "")
            except Exception:
                raw = ""
            if raw:
                shown = display_path(target, raw)
                rows[canonical]["files"][shown] = 1
    ordered = sorted(
        rows.values(),
        key=lambda r: ((RISK_ORDER.index(r["risk"])
                        if r["risk"] in RISK_ORDER else 9),
                       -r["uses"], r["algorithm"]))
    out = []
    for row in ordered:
        out.append({
            "algorithm": row["algorithm"],
            "type": _algo_type(row["algorithm"],
                               sorted(row["operation_types"])),
            "uses": row["uses"],
            "confirmed_uses": row["confirmed_uses"],
            "capability_uses": row["capability_uses"],
            "confirmed": row["confirmed_uses"] > 0,
            "file_count": len(row["files"]),
            "files": [{"file": name, "count": count}
                      for name, count in sorted(
                          row["files"].items(),
                          key=lambda item: (-item[1], item[0]))][:10],
            "risk": row["risk"],
            "migration": migration_by_canon.get(row["algorithm"], ""),
        })
    return out


def _affected_components(doc: dict, cir: dict | None,
                         target: str) -> list[dict]:
    """Group findings by top-level directory (repo-relative module)."""
    comp: dict[str, dict] = {}
    for finding in doc.get("findings", []) or []:
        if not isinstance(finding, dict):
            continue
        shown = display_path(target, str(finding.get("file", "unknown")))
        parts = shown.replace("\\", "/").split("/")
        module = parts[0] if len(parts) > 1 else "(root)"
        entry = comp.setdefault(module, {
            "module": module, "findings": 0,
            "by_severity": {}, "algorithms": set(), "files": set(),
        })
        entry["findings"] += 1
        sev = _unified_severity(finding)
        entry["by_severity"][sev] = entry["by_severity"].get(sev, 0) + 1
        entry["files"].add(shown)
        meta = finding.get("metadata") if isinstance(
            finding.get("metadata"), dict) else {}
        if meta.get("canonical_name"):
            entry["algorithms"].add(str(meta["canonical_name"]))
        elif finding.get("rule_id"):
            entry["algorithms"].add(str(finding["rule_id"]))
    ranked = sorted(comp.values(),
                    key=lambda e: (-e["findings"], e["module"]))
    out = []
    for entry in ranked[:15]:
        sev = entry["by_severity"]
        highest = next((s for s in SEVERITY_ORDER if sev.get(s)), "info")
        out.append({
            "module": entry["module"],
            "findings": entry["findings"],
            "file_count": len(entry["files"]),
            "by_severity": dict(sorted(sev.items())),
            "algorithms": sorted(entry["algorithms"])[:10],
            "highest_severity": highest,
        })
    return out


def _coverage_summary(doc: dict, coverage: dict | None,
                      target: str = "") -> dict:
    """Judge-facing coverage: discovered / analyzed / skipped with reasons.

    ``files_discovered`` is the inventory artifact count; ``files_analyzed``
    is files with cryptographic evidence in the CIR. Their gap is files
    scanned with no crypto evidence — stated explicitly, never hidden.
    Every skipped path carries the inventory's own reason, bucketed by
    prefix for the summary and listed per file for audit.
    """
    coverage = coverage if isinstance(coverage, dict) else {}
    try:
        discovered = int(coverage.get("artifacts_total", 0) or 0)
    except (TypeError, ValueError):
        discovered = 0
    try:
        analyzed = int((doc.get("stats", {}) or {}).get("files_scanned", 0) or 0)
    except (TypeError, ValueError):
        analyzed = 0
    if not discovered:
        discovered = analyzed
    skipped_raw = coverage.get("skipped", []) or []
    reasons: dict[str, int] = {}
    buckets: dict[str, int] = {}
    skipped: list[dict] = []
    for entry in skipped_raw:
        if isinstance(entry, dict):
            reason = str(entry.get("reason", "unknown") or "unknown")
            raw_path = str(entry.get("path", "") or "")
            reasons[reason] = reasons.get(reason, 0) + 1
            bucket = reason.split(":")[0].strip() or reason
            buckets[bucket] = buckets.get(bucket, 0) + 1
            shown = display_path(target, raw_path) if target else raw_path
            skipped.append({"path": shown or raw_path, "reason": reason})
        else:
            text = str(entry)
            reasons[text] = reasons.get(text, 0) + 1
            bucket = text.split(":")[0].strip() or text
            buckets[bucket] = buckets.get(bucket, 0) + 1
            skipped.append({"path": "", "reason": text})
    skipped.sort(key=lambda e: (e["reason"], e["path"]))
    skipped_count = len(skipped_raw) if isinstance(skipped_raw, list) else 0
    no_evidence = max(0, discovered - analyzed - skipped_count)
    status = coverage.get("scanner_status", {}) or {}
    failed = sorted(name for name, state in status.items()
                    if isinstance(state, str) and state.startswith("failed"))
    return {
        "files_discovered": discovered,
        "files_analyzed": analyzed,
        "files_skipped": skipped_count,
        "files_without_evidence": no_evidence,
        "skipped_by_reason": dict(sorted(reasons.items(),
                                         key=lambda kv: (-kv[1], kv[0]))),
        "skipped_by_bucket": dict(sorted(buckets.items(),
                                         key=lambda kv: (-kv[1], kv[0]))),
        "skipped": skipped[:50],
        "skipped_files": skipped[:200],
        "failed_scanners": failed,
        "scanner_status": {str(k): str(v) for k, v in status.items()},
        "profile": str(coverage.get("profile", "standard") or "standard"),
        "cache_hit": bool(coverage.get("cache_hit", False)),
        "elapsed_sec": coverage.get("elapsed_sec"),
    }


def _migration_groups(recommendations: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {name: [] for name, _ in MIGRATION_GROUPS}
    for item in recommendations or []:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity", "info")).lower()
        for name, members in MIGRATION_GROUPS:
            if sev in members:
                grouped[name].append(item)
                break
        else:
            grouped["Informational"].append(item)
    return grouped


def _migration_lead_normalized(action: str) -> str:
    """Normalize the op-specific lead for grouping/display.

    P1 reason leads look like ``RSA at multi_evidence.py -> ...``.
    The single location is fully represented in the merged
    affected-files list, so grouping and display drop just that
    fragment; the rest of the P1 text stays verbatim. Pure.
    """
    try:
        return re.sub(r"^(.+?) at \S+?(\s+->)", r"\1\2",
                      str(action or ""), count=1)
    except Exception:
        return str(action or "")


def _dedupe_migration(recommendations: list[dict]) -> list[dict]:
    """Collapse per-operation duplicates into one action per rule.

    Items sharing (rule_key, rule, severity, title, normalized action)
    merge: counts sum, affected files / graph nodes / refs / blockers /
    targets union (order-preserving). Structured P1 fields are kept
    from the first item (identical within a merge key by construction).
    The P1 recommendation body stays verbatim apart from the folded
    location lead (see above).
    """
    merged: dict[tuple, dict] = {}
    order: list[tuple] = []
    for item in recommendations or []:
        if not isinstance(item, dict):
            continue
        norm_action = _migration_lead_normalized(str(item.get("action", "")))
        key = (str(item.get("rule_key", "")), str(item.get("rule_id", "")),
               str(item.get("severity", "")), str(item.get("title", "")),
               norm_action)
        slot = merged.get(key)
        if slot is None:
            slot = dict(item)
            try:
                slot["count"] = int(item.get("count", 1) or 1)
            except (TypeError, ValueError):
                slot["count"] = 1
            slot["action"] = norm_action
            slot["affected_files"] = list(item.get("affected_files", []) or [])
            slot["graph_node_ids"] = list(item.get("graph_node_ids", []) or [])
            slot["refs"] = list(item.get("refs", []) or [])
            merged[key] = slot
            order.append(key)
            continue
        try:
            slot["count"] += int(item.get("count", 1) or 1)
        except (TypeError, ValueError):
            slot["count"] += 1
        for field in ("affected_files", "graph_node_ids", "refs"):
            for value in item.get(field, []) or []:
                if value not in slot[field]:
                    slot[field].append(value)
    return [merged[key] for key in order]


def _methodology(doc: dict, coverage: dict | None,
                 real_risk: dict) -> dict:
    """Technical appendix data: risk model, scanners, versions.

    Keeps the risk formula and scanner internals out of the
    judge-facing sections; everything here is recorded scan data.
    """
    coverage = coverage if isinstance(coverage, dict) else {}
    try:
        from ecdat.adapters.risk_view import REAL_MODEL_NOTE as _note
    except Exception:
        _note = ""
    tools = doc.get("tool_versions", {}) or {}
    status = coverage.get("scanner_status", {}) or {}
    return {
        "risk_model": str(real_risk.get("model", "") or _note or ""),
        "risk_source": str(real_risk.get("source", "") or ""),
        "registry_version": str(coverage.get("registry_version", "") or ""),
        "profile": str(coverage.get("profile", "standard") or "standard"),
        "scanners": sorted(coverage.get("scanners", []) or []),
        "scanner_status": {str(k): str(v) for k, v in status.items()},
        "tool_versions": {str(k): str(v) for k, v in dict(tools).items()},
        "elapsed_sec": coverage.get("elapsed_sec"),
        "cache_hit": bool(coverage.get("cache_hit", False)),
    }


def _executive_summary(project: str, files_analyzed: int,
                       operation_count: int, finding_count: int,
                       groups: list[dict], components: list[dict]) -> str:
    """One deterministic paragraph from real scan data only.

    Names precise rule IDs (e.g. RSA-1024, not generic RSA) from the
    top confirmed finding groups.
    """
    if not finding_count and not operation_count:
        return (f"ECDAT analyzed {files_analyzed} files in {project} and "
                "detected no cryptographic observations.")
    if operation_count:
        volume = (f"detected {operation_count} cryptographic observations "
                  f"({finding_count} findings)")
    else:
        volume = (f"detected {finding_count} finding(s)"
                  if finding_count != 1 else "detected 1 finding")
    confirmed = [g for g in groups if g.get("confirmed")]
    pool = confirmed or list(groups)
    risk_names = ", ".join(g["rule_id"] for g in pool[:3]) or (
        "no named algorithms")
    where = ""
    if components:
        where = f" These issues are concentrated in {components[0]['module']}"
        if len(components) > 1:
            others = len(components) - 1
            where += f" and {others} other area" + ("s" if others != 1 else "")
        where += " and should be prioritized for migration."
    return (f"ECDAT analyzed {files_analyzed} files in {project} and "
            f"{volume}. "
            f"The main risks are {risk_names}.{where}")


def build_report(doc: dict, real_risk: dict | None = None,
                 recommendations: list[dict] | None = None,
                 cir: dict | None = None,
                 limitations: dict | None = None,
                 coverage: dict | None = None,
                 display_label: str = "") -> dict:
    findings = doc.get("findings", []) or []
    severity_counts: dict[str, int] = {}
    rule_counts: dict[str, dict] = {}
    file_counts: dict[str, int] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = _unified_severity(finding)
        rule_id = str(finding.get("rule_id", "UNKNOWN"))
        file_name = str(finding.get("file", "unknown"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        file_counts[file_name] = file_counts.get(file_name, 0) + 1
        # One row per rule: severity rolls up to the highest unified
        # label so the rule table agrees with the finding sections.
        row = rule_counts.setdefault(rule_id, {
            "rule_id": rule_id, "title": str(finding.get("title", rule_id)),
            "severity": severity, "count": 0,
        })
        row["count"] += 1
        old_rank = SEVERITY_ORDER.index(row["severity"]) \
            if row["severity"] in SEVERITY_ORDER else 9
        new_rank = SEVERITY_ORDER.index(severity) \
            if severity in SEVERITY_ORDER else 9
        if new_rank < old_rank:
            row["severity"] = severity
            if finding.get("title"):
                row["title"] = str(finding["title"])
    target = str(doc.get("target", "unknown"))
    top_files = [{"file": display_path(target, name), "count": count}
                 for name, count in sorted(
                     file_counts.items(),
                     key=lambda item: (-item[1], item[0]))[:TOP_FILES_LIMIT]]
    risks = (cir.get("risks", []) or []) if isinstance(cir, dict) else []
    top_operations, usage_states, algorithms = _operations_summary(
        cir, risks, target)
    operations_rollup = _operations_rollup(cir, risks, target)
    if real_risk is None:
        real_risk = {"score": 0.0, "level": "none", "finding_count": len(findings),
                     "risk_count": 0, "source": "no-risk-record"}
    recommendations = list(recommendations or [])
    operation_count = len((cir.get("operations", []) or [])
                          if isinstance(cir, dict) else [])
    asset_count = len((cir.get("assets", []) or [])
                      if isinstance(cir, dict) else [])
    try:
        files_scanned = int((doc.get("stats", {}) or {}).get("files_scanned", 0) or 0)
    except (TypeError, ValueError):
        files_scanned = 0
    display_target = (str(display_label).strip()
                      or display_path(target, target))
    project = _project_name(target, display_target)
    inventory = _crypto_inventory(cir, risks, recommendations, target)
    groups = _finding_groups(doc, target)
    components = _affected_components(doc, cir, target)
    coverage_summary = _coverage_summary(doc, coverage, target)
    actions = _dedupe_migration(recommendations)
    migration = _migration_groups(actions)
    top_issues = [{"rule_id": g["rule_id"], "severity": g["severity"],
                   "title": g["title"], "count": g["count"],
                   "file_count": g["file_count"],
                   "file": g["occurrences"][0]["file"] if g["occurrences"] else "",
                   "line": g["occurrences"][0]["line"] if g["occurrences"] else 0,
                   "snippet": g["occurrences"][0]["snippet"] if g["occurrences"] else ""}
                  for g in groups[:8]]
    # Top risk contributors: highest wire risks with human context.
    # Each carries the unified display label, location, and the first
    # stored evidence snippet so reports can show why it matters.
    ops_by_id = {}
    assets_by_id = {}
    snippet_by_op: dict[str, str] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        meta = finding.get("metadata")
        op_id = str(meta.get("cir_op_id", "")) if isinstance(meta, dict) else ""
        if op_id and op_id not in snippet_by_op and finding.get("snippet"):
            snippet_by_op[op_id] = _scrub_snippet(
                str(finding.get("snippet", "") or ""), 300)
    if isinstance(cir, dict):
        for op in cir.get("operations", []) or []:
            if isinstance(op, dict) and op.get("operation_id"):
                ops_by_id[str(op["operation_id"])] = op
        for asset in cir.get("assets", []) or []:
            if isinstance(asset, dict) and asset.get("asset_id"):
                assets_by_id[str(asset["asset_id"])] = asset
    contributors = []
    for record in (risks or [])[:8]:
        if not isinstance(record, dict):
            continue
        op = ops_by_id.get(str(record.get("operation_id", "")), {})
        asset = assets_by_id.get(str(op.get("asset_id",
                                            record.get("asset_id", ""))), {})
        loc = op.get("location") if isinstance(op, dict) else None
        raw = str((loc or {}).get("file", "") or "")
        try:
            line_no = int((loc or {}).get("line", 0) or 0)
        except (TypeError, ValueError):
            line_no = 0
        cls = str(record.get("class", "Informational"))
        contributors.append({
            "class": cls,
            "severity": _RISK_CLASS_TO_SEVERITY.get(cls, "info"),
            "score": record.get("score", 0.0),
            "confidence": record.get("confidence"),
            "algorithm": str(asset.get("canonical",
                                       record.get("title", "UNKNOWN"))),
            "file": display_path(target, raw) if raw else "",
            "line": max(0, line_no),
            "usage_state": _usage_of(op) if op else "",
            "title": re.sub(r"\s*\[[^\]]*\]\s*$", "",
                            str(record.get("title", "") or "")),
            "description": str(record.get("description", "") or ""),
            "snippet": snippet_by_op.get(str(record.get("operation_id", "")), ""),
        })
    summary = _executive_summary(project, files_scanned, operation_count,
                                 len(findings), groups, components)
    methodology = _methodology(doc, coverage, real_risk)
    return {
        "scan_id": doc.get("scan_id", ""), "target": target,
        "display_target": display_target,
        "project_name": project,
        "status": "COMPLETE",
        "started_at": doc.get("started_at", ""),
        "finished_at": doc.get("finished_at", ""),
        "duration_sec": _duration_sec(doc),
        "tool_versions": dict(doc.get("tool_versions", {}) or {}),
        "finding_count": len(findings), "files_scanned": files_scanned,
        "by_severity": dict(sorted(severity_counts.items())),
        "by_rule": sorted(rule_counts.values(), key=lambda r: (-r["count"], r["rule_id"])),
        "top_files": top_files,
        "risk": dict(real_risk), "real_risk": dict(real_risk),
        "recommendations": recommendations,
        "migration_actions": actions,
        "migration_groups": {name: items for name, items in migration.items()},
        "migration_counts": {name: len(items)
                             for name, items in migration.items()},
        # Phase 12 operation/evidence-centric delivery (default empty so
        # older callers keep working byte-for-byte on the base keys).
        "operation_count": operation_count,
        "asset_count": asset_count,
        "top_operations": top_operations,
        "operations_rollup": operations_rollup,
        "top_risks": contributors,
        "top_issues": top_issues,
        "usage_states": usage_states,
        "algorithms": algorithms,
        "inventory": inventory,
        "finding_groups": groups,
        "components": components,
        "summary": summary,
        "methodology": methodology,
        "limitations": dict(limitations or {}),
        "coverage": dict(coverage or {}),
        "coverage_summary": coverage_summary,
    }


# --- Phase 15: report-quality projection views (additive) -------------------
# Each view below *projects* structures build_report() already produces
# (or the CIR / risk / recommendation wires it consumes) without changing
# build_report() itself. All views are pure, never raise, and return
# plain JSON-able dicts/lists so GUI + export layers share one shape.


def inventory_view(cir: dict | None) -> list[dict]:
    """Per-algorithm inventory projection (algorithm/type/uses/confirmed).

    Projects CIR operations + assets without needing risks or
    recommendations: one row per canonical algorithm with use counts,
    confirmed-vs-capability split, file fan-out, and operation types.
    """
    try:
        if not isinstance(cir, dict):
            return []
        assets_by_id: dict[str, dict] = {}
        for asset in cir.get("assets", []) or []:
            if isinstance(asset, dict) and asset.get("asset_id"):
                assets_by_id[str(asset["asset_id"])] = asset
        rows: dict[str, dict] = {}
        for op in cir.get("operations", []) or []:
            if not isinstance(op, dict):
                continue
            asset = assets_by_id.get(str(op.get("asset_id", "")), {})
            canonical = str(asset.get("canonical", "UNKNOWN"))
            row = rows.setdefault(canonical, {
                "algorithm": canonical, "type": "Other", "uses": 0,
                "confirmed_uses": 0, "capability_uses": 0,
                "files": {}, "operation_types": set(),
            })
            row["uses"] += 1
            if _is_confirmed_usage(_usage_of(op)):
                row["confirmed_uses"] += 1
            else:
                row["capability_uses"] += 1
            row["operation_types"].add(str(op.get("operation_type", "")))
            try:
                location = op.get("location") or {}
                raw = str(location.get("file", "") or "")
            except Exception:
                raw = ""
            if raw:
                row["files"][raw] = row["files"].get(raw, 0) + 1
        for asset in cir.get("assets", []) or []:
            if not isinstance(asset, dict):
                continue
            canonical = str(asset.get("canonical", "UNKNOWN"))
            if canonical not in rows:
                confirmed = _is_confirmed_usage(
                    str(asset.get("usage_state", "") or ""))
                rows[canonical] = {
                    "algorithm": canonical, "type": "Other", "uses": 0,
                    "confirmed_uses": 1 if confirmed else 0,
                    "capability_uses": 0 if confirmed else 1,
                    "files": {}, "operation_types": set(),
                }
        out = []
        for row in sorted(rows.values(),
                          key=lambda r: (-r["uses"], r["algorithm"])):
            out.append({
                "algorithm": row["algorithm"],
                "type": _algo_type(row["algorithm"],
                                   sorted(row["operation_types"])),
                "uses": row["uses"],
                "confirmed_uses": row["confirmed_uses"],
                "capability_uses": row["capability_uses"],
                "confirmed": row["confirmed_uses"] > 0,
                "file_count": len(row["files"]),
                "operation_types": sorted(row["operation_types"]),
            })
        return out
    except Exception:
        return []


def findings_view(cir: dict | None, risks: list[dict] | None) -> list[dict]:
    """Only-actionable findings projection: confirmed use with real risk.

    Joins CIR operations to wire risks; operations without a risk record
    or without Confirmed/Probable use are excluded (declared capabilities
    belong in the inventory view, not here). Sorted worst-first.
    """
    try:
        if not isinstance(cir, dict):
            return []
        risk_by_op: dict[str, dict] = {}
        for record in risks or []:
            if isinstance(record, dict) and record.get("operation_id"):
                risk_by_op[str(record["operation_id"])] = record
        assets_by_id: dict[str, dict] = {}
        for asset in cir.get("assets", []) or []:
            if isinstance(asset, dict) and asset.get("asset_id"):
                assets_by_id[str(asset["asset_id"])] = asset
        rows = []
        for op in cir.get("operations", []) or []:
            if not isinstance(op, dict):
                continue
            op_id = str(op.get("operation_id", "") or "")
            record = risk_by_op.get(op_id)
            if record is None:
                continue
            if not _is_confirmed_usage(_usage_of(op)):
                continue
            asset = assets_by_id.get(str(op.get("asset_id", "")), {})
            location = op.get("location") if isinstance(
                op.get("location"), dict) else {}
            rows.append({
                "operation_id": op_id,
                "operation_type": str(op.get("operation_type", "")),
                "algorithm": str(asset.get("canonical", "UNKNOWN")),
                "usage_state": _usage_of(op),
                "confidence": op.get("confidence"),
                "file": str((location or {}).get("file", "") or ""),
                "line": int((location or {}).get("line", 0) or 0),
                "risk_class": str(record.get("class", "Informational")),
                "risk_score": record.get("score", 0.0),
                "title": str(record.get("title", "") or ""),
            })
        rank = {name: idx for idx, name in enumerate(RISK_ORDER)}
        rows.sort(key=lambda r: (rank.get(r["risk_class"], 9),
                                 r["operation_id"]))
        return rows
    except Exception:
        return []


def migration_view(cir: dict | None,
                   recs: list[dict] | None) -> list[dict]:
    """Migration projection: deduped actions joined to affected algorithms.

    Reuses the same dedupe + normalisation as build_report() so the view
    agrees with the shipped report byte-for-byte on content.
    """
    try:
        actions = _dedupe_migration(list(recs or []))
        algos_by_file: dict[str, set] = {}
        if isinstance(cir, dict):
            assets_by_id = {}
            for asset in cir.get("assets", []) or []:
                if isinstance(asset, dict) and asset.get("asset_id"):
                    assets_by_id[str(asset["asset_id"])] = asset
            for op in cir.get("operations", []) or []:
                if not isinstance(op, dict):
                    continue
                asset = assets_by_id.get(str(op.get("asset_id", "")), {})
                canon = str(asset.get("canonical", ""))
                try:
                    raw = str((op.get("location") or {}).get("file", "")
                              or "")
                except Exception:
                    raw = ""
                if canon and raw:
                    algos_by_file.setdefault(raw, set()).add(canon)
        out = []
        for item in actions:
            if not isinstance(item, dict):
                continue
            files = list(item.get("affected_files", []) or [])
            algos: set = set()
            for path in files:
                algos |= algos_by_file.get(str(path), set())
            out.append({
                "title": str(item.get("title", "")),
                "action": str(item.get("action", "")),
                "severity": str(item.get("severity", "info")),
                "count": item.get("count", 1),
                "affected_files": files,
                "algorithms": sorted(algos),
                "rule_key": str(item.get("rule_key", "")),
                "rule_id": str(item.get("rule_id", "")),
            })
        return out
    except Exception:
        return []


def evidence_view(operation: dict | None) -> list[dict]:
    """Evidence projection for one CIR operation (scrubbed, ordered).

    Returns the stored evidence signals with defensive snippet
    redaction; never invents content, never raises.
    """
    try:
        if not isinstance(operation, dict):
            return []
        signals = operation.get("evidence", []) or []
        out = []
        for index, signal in enumerate(signals):
            if isinstance(signal, dict):
                out.append({
                    "index": index,
                    "kind": str(signal.get("kind", "") or ""),
                    "confidence": signal.get("confidence"),
                    "snippet": _scrub_snippet(
                        str(signal.get("snippet", "") or "")),
                    "scanner": str(signal.get("scanner", "") or ""),
                    "detail": str(signal.get("detail", "") or ""),
                })
            else:
                out.append({"index": index, "kind": "unknown",
                            "confidence": None,
                            "snippet": _scrub_snippet(str(signal)),
                            "scanner": "", "detail": ""})
        return out
    except Exception:
        return []


def risk_details_view(risk: dict | None) -> dict:
    """Risk-record projection: class/score/confidence + human context."""
    try:
        if not isinstance(risk, dict):
            return {"class": "Informational", "score": 0.0,
                    "confidence": None, "title": "",
                    "description": "", "severity": "info",
                    "operation_id": ""}
        cls = str(risk.get("class", "Informational") or "Informational")
        return {
            "class": cls,
            "severity": _RISK_CLASS_TO_SEVERITY.get(cls, "info"),
            "score": risk.get("score", 0.0),
            "confidence": risk.get("confidence"),
            "title": str(risk.get("title", "") or ""),
            "description": str(risk.get("description", "") or ""),
            "operation_id": str(risk.get("operation_id", "") or ""),
            "factors": dict(risk.get("factors", {}) or {})
            if isinstance(risk.get("factors"), dict) else {},
        }
    except Exception:
        return {"class": "Informational", "score": 0.0,
                "confidence": None, "title": "",
                "description": "", "severity": "info",
                "operation_id": ""}


def coverage_view(scan_result: dict | None) -> dict:
    """Coverage projection for a stored scan result (plan + diagnostics).

    Accepts either a full scan-result mapping with ``plan`` /
    ``diagnostics`` keys or an already-shaped coverage mapping;
    delegates to coverage_payload() so the view agrees with reports.
    """
    try:
        if not isinstance(scan_result, dict):
            return coverage_payload(None, None)
        if "plan" in scan_result or "diagnostics" in scan_result:
            return coverage_payload(scan_result.get("plan"),
                                    scan_result.get("diagnostics"))
        return coverage_payload(scan_result.get("coverage_plan"),
                                scan_result)
    except Exception:
        return coverage_payload(None, None)
