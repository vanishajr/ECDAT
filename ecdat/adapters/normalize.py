"""CIR/canonical normalization (Person 3 platform layer).

P3-owned fixes for known P1/P2 producer gaps, applied without editing
vendored modules:

- deterministic ``scan:<16hex>`` IDs (both producers use uuid4)
- RFC3339 UTC timestamps (P2 emits malformed ``isoformat() + "Z"``)
- real ``files_scanned`` (P1 hardcodes 0)
- asset-only findings (P1 ``to_canonical`` is operation-oriented and
  drops assets — e.g. dependency-only libraries — with no operation)

Pure helpers; all raise ValueError on unusable input (never invent).
"""

from __future__ import annotations

import copy
import hashlib
import re
from datetime import datetime, timezone

SCAN_ID_RE = re.compile(r"^scan:[0-9a-f]{16}$")


def to_rfc3339(value: object) -> str:
    """Normalize a timestamp to ``YYYY-MM-DDTHH:MM:SSZ`` (RFC3339 UTC).

    Accepts datetimes (naive assumed UTC) and ISO strings, including the
    malformed ``...+00:00Z`` shape some producers emit. Raises ValueError
    when nothing parseable remains.
    """
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = str(value or "").strip()
    if not text:
        raise ValueError("empty timestamp cannot be normalized")
    # Repair malformed "+00:00Z" tails before parsing.
    if text.endswith("Z") and ("+" in text[10:] or text[10:].count("-") > 2):
        text = text[:-1]
    candidate = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        raise ValueError(f"unparseable timestamp: {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def deterministic_scan_id(
    target: str,
    registry_version: str,
    tool_versions: dict,
    operation_ids: list[str],
    context_seed: str = "",
) -> str:
    """Stable ``scan:<16hex>`` over scan inputs (no uuid4 anywhere).

    Phase 10: an explicit user context (risk-relevant scan input) joins
    the seed so context-bearing scans get their own IDs instead of
    colliding with default-context scans of the same target. Empty seed
    preserves every historical ID byte-for-byte.
    """
    tools = ",".join(f"{k}={tool_versions[k]}" for k in sorted(tool_versions))
    seed = "|".join([
        str(target),
        str(registry_version),
        tools,
        ",".join(sorted(str(o) for o in operation_ids)),
        str(context_seed or ""),
    ]).encode("utf-8")
    return "scan:" + hashlib.blake2s(seed, digest_size=8).hexdigest()


def files_from_cir(cir: dict) -> list[str]:
    """Distinct real file paths referenced by CIR assets/operations."""
    files: set[str] = set()
    for section in ("assets", "operations"):
        for entry in cir.get(section, []) or []:
            if not isinstance(entry, dict):
                continue
            loc = entry.get("location")
            if isinstance(loc, dict):
                path = str(loc.get("file") or "").strip()
                if path and path != "unknown":
                    files.add(path)
    return sorted(files)


def normalize_cir(cir: dict, target: str, context_seed: str = "") -> dict:
    """Assign deterministic ID + valid timestamps + true stats counts.

    Returns a new dict; the input is not mutated. Risks/recommendations
    already present (e.g. from a re-processed document) are preserved.
    """
    if not isinstance(cir, dict):
        raise ValueError("CIR must be a dict")
    doc = copy.deepcopy(cir)
    op_ids = [
        str(o.get("operation_id"))
        for o in doc.get("operations", []) or []
        if isinstance(o, dict) and o.get("operation_id")
    ]
    tools = doc.get("tool_versions", {}) or {}
    doc["scan_id"] = deterministic_scan_id(
        target, str(doc.get("registry_version", "")), tools, op_ids,
        context_seed)
    doc["target"] = str(target)
    doc["started_at"] = to_rfc3339(doc.get("started_at"))
    doc["finished_at"] = to_rfc3339(doc.get("finished_at"))
    graph = doc.get("graph", {}) or {}
    doc["stats"] = {
        "asset_count": len(doc.get("assets", []) or []),
        "operation_count": len(doc.get("operations", []) or []),
        "node_count": len(graph.get("nodes", []) or []),
        "edge_count": len(graph.get("edges", []) or []),
    }
    if doc.get("risks") is not None:
        doc["stats"]["risk_count"] = len(doc["risks"] or [])
    if doc.get("recommendations") is not None:
        doc["stats"]["recommendation_count"] = len(doc["recommendations"] or [])
    return doc


def synthesize_asset_only_findings(cir: dict) -> list[dict]:
    """Info-level canonical findings for assets with no operation.

    Reuses P1's own rule/severity mapping so asset-only detections
    (typically dependency-only / ProvidedOnly libraries) keep P1
    semantics instead of vanishing. Raises nothing; skips malformed
    assets defensively (they fail CIR validation upstream anyway).
    """
    # P3-owned reuse of P1's pure mapping (vendored module is read-only
    # reference; importing the function avoids a second rule vocabulary).
    from ecdat.core.api import _rule_id_for  # noqa: PLC2701
    from ecdat.core.api import _severity_for  # noqa: PLC2701

    assets = [a for a in cir.get("assets", []) or [] if isinstance(a, dict)]
    referenced: set[str] = set()
    for op in cir.get("operations", []) or []:
        if isinstance(op, dict) and op.get("asset_id"):
            referenced.add(str(op["asset_id"]))
    findings = []
    for asset in assets:
        asset_id = str(asset.get("asset_id") or "")
        if not asset_id or asset_id in referenced:
            continue
        canonical = str(asset.get("canonical") or "UNKNOWN")
        usage_state = str(asset.get("usage_state") or "Possible")
        raw_location = asset.get("location")
        location = raw_location if isinstance(raw_location, dict) else {}
        raw_evidence = asset.get("evidence")
        evidence = raw_evidence if isinstance(raw_evidence, list) else []
        first = evidence[0] if evidence and isinstance(evidence[0], dict) else {}
        try:
            line = int(location.get("line", 0))
        except (TypeError, ValueError):
            line = 0
        finding: dict = {
            "rule_id": _rule_id_for(
                canonical, asset.get("key_size"),
                asset.get("mode", ""), asset.get("protocol", "")),
            "title": f"{canonical} [{asset_id}]",
            "severity": _severity_for(usage_state, None),
            "file": str(location.get("file") or first.get("file")
                        or "unknown") or "unknown",
            "line": max(0, line),
        }
        snippet = str(first.get("snippet", "") or "")
        if snippet:
            finding["snippet"] = snippet[:500]
        try:
            conf = float(asset["confidence"]) if asset.get(
                "confidence") is not None else None
        except (TypeError, ValueError):
            conf = None
        if conf is not None:
            finding["confidence"] = min(1.0, max(0.0, conf))
        metadata: dict = {
            "cir_asset_id": asset_id,
            "canonical_name": canonical,
            "usage_state": usage_state,
            "asset_only": True,
        }
        for key in ("library", "key_size", "mode", "curve", "protocol"):
            if asset.get(key) is not None:
                metadata[key] = asset[key]
        finding["metadata"] = metadata
        findings.append(finding)
    findings.sort(key=lambda f: (str(f["rule_id"]), str(f["file"]), f["line"]))
    return findings
