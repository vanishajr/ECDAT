"""CIR wire graph -> P3 GUI graph vocabulary (Person 3 platform layer).

Maps CIR node kinds (asset|operation|file|service|host|library|key) and
relationships (uses|calls|contains|derives|protects|depends_on|
terminates) onto the frozen P3 frontend model without replacing it.

File nodes are FOLDED (P3 has no File type): each ``file CONTAINS X``
edge is dropped and the file path is preserved on X's node metadata
(``location_file``) — no information loss, no invented nodes.

Unknown kinds/relationships raise ValueError (never silently
discarded). No trace paths are synthesized: an empty list is honest
(P2 emits none; P1's rich traces are a future enhancement).
"""

from __future__ import annotations

_KIND_TO_TYPE = {
    "asset": "CryptoAsset",
    "operation": "CryptoOperation",
    "library": "Library",
    "service": "Service",
    "host": "Endpoint",
    "key": "CertificateKey",
}

_REL_TO_TYPE = {
    "uses": "uses",
    "depends_on": "depends_on",
    "protects": "protects",
    "contains": "implements",
    "derives": "depends_on",
    "calls": "uses",
    "terminates": "exposes",
}

# Wire relationships whose meaning changes in the GUI vocabulary; the
# original name is preserved in edge detail for traceability.
_REL_DETAIL = {
    "contains": "CIR contains",
    "derives": "CIR derives",
    "calls": "CIR calls",
    "terminates": "CIR terminates",
}

_CLASS_TO_RISK = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}


def adapt_cir_graph(
    cir: dict, risks: list[dict] | None = None
) -> tuple[dict, list[str]]:
    """Adapt a stored enriched CIR graph to the P3 frontend envelope.

    Returns ``(raw_envelope, folded_files)`` where raw_envelope is ready
    for ``to_frontend_graph`` ({nodes, edges, trace_paths}) and
    folded_files lists the file paths preserved into node metadata.
    ``risks`` are P1 wire risks (operation_id -> class) for node rings.
    """
    if not isinstance(cir, dict):
        raise ValueError("CIR must be a dict")
    wire = cir.get("graph", {}) or {}
    wire_nodes = wire.get("nodes", []) or []
    wire_edges = wire.get("edges", []) or []

    risk_by_op: dict[str, str] = {}
    for record in risks or []:
        if isinstance(record, dict) and record.get("operation_id"):
            cls = str(record.get("class", ""))
            if cls in _CLASS_TO_RISK:
                risk_by_op[str(record["operation_id"])] = _CLASS_TO_RISK[cls]

    assets_by_id: dict[str, dict] = {}
    for asset in cir.get("assets", []) or []:
        if isinstance(asset, dict) and asset.get("asset_id"):
            assets_by_id[str(asset["asset_id"])] = asset
    ops_by_id: dict[str, dict] = {}
    for op in cir.get("operations", []) or []:
        if isinstance(op, dict) and op.get("operation_id"):
            ops_by_id[str(op["operation_id"])] = op
    asset_risk: dict[str, str] = {}
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for op_id, op in ops_by_id.items():
        risk = risk_by_op.get(op_id)
        asset_id = str(op.get("asset_id", ""))
        if risk and asset_id:
            prev = asset_risk.get(asset_id)
            if prev is None or _order[risk] < _order[prev]:
                asset_risk[asset_id] = risk

    from ecdat.core.api import _rule_id_for  # noqa: PLC2701

    def rule_for(node_id: str, kind: str) -> str | None:
        if kind == "operation":
            op = ops_by_id.get(node_id, {})
            asset = assets_by_id.get(str(op.get("asset_id", "")), {})
        elif kind == "asset":
            asset = assets_by_id.get(node_id, {})
        else:
            return None
        if not asset:
            return None
        return _rule_id_for(
            str(asset.get("canonical", "UNKNOWN")), asset.get("key_size"),
            asset.get("mode", ""), asset.get("protocol", ""))

    file_labels: dict[str, str] = {}
    for node in wire_nodes:
        if isinstance(node, dict) and node.get("kind") == "file":
            file_labels[str(node["id"])] = str(
                node.get("label") or node.get("ref") or node["id"])

    folded: dict[str, set[str]] = {}
    nodes: list[dict] = []
    for node in wire_nodes:
        if not isinstance(node, dict) or not node.get("id"):
            continue
        nid = str(node["id"])
        kind = str(node.get("kind", ""))
        if kind == "file":
            continue  # folded into connected nodes below
        if kind not in _KIND_TO_TYPE:
            raise ValueError(f"unmapped CIR graph node kind: {kind!r}")
        meta: dict = {}
        confidence = None
        risk = "none"
        if kind == "operation":
            op = ops_by_id.get(nid, {})
            risk = risk_by_op.get(nid, "none")
            if isinstance(op.get("confidence"), (int, float)):
                confidence = float(op["confidence"])
            if op.get("operation_type"):
                meta["operation_type"] = str(op["operation_type"])
        elif kind == "asset":
            asset = assets_by_id.get(nid, {})
            risk = asset_risk.get(nid, "none")
            if isinstance(asset.get("confidence"), (int, float)):
                confidence = float(asset["confidence"])
            for key in ("canonical", "key_size", "mode", "curve",
                        "protocol", "library"):
                if asset.get(key) is not None:
                    meta[key] = asset[key]
        # Folded file paths are attached after edge folding below.
        rule_id = rule_for(nid, kind)
        out: dict = {
            "id": nid,
            "type": _KIND_TO_TYPE[kind],
            "label": str(node.get("label") or nid),
            "risk": risk,
            "confidence": confidence,
            "metadata": meta,
        }
        if rule_id is not None:
            out["rule_id"] = rule_id
        nodes.append(out)

    for edge in wire_edges:
        if not isinstance(edge, dict):
            continue
        src, dst = str(edge.get("from", "")), str(edge.get("to", ""))
        rel = str(edge.get("relationship", ""))
        if src in file_labels or dst in file_labels:
            other = dst if src in file_labels else src
            path = file_labels.get(src) or file_labels.get(dst, "")
            if other and path:
                folded.setdefault(other, set()).add(path)
            continue
        if rel not in _REL_TO_TYPE:
            raise ValueError(f"unmapped CIR graph relationship: {rel!r}")
    # Second pass: edges between kept nodes (file edges already folded).
    edges: list[dict] = []
    for edge in wire_edges:
        if not isinstance(edge, dict):
            continue
        src, dst = str(edge.get("from", "")), str(edge.get("to", ""))
        rel = str(edge.get("relationship", ""))
        if src in file_labels or dst in file_labels:
            continue
        gui_rel = _REL_TO_TYPE[rel]  # validated above; KeyError impossible
        edges.append({
            "id": f"{src}|{gui_rel}|{dst}",
            "source": src,
            "target": dst,
            "type": gui_rel,
            "detail": _REL_DETAIL.get(rel, ""),
        })

    # Attach folded file paths to node metadata (nodes were built before
    # folding ran; patch in place deterministically).
    by_id = {n["id"]: n for n in nodes}
    for nid, paths in folded.items():
        node = by_id.get(nid)
        if node is not None:
            node["metadata"]["location_file"] = sorted(paths)[0]
    folded_files = sorted({p for paths in folded.values() for p in paths})
    return {"nodes": nodes, "edges": edges, "trace_paths": []}, folded_files
