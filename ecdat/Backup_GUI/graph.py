"""Crypto Knowledge Graph data layer (Person 3 platform layer).

Separation rule: rendering lives in `server.py` (SVG/JS), data lives
here. The UI consumes only `to_frontend_graph()` output, so the mock
dataset below can later be replaced by real Person 1 API/CIR graph
data without rewriting the UI:

    UI (server.py SVG) -> to_frontend_graph() -> GraphProvider
        MockGraphProvider today (deterministic, hand-authored, mock-labeled)
        Person 1 CIR provider later (same envelope, real edges)

This module is NOT a backend/core graph engine and performs no
detection. It owns no intelligence: node risk values reuse the
existing canonical severity vocabulary, and remediation pointers
reference rule_ids already present in fixtures. Do NOT invent
canonical fields here.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

NODE_TYPES: tuple[str, ...] = (
    "Endpoint",
    "Service",
    "Container",
    "Library",
    "CryptoOperation",
    "CryptoAsset",
    "CertificateKey",
    "CloudResource",
)

RELATIONS: tuple[str, ...] = (
    "uses",
    "provides",
    "implements",
    "configures",
    "protects",
    "exposes",
    "runs_in",
    "depends_on",
)

# Deterministic layered layout (columns follow NODE_TYPES order).
_COL_W, _ROW_H, _NODE_W, _NODE_H = 180, 120, 150, 56
_CANVAS_W, _CANVAS_H = 1500, 680

_MOCK_NOTE = (
    "Deterministic mock graph dataset for UI development. Not derived "
    "from a scan and not Person 1 CIR data; replace the provider with "
    "real CIR output without changing the UI."
)


def _node(
    id: str,
    type: str,
    label: str,
    risk: str,
    confidence: float,
    rule_id: str | None = None,
    **meta: str,
) -> dict:
    node: dict = {
        "id": id,
        "type": type,
        "label": label,
        "risk": risk,
        "confidence": confidence,
        "metadata": dict(meta),
    }
    if rule_id is not None:
        node["rule_id"] = rule_id
    return node


def _edge(source: str, target: str, type: str, detail: str = "") -> dict:
    return {"id": f"{source}|{type}|{target}", "source": source,
            "target": target, "type": type, "detail": detail}


def build_mock_graph() -> dict:
    """Hand-authored deterministic mock graph: 26 nodes, 39 edges."""
    nodes = [
        _node("internet", "Endpoint", "internet", "none", 1.0,
              zone="public", note="external traffic entry point"),
        _node("internal-mesh", "Endpoint", "internal-mesh", "none", 1.0,
              zone="private", note="east-west service mesh"),
        _node("payments-api", "Service", "payments-api", "high", 0.9,
              "RSA-1024", framework="fastapi", version="2.1",
              note="internet-facing payments service"),
        _node("auth-svc", "Service", "auth-svc", "medium", 0.9,
              "MD5-USAGE", framework="go", version="1.22",
              note="authentication service"),
        _node("legacy-billing", "Service", "legacy-billing", "high", 0.85,
              "RSA-1024", framework="flask", version="1.1",
              note="legacy billing service, modernization candidate"),
        _node("payments-ctr", "Container", "payments-ctr", "none", 0.95,
              image="payments:2.1", runtime="containerd"),
        _node("billing-ctr", "Container", "billing-ctr", "none", 0.95,
              image="billing:1.1", runtime="containerd"),
        _node("openssl-3.1", "Library", "openssl-3.1", "none", 0.95,
              version="3.1.4", language="c"),
        _node("boringssl", "Library", "boringssl", "none", 0.9,
              version="stable", language="c++"),
        _node("old-crypto-lib", "Library", "old-crypto-lib", "high", 0.85,
              "RSA-1024", version="0.9", language="c",
              note="unmaintained; source of weak primitives"),
        _node("tls-handshake", "CryptoOperation", "tls-handshake", "low", 0.9,
              protocol="TLS 1.2", mode="ECDHE+AES-GCM"),
        _node("data-encrypt", "CryptoOperation", "data-encrypt", "critical", 0.99,
              "AES-ECB", mode="ECB (risky) alongside GCM"),
        _node("password-hash", "CryptoOperation", "password-hash", "medium", 0.9,
              "MD5-USAGE", note="MD5 path must migrate to SHA-256+"),
        _node("jwt-sign", "CryptoOperation", "jwt-sign", "high", 0.9,
              "RSA-1024", algorithm="RS256-1024"),
        _node("RSA-2048", "CryptoAsset", "RSA-2048", "none", 0.95,
              algorithm="RSA", key_size="2048"),
        _node("AES-256-GCM", "CryptoAsset", "AES-256-GCM", "none", 0.95,
              algorithm="AES", key_size="256", mode="GCM"),
        _node("MD5", "CryptoAsset", "MD5", "medium", 0.9,
              "MD5-USAGE", algorithm="MD5", status="broken"),
        _node("SHA-256", "CryptoAsset", "SHA-256", "none", 0.95,
              algorithm="SHA-2", digest_size="256"),
        _node("RSA-1024", "CryptoAsset", "RSA-1024", "high", 0.95,
              "RSA-1024", algorithm="RSA", key_size="1024",
              status="weak"),
        _node("AES-ECB", "CryptoAsset", "AES-ECB", "critical", 0.99,
              "AES-ECB", algorithm="AES", mode="ECB",
              status="leaks structure"),
        _node("payments-cert", "CertificateKey", "payments-cert", "none", 0.95,
              key="RSA-2048", issuer="acm", expiry="2027-03-01"),
        _node("auth-jwt-key", "CertificateKey", "auth-jwt-key", "high", 0.9,
              "RSA-1024", key="RSA-1024", rotation="manual"),
        _node("legacy-cert", "CertificateKey", "legacy-cert", "high", 0.85,
              "RSA-1024", key="RSA-1024", expiry="2024-11-01",
              status="expired"),
        _node("db-enc-key", "CertificateKey", "db-enc-key", "none", 0.95,
              key="AES-256-GCM", managed_by="aws-kms"),
        _node("aws-acm", "CloudResource", "aws-acm", "none", 0.95,
              provider="aws", service="acm"),
        _node("acm-private-ca", "CloudResource", "acm-private-ca", "none", 0.9,
              provider="aws", service="acm-pca"),
        _node("aws-kms", "CloudResource", "aws-kms", "none", 0.95,
              provider="aws", service="kms", rotation="automatic"),
    ]
    edges = [
        _edge("payments-api", "internet", "exposes", "public HTTPS ingress"),
        _edge("legacy-billing", "internet", "exposes", "public HTTPS ingress (legacy)"),
        _edge("auth-svc", "internal-mesh", "exposes", "mesh-only mTLS"),
        _edge("payments-api", "payments-ctr", "runs_in"),
        _edge("auth-svc", "payments-ctr", "runs_in"),
        _edge("legacy-billing", "billing-ctr", "runs_in"),
        _edge("payments-api", "openssl-3.1", "uses"),
        _edge("auth-svc", "boringssl", "uses"),
        _edge("legacy-billing", "old-crypto-lib", "uses", "risky: unmaintained lib"),
        _edge("billing-ctr", "old-crypto-lib", "depends_on"),
        _edge("openssl-3.1", "tls-handshake", "implements"),
        _edge("openssl-3.1", "data-encrypt", "implements"),
        _edge("boringssl", "tls-handshake", "implements"),
        _edge("old-crypto-lib", "password-hash", "implements", "risky"),
        _edge("old-crypto-lib", "jwt-sign", "implements", "risky: 1024-bit RS256"),
        _edge("old-crypto-lib", "MD5", "provides"),
        _edge("old-crypto-lib", "RSA-1024", "provides"),
        _edge("old-crypto-lib", "AES-ECB", "provides"),
        _edge("openssl-3.1", "RSA-2048", "provides"),
        _edge("openssl-3.1", "AES-256-GCM", "provides"),
        _edge("openssl-3.1", "SHA-256", "provides"),
        _edge("tls-handshake", "RSA-2048", "uses"),
        _edge("data-encrypt", "AES-256-GCM", "uses"),
        _edge("data-encrypt", "AES-ECB", "uses", "risky: legacy ECB mode"),
        _edge("password-hash", "MD5", "uses", "risky: migrate to SHA-256+"),
        _edge("password-hash", "SHA-256", "uses"),
        _edge("jwt-sign", "RSA-1024", "uses", "risky: 1024-bit key"),
        _edge("RSA-2048", "payments-cert", "provides"),
        _edge("RSA-1024", "auth-jwt-key", "provides"),
        _edge("RSA-1024", "legacy-cert", "provides"),
        _edge("AES-256-GCM", "db-enc-key", "provides"),
        _edge("payments-cert", "payments-api", "protects"),
        _edge("legacy-cert", "legacy-billing", "protects", "expired cert on live path"),
        _edge("aws-acm", "payments-cert", "configures", "managed renewal"),
        _edge("acm-private-ca", "legacy-cert", "configures", "manual renewal"),
        _edge("aws-kms", "db-enc-key", "provides", "automatic rotation"),
        _edge("aws-kms", "auth-jwt-key", "provides"),
        _edge("auth-svc", "auth-jwt-key", "depends_on"),
        _edge("payments-api", "payments-cert", "depends_on"),
    ]
    trace_paths = [
        {
            "id": "internet-to-risk",
            "label": "internet-facing service → TLS → RSA-2048 → certificate → risk",
            "node_ids": ["internet", "payments-api", "openssl-3.1",
                         "tls-handshake", "RSA-2048", "payments-cert"],
            "note": "Then open the Risk dashboard (score/level) and the "
                    "inventory RSA-1024 rule filter for findings on this estate.",
        },
        {
            "id": "legacy-risky-path",
            "label": "legacy risky path → MD5 / RSA-1024",
            "node_ids": ["internet", "legacy-billing", "old-crypto-lib",
                         "password-hash", "MD5"],
            "note": "Weak-primitive path: unmaintained lib serving MD5 "
                    "password hashing on an internet-facing service.",
        },
    ]
    return {"nodes": nodes, "edges": edges, "trace_paths": trace_paths}


def to_frontend_graph(raw: dict) -> dict:
    """Validate + deterministically lay out a provider graph for the UI.

    Raises ValueError on dangling edge endpoints, unknown types, or
    broken trace paths. Output node order is stable (type column, then
    id); every node carries x/y canvas coordinates.
    """
    nodes = list(raw.get("nodes", []))
    edges = list(raw.get("edges", []))
    ids = {n["id"] for n in nodes}
    for n in nodes:
        if n["type"] not in NODE_TYPES:
            raise ValueError(f"unknown node type: {n['type']!r}")
    for e in edges:
        if e["type"] not in RELATIONS:
            raise ValueError(f"unknown relation: {e['type']!r}")
        if e["source"] not in ids or e["target"] not in ids:
            raise ValueError(f"dangling edge: {e['id']!r}")
    for t in raw.get("trace_paths", []):
        for nid in t["node_ids"]:
            if nid not in ids:
                raise ValueError(f"trace {t['id']!r} references unknown node {nid!r}")
    by_col: dict[int, list[dict]] = {}
    for n in nodes:
        by_col.setdefault(NODE_TYPES.index(n["type"]), []).append(n)
    placed = []
    for col in sorted(by_col):
        column = sorted(by_col[col], key=lambda n: n["id"])
        for i, n in enumerate(column):
            x = 60 + col * _COL_W
            y = 60 if len(column) == 1 else 60 + i * ((_CANVAS_H - 120) / (len(column) - 1))
            placed.append({**n, "x": round(x, 1), "y": round(y, 1)})
    placed.sort(key=lambda n: (NODE_TYPES.index(n["type"]), n["id"]))
    return {
        "graph_version": "1",
        "nodes": placed,
        "edges": sorted(edges, key=lambda e: e["id"]),
        "trace_paths": list(raw.get("trace_paths", [])),
        "node_count": len(placed),
        "edge_count": len(edges),
        "canvas": {"width": _CANVAS_W, "height": _CANVAS_H,
                   "node_w": _NODE_W, "node_h": _NODE_H},
        "node_types": list(NODE_TYPES),
        "relations": list(RELATIONS),
    }


@runtime_checkable
class GraphProvider(Protocol):
    """Future Person 1 CIR providers implement this envelope."""

    name: str

    def get_graph(self) -> dict:
        """Return a frontend-ready graph envelope (see to_frontend_graph)."""
        ...


class MockGraphProvider:
    """Deterministic mock provider. UI-development placeholder only."""

    name = "mock-graph"

    def get_graph(self) -> dict:
        graph = to_frontend_graph(build_mock_graph())
        graph.update({
            "mock": True,
            "dataset": "mock-graph",
            "note": _MOCK_NOTE,
            "source": "hand-authored mock dataset (NOT canonical scan data)",
        })
        return graph
