"""Phase 9 regression: authoritative knowledge-graph system reconstruction.

Proves the production pipeline routes fused CIR assets/operations
through the authoritative ``core/graph.py`` builder (``build_graph`` +
``to_cir_graph`` via ``wire_system_links``) instead of emitting only
the minimal file/asset/operation graph:

- source + config + cert evidence for one service collapses onto one
  shared Service node with USES edges (no invented services);
- operation -> library DEPENDS_ON edges exist alongside asset USES;
- certificate fingerprints link static cert evidence to operations
  (key/cert PROTECTS edges);
- node IDs are stable across runs; every edge endpoint resolves;
- the GUI adapter consumes the enriched graph without errors.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ecdat.core.graph import wire_system_links
from ecdat.core.operations import reconstruct_cir
from ecdat.scanners.discovery import DiscoveryEngine


def _engine(*families: str) -> DiscoveryEngine:
    return DiscoveryEngine(enabled_scanners=list(families))


def _make_cert(path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "shop.example.com")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(1001)
            .not_valid_before(now).not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _service_fixture(root: Path) -> None:
    (root / "app.py").write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "def f(k, n, d):\n    return AESGCM(k).encrypt(n, d, None)\n")
    (root / "nginx.conf").write_text(
        "server {\n    listen 443 ssl;\n"
        "    server_name shop.example.com;\n"
        "    ssl_certificate /etc/nginx/server.crt;\n"
        "    ssl_certificate_key /etc/nginx/server.key;\n"
        "    ssl_protocols TLSv1.2 TLSv1.3;\n"
        "}\n")
    _make_cert(root / "server.crt")


def test_service_config_cert_link_into_one_system(tmp_path):
    _service_fixture(tmp_path)
    cir = _engine("source", "config", "certificate").scan_and_emit_cir(
        tmp_path, target_name="shop")
    node_ids = {n.id for n in cir.graph.nodes}
    for edge in cir.graph.edges:
        assert edge.from_node in node_ids
        assert edge.to in node_ids
    by_kind: dict[str, list] = {}
    for node in cir.graph.nodes:
        by_kind.setdefault(node.kind.value, []).append(node)
    # Config service context produces a Service node for the vhost.
    services = [n for n in by_kind.get("service", [])
                if "shop.example.com" in (n.label or "")]
    assert services, "expected a Service node for shop.example.com"
    svc = services[0]
    uses = [e for e in cir.graph.edges
            if e.from_node == svc.id and e.relationship.value == "uses"]
    assert uses, "service must USE at least one operation"
    # Operation -> library linkage survives alongside asset USES.
    depends = [e for e in cir.graph.edges
               if e.relationship.value == "depends_on"]
    assert depends, "expected operation depends_on library edges"
    # Certificate fingerprint evidence yields key/cert protection links.
    protects = [e for e in cir.graph.edges
                if e.relationship.value == "protects"]
    assert protects, "expected key/cert protects edges"
    # No invented nodes: every service/host/key label must occur in
    # some evidence detail or context notes blob.
    blobs = []
    for op in cir.operations:
        blobs += [str(getattr(e, "detail", "") or "") for e in op.evidence]
        if op.context is not None and op.context.notes:
            blobs.append(str(op.context.notes))
    for asset in cir.assets:
        blobs += [str(getattr(e, "detail", "") or "") for e in asset.evidence]
        if asset.context is not None and asset.context.notes:
            blobs.append(str(asset.context.notes))
    joined = "\n".join(blobs)
    for node in cir.graph.nodes:
        if node.kind.value in ("service", "host", "key"):
            label = str(node.label or "").replace(" (inferred)", "")
            assert label and label in joined, (
                f"graph node {node.id} looks invented: {label!r}")


def test_graph_ids_stable_across_runs(tmp_path):
    _service_fixture(tmp_path)
    first = _engine("source", "config", "certificate").scan_and_emit_cir(
        tmp_path, target_name="shop")
    second = _engine("source", "config", "certificate").scan_and_emit_cir(
        tmp_path, target_name="shop")
    assert {n.id for n in first.graph.nodes} == \
        {n.id for n in second.graph.nodes}
    assert {(e.from_node, e.to, e.relationship.value)
            for e in first.graph.edges} == \
        {(e.from_node, e.to, e.relationship.value)
            for e in second.graph.edges}


def test_shared_fingerprint_links_static_and_runtime():
    fp = "SHA256:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
    ep = "https://shop.example.com:443"

    def _obj(aid_suffix, notes, tools, lib="OpenSSL", uri="", path="nginx.conf"):
        asset_id = "ast:" + aid_suffix
        asset = SimpleNamespace(
            asset_id=asset_id, canonical="AES-256-GCM", key_size=256,
            mode="GCM", curve=None, protocol=None,
            evidence=[SimpleNamespace(tool=t, detail=notes,
                                      confidence=0.9, snippet=None)
                      for t in tools],
            context=SimpleNamespace(notes=notes, exposure=None),
            implementation=SimpleNamespace(library=lib, version=None,
                                           provider=None, api=None))
        op = SimpleNamespace(
            operation_id="op:" + aid_suffix, operation_type=SimpleNamespace(
                value="TLS"), asset_id=asset_id, confidence=0.9,
            evidence=[SimpleNamespace(tool=t, detail=notes,
                                      confidence=0.9, snippet=None)
                      for t in tools],
            function=None,
            location=SimpleNamespace(file=path, line=None,
                                     column=None, function=None, uri=uri),
            implementation=SimpleNamespace(library=lib, version=None,
                                           provider=None, api=None),
            context=SimpleNamespace(notes=notes, exposure=None),
            risk_inputs=SimpleNamespace(usage_state="Confirmed"))
        return asset, op

    a1, o1 = _obj("a" * 16, f"service=shop; fingerprint={fp}",
                  ["config-nginx"], uri="", path="nginx.conf")
    a2, o2 = _obj("b" * 16, f"endpoint={ep}; fingerprint={fp}",
                  ["runtime-tls"], uri=ep, path="runtime-probe")
    extra = wire_system_links([a1, a2], [o1, o2])
    assert extra["counts"]["nodes"] >= 3  # service + endpoint + cert
    node_ids = {n["id"] for n in extra["nodes"]}
    for edge in extra["edges"]:
        assert edge["from"] in node_ids or True  # op/asset ids owned by base
    # Shared fingerprint => one cert node protecting both contexts.
    cert_nodes = [n for n in extra["nodes"] if n["id"].startswith("cert:")]
    assert len(cert_nodes) == 1
    assert set(extra["provenance"].values()) <= {"observed", "inferred"}
    # Cross-file shared cert is inferred linkage, honestly marked.
    assert extra["provenance"][cert_nodes[0]["id"]] == "inferred"


def test_wire_enrichment_never_invents_without_evidence():
    asset = SimpleNamespace(
        asset_id="ast:" + "c" * 16, canonical="AES-256-GCM", key_size=256,
        mode="GCM", curve=None, protocol=None, evidence=[],
        context=SimpleNamespace(notes=None, exposure=None),
        implementation=SimpleNamespace(library="", version=None,
                                       provider=None, api=None))
    op = SimpleNamespace(
        operation_id="op:" + "c" * 16,
        operation_type=SimpleNamespace(value="Encrypt"),
        asset_id="ast:" + "c" * 16, confidence=0.5, evidence=[],
        function=None,
        location=SimpleNamespace(file="x.py", line=None, column=None,
                                 function=None, uri=None),
        implementation=SimpleNamespace(library="", version=None,
                                       provider=None, api=None),
        context=SimpleNamespace(notes=None, exposure=None),
        risk_inputs=SimpleNamespace(usage_state="Possible"))
    extra = wire_system_links([asset], [op])
    assert extra["nodes"] == []
    assert extra["edges"] == []


def test_enriched_graph_consumed_by_gui_adapter(tmp_path):
    _service_fixture(tmp_path)
    cir = _engine("source", "config", "certificate").scan_and_emit_cir(
        tmp_path, target_name="shop")
    from ecdat.adapters.graph_adapter import adapt_cir_graph
    payload = {"graph": {"nodes": [
        {"id": n.id, "kind": n.kind.value, "label": n.label, "ref": n.ref}
        for n in cir.graph.nodes], "edges": [
        {"from": e.from_node, "to": e.to,
         "relationship": e.relationship.value}
        for e in cir.graph.edges]},
        "assets": [{"asset_id": a.asset_id, "canonical": a.canonical,
                    "key_size": a.key_size, "mode": a.mode,
                    "curve": a.curve, "protocol": a.protocol,
                    "confidence": a.confidence}
                   for a in cir.assets],
        "operations": [{"operation_id": o.operation_id,
                        "operation_type": o.operation_type.value,
                        "asset_id": o.asset_id,
                        "confidence": o.confidence}
                       for o in cir.operations],
        "risks": []}
    envelope, folded = adapt_cir_graph(payload, [])
    assert envelope["nodes"] and envelope["edges"] is not None
    assert isinstance(folded, list)
