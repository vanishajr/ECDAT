"""Phase 8 regression: authoritative fusion + operation reconstruction.

Proves the production pipeline calls the real fusion layer
(weighted_fusion/decide_usage) and the real operation builder
(build_operations/reconstruct_cir): dozens of raw mentions collapse
into few semantically strong operations with provenance, usage states
stay explainable, ProvidedOnly never leaks into use, and the CIR
reflects fused evidence.
"""

from __future__ import annotations

from pathlib import Path

from ecdat.core.operations import build_operations, reconstruct_cir
from ecdat.scanners.discovery import DiscoveryEngine


def _engine(*families: str) -> DiscoveryEngine:
    return DiscoveryEngine(enabled_scanners=list(families))


def test_production_calls_fusion_and_builder(tmp_path, monkeypatch):
    import ecdat.core.operations as ops_mod

    calls: list[str] = []
    original = ops_mod.reconstruct_cir

    def _spy(cir):
        calls.append(getattr(cir, "scan_id", ""))
        return original(cir)

    # scan_and_emit_cir imports reconstruct_cir from ecdat.core.operations
    # at call time: patching the source attribute intercepts production.
    monkeypatch.setattr(ops_mod, "reconstruct_cir", _spy)
    (tmp_path / "a.py").write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "def f(k, n, d):\n    return AESGCM(k).encrypt(n, d, None)\n")
    from ecdat.core.orchestrator import ScanRequest, get_orchestrator
    result = get_orchestrator().scan(
        ScanRequest(target=str(tmp_path), scanners=["source"],
                    caller="phase8-spy"))
    assert calls, "production scan must call reconstruct_cir"
    # Post-fusion IDs are content-derived (normalize assigns them after
    # regrouping), so only the call itself plus fused markers assert here;
    # ID determinism is covered by test_operation_ids_stable_and_deterministic.
    assert any("fusion=" in (o.get("context", {}) or {}).get("notes", "")
               for o in result.cir["operations"])


def test_many_mentions_collapse_to_few_operations(tmp_path):
    lines = ["from cryptography.hazmat.primitives.ciphers.aead import AESGCM",
             "",
             "def worker_a(key, nonce, data):"]
    # Same-function repeats far apart (>5 lines: beyond proximity merge).
    for i in range(6):
        lines.append(f"    r{i} = AESGCM(key).encrypt(nonce, data, None)")
        lines.append(f"    _pad{i} = (1, 2, 3, 4, 5, 6)")
    lines.append("    return (r0, r1, r2, r3, r4, r5)")
    lines.append("")
    lines.append("def worker_b(key, nonce, data):")
    for i in range(6, 12):
        lines.append(f"    r{i} = AESGCM(key).encrypt(nonce, data, None)")
        lines.append(f"    _pad{i} = (1, 2, 3, 4, 5, 6)")
    lines.append("    return (r6, r7, r8, r9, r10, r11)")
    (tmp_path / "batch.py").write_text("\n".join(lines) + "\n")
    cir = _engine("source").scan_and_emit_cir(tmp_path, target_name="batch")
    aes_ops = [o for o in cir.operations
               if _asset_canonical(cir, o) == "AES-256-GCM"]
    # 12 raw mentions -> 2 operations (one per function), not 12.
    assert len(aes_ops) == 2
    assert len(cir.operations) < 12
    for op in aes_ops:
        assert len(op.evidence) == 6  # full provenance retained
        assert op.confidence >= 0.85
        assert op.risk_inputs.usage_state.value == "Confirmed"


def _asset_canonical(cir, op) -> str:
    for asset in cir.assets:
        if asset.asset_id == op.asset_id:
            return asset.canonical
    return ""


def test_provided_only_never_becomes_use(tmp_path):
    (tmp_path / "requirements.txt").write_text("openssl==23.0.0\n")
    (tmp_path / "app.py").write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "def f(k, n, d):\n    return AESGCM(k).encrypt(n, d, None)\n")
    cir = _engine("source", "dependency").scan_and_emit_cir(
        tmp_path, target_name="mix")
    provided = [a for a in cir.assets if a.usage_state.value == "ProvidedOnly"]
    assert provided, "dependency capability must survive as ProvidedOnly"
    assert all(a.confidence <= 0.6 for a in provided)
    used = [a for a in cir.assets if a.canonical == "AES-256-GCM"]
    assert used and all(a.usage_state.value == "Confirmed" for a in used)
    # Capability notes ride along; no per-algorithm explosion.
    openssl = [a for a in provided if a.canonical == "OpenSSL"]
    assert openssl


def test_asset_only_evidence_preserved(tmp_path):
    (tmp_path / "requirements.txt").write_text("cryptography==42.0\n")
    cir = _engine("dependency").scan_and_emit_cir(tmp_path, target_name="dep")
    assert cir.assets, "asset-only evidence must be preserved"
    assert cir.operations == []


def test_test_vectors_suppress_not_confirm(tmp_path):
    test_dir = tmp_path / "proj" / "test"
    test_dir.mkdir(parents=True)
    (test_dir / "vectors.c").write_text(
        "#include <openssl/evp.h>\n"
        "int check_aes(void) {\n"
        "    return EVP_EncryptInit_ex(0, EVP_aes_256_gcm(), 0, 0, 0);\n"
        "}\n")
    cir = _engine("source").scan_and_emit_cir(tmp_path, target_name="vec")
    states = {o.risk_inputs.usage_state.value for o in cir.operations
              if o.risk_inputs}
    assert states, "expected reconstructed operations"
    assert "Confirmed" not in states
    assert "FalsePositiveSuppressed" in states


def test_operation_ids_stable_and_deterministic(tmp_path):
    (tmp_path / "a.py").write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "def f(k, n, d):\n    return AESGCM(k).encrypt(n, d, None)\n")
    first = _engine("source").scan_and_emit_cir(tmp_path, target_name="t")
    second = _engine("source").scan_and_emit_cir(tmp_path, target_name="t")
    assert [o.operation_id for o in first.operations] == \
        [o.operation_id for o in second.operations]
    assert [a.asset_id for a in first.assets] == \
        [a.asset_id for a in second.assets]
    assert first.operations[0].operation_id.startswith("op:")
    assert first.operations[0].asset_id.startswith("ast:")


def test_graph_consistent_after_rebuild(tmp_path):
    (tmp_path / "a.py").write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "def f(k, n, d):\n    return AESGCM(k).encrypt(n, d, None)\n"
        "def g(k, n, d):\n    return AESGCM(k).decrypt(n, d, None)\n")
    (tmp_path / "requirements.txt").write_text("cryptography==42.0\n")
    cir = _engine("source", "dependency").scan_and_emit_cir(
        tmp_path, target_name="g")
    node_ids = {n.id for n in cir.graph.nodes}
    for edge in cir.graph.edges:
        assert edge.from_node in node_ids
        assert edge.to in node_ids
    asset_ids = {a.asset_id for a in cir.assets}
    op_ids = {o.operation_id for o in cir.operations}
    for node in cir.graph.nodes:
        if node.kind.value == "asset":
            assert node.ref in asset_ids
        elif node.kind.value == "operation":
            assert node.ref in op_ids
            assert next(
                o for o in cir.operations
                if o.operation_id == node.ref).asset_id in asset_ids


def test_empty_scan_reconstructs_to_empty(tmp_path):
    (tmp_path / "notes.md").write_text("# nothing\n")
    cir = _engine("source", "dependency").scan_and_emit_cir(
        tmp_path, target_name="empty")
    assert cir.assets == [] and cir.operations == []


def test_fusion_floor_and_usage_bands():
    # Direct observation floors confidence; flags still dominate usage.
    fused = build_operations([{
        "operation_type": "Encrypt", "canonical_name": "AES-256-GCM",
        "file": "a.py", "function": "f",
        "evidence": [{"detector": "source", "signal_type": "call",
                      "confidence": 0.92}],
    }])
    assert len(fused) == 1
    assert fused[0]["confidence"] >= 0.9
    assert fused[0]["usage_state"] == "Confirmed"
    assert fused[0]["breakdown"]["has_direct_usage"] is True

    weak = build_operations([{
        "operation_type": "Hash", "canonical_name": "MD5",
        "file": "b.py", "function": "g",
        "evidence": [{"detector": "strings",
                      "signal_type": "pattern-match", "confidence": 0.35}],
    }])
    assert weak[0]["usage_state"] == "Possible"

    provided = build_operations([{
        "operation_type": "Encrypt", "canonical_name": "AES-256-GCM",
        "file": "req.txt", "function": None,
        "dependency_only": True,
        "evidence": [{"detector": "dependency",
                      "signal_type": "dependency-capability",
                      "confidence": 0.6}],
    }])
    assert provided[0]["usage_state"] == "ProvidedOnly"
    assert provided[0]["confidence"] <= 0.35
