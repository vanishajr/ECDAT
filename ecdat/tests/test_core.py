from __future__ import annotations

import json
from pathlib import Path

import pytest

from ecdat.core import (
    CIRDocument,
    CryptoAsset,
    CryptoOperation,
    EvidenceSignal,
    Graph,
    GraphEdge,
    GraphNode,
    UsageState,
    OperationType,
    Exposure,
    GraphNodeKind,
    GraphRelationship,
    new_asset_id,
    new_operation_id,
    load_cir_json,
    validate_cir_json,
    load_registry,
    get_registry_version,
    normalize_algorithm,
    get_category,
    infer_usage_state,
    infer_operation_type,
)


class TestCIRModels:
    def test_evidence_signal_redaction(self):
        evidence = EvidenceSignal(
            tool="test",
            detail="test detail",
            snippet="password=secret123 api_key=abc123 -----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----"
        )
        assert "REDACTED" in evidence.snippet
        assert "secret123" not in evidence.snippet
        assert "abc123" not in evidence.snippet

    def test_evidence_signal_redaction_various_secrets(self):
        """Test redaction of various secret formats."""
        test_cases = [
            ("password=secret123", "secret123"),
            ("secret=mysecret", "mysecret"),
            ("token=abc123def456", "abc123def456"),
            ("api_key=key123", "key123"),
            ("apikey=key456", "key456"),
            ("private_key=mykey", "mykey"),
            ("access_token=token123", "token123"),
            ("bearer_token=bearer123", "bearer123"),
            ("secret_key=sk_123456", "sk_123456"),
            ("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----", "PRIVATE KEY"),
            ("-----BEGIN RSA PRIVATE KEY-----\nkey\n-----END RSA PRIVATE KEY-----", "RSA PRIVATE KEY"),
            ("-----BEGIN EC PRIVATE KEY-----\nkey\n-----END EC PRIVATE KEY-----", "EC PRIVATE KEY"),
            ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC", "ssh-rsa"),
        ]
        
        for snippet, secret in test_cases:
            evidence = EvidenceSignal(
                tool="test",
                detail="test",
                snippet=snippet
            )
            assert "REDACTED" in evidence.snippet, f"Failed to redact: {snippet}"
            assert secret not in evidence.snippet, f"Secret leaked: {secret} in {evidence.snippet}"

    def test_evidence_signal_redaction_base64(self):
        """Test redaction of base64-encoded secrets."""
        # Long base64 strings should be redacted
        b64_secret = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldCBrZXk="
        evidence = EvidenceSignal(tool="test", detail="test", snippet=f"key={b64_secret}")
        assert "REDACTED" in evidence.snippet or "REDACTED_BASE64" in evidence.snippet

    def test_crypto_asset_creation(self):
        asset = CryptoAsset(
            asset_id="ast:abcdef1234567890",
            canonical="AES-256-GCM",
            usage_state=UsageState.CONFIRMED,
            confidence=0.9,
            evidence=[EvidenceSignal(tool="test", detail="found AES-GCM")],
        )
        assert asset.asset_id == "ast:abcdef1234567890"
        assert asset.canonical == "AES-256-GCM"
        assert asset.usage_state == UsageState.CONFIRMED

    def test_crypto_operation_creation(self):
        op = CryptoOperation(
            operation_id="op:abcdef1234567890",
            operation_type=OperationType.ENCRYPT,
            asset_id="ast:abcdef1234567890",
            confidence=0.9,
            evidence=[EvidenceSignal(tool="test", detail="encrypt call")],
        )
        assert op.operation_type == OperationType.ENCRYPT

    def test_cir_document_stats_update(self):
        asset = CryptoAsset(
            asset_id="ast:abcdef1234567890",
            canonical="AES-256-GCM",
            usage_state=UsageState.CONFIRMED,
            confidence=0.9,
            evidence=[],
        )
        op = CryptoOperation(
            operation_id="op:abcdef1234567890",
            operation_type=OperationType.ENCRYPT,
            asset_id="ast:abcdef1234567890",
            confidence=0.9,
            evidence=[],
        )
        cir = CIRDocument(
            scan_id="scan:abcdef1234567890",
            target="test",
            started_at="2024-01-01T00:00:00Z",
            finished_at="2024-01-01T00:00:00Z",
            registry_version="2026.09.11",
            assets=[asset],
            operations=[op],
        )
        assert cir.stats.asset_count == 1
        assert cir.stats.operation_count == 1

    def test_new_asset_id_deterministic(self):
        id1 = new_asset_id("AES-256-GCM", 256, "GCM")
        id2 = new_asset_id("AES-256-GCM", 256, "GCM")
        assert id1 == id2
        assert id1.startswith("ast:")

    def test_new_operation_id_deterministic(self):
        from ecdat.core.cir_models import Location
        id1 = new_operation_id(OperationType.ENCRYPT, "ast:abcdef1234567890", "my_func", Location(file="test.py", line=10))
        id2 = new_operation_id(OperationType.ENCRYPT, "ast:abcdef1234567890", "my_func", Location(file="test.py", line=10))
        assert id1 == id2
        assert id1.startswith("op:")


class TestSignatureRegistry:
    def test_load_registry(self):
        reg = load_registry()
        assert "version" in reg
        assert "algorithms" in reg

    def test_get_registry_version(self):
        version = get_registry_version()
        assert version == "2026.09.11"

    def test_normalize_algorithm(self):
        canonical, original = normalize_algorithm("AES-GCM")
        assert canonical == "AES-256-GCM"

        canonical, original = normalize_algorithm("SHA256")
        assert canonical == "SHA-256"

        canonical, original = normalize_algorithm("UnknownAlgo")
        assert canonical == "UnknownAlgo"

    def test_get_category(self):
        assert get_category("RSA") == "asymmetric"
        assert get_category("AES-256-GCM") == "symmetric"
        assert get_category("SHA-256") == "hash"
        assert get_category("PBKDF2") == "kdf"
        assert get_category("TLS1.2") == "protocol"
        assert get_category("OpenSSL") == "library"
        assert get_category("ML-KEM") == "pqc_kem"

    def test_infer_usage_state(self):
        assert infer_usage_state("library", False, False) == UsageState.PROVIDED_ONLY
        assert infer_usage_state("asymmetric", True, False) == UsageState.CONFIRMED
        assert infer_usage_state("asymmetric", False, True) == UsageState.PROBABLE
        assert infer_usage_state("asymmetric", False, False) == UsageState.POSSIBLE

    def test_infer_operation_type(self):
        assert infer_operation_type("asymmetric", "rsa encrypt") == OperationType.ENCRYPT
        assert infer_operation_type("asymmetric", "rsa sign") == OperationType.SIGN
        assert infer_operation_type("symmetric", "aes encrypt") == OperationType.ENCRYPT
        assert infer_operation_type("hash", "sha256 hash") == OperationType.HASH
        assert infer_operation_type("kdf", "pbkdf2 derive") == OperationType.KDF
        assert infer_operation_type("protocol", "tls handshake") == OperationType.TLS
        assert infer_operation_type("key_exchange", "ecdh") == OperationType.KEY_EXCHANGE


class TestCIRSchemaValidation:
    def test_cir_schema_loads(self):
        schema_path = Path(__file__).parent.parent / "core" / "cir.schema.json"
        with open(schema_path) as f:
            schema = json.load(f)
        assert schema["$id"] == "https://ecdat.local/schemas/cir/v0.1/cir.schema.json"
        assert "CryptoAsset" in schema["$defs"]
        assert "CryptoOperation" in schema["$defs"]


class TestCIRValidation:
    def test_validate_cir_json(self, tmp_path):
        asset = CryptoAsset(
            asset_id="ast:abcdef1234567890",
            canonical="AES-256-GCM",
            usage_state=UsageState.CONFIRMED,
            confidence=0.9,
            evidence=[EvidenceSignal(tool="test", detail="test")],
        )
        cir = CIRDocument(
            scan_id="scan:abcdef1234567890",
            target="test",
            started_at="2024-01-01T00:00:00Z",
            finished_at="2024-01-01T00:00:00Z",
            registry_version="2026.09.11",
            assets=[asset],
        )

        cir_file = tmp_path / "test_cir.json"
        cir_file.write_text(cir.model_dump_json(indent=2))

        validated = validate_cir_json(cir_file)
        assert validated.scan_id == cir.scan_id
        assert len(validated.assets) == 1

    def test_load_cir_json(self, tmp_path):
        cir_file = tmp_path / "test_cir.json"
        cir_data = {
            "cir_version": "0.1",
            "scan_id": "scan:abcdef1234567890",
            "target": "test",
            "started_at": "2024-01-01T00:00:00Z",
            "finished_at": "2024-01-01T00:00:00Z",
            "tool_versions": {},
            "registry_version": "2026.09.11",
            "assets": [],
            "operations": [],
            "graph": {"nodes": [], "edges": []},
            "stats": {"asset_count": 0, "operation_count": 0, "node_count": 0, "edge_count": 0},
        }
        cir_file.write_text(json.dumps(cir_data))

        cir = load_cir_json(cir_file)
        assert cir.cir_version == "0.1"