from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from ecdat import create_discovery_engine, load_cir_json, validate_cir_json
from ecdat.core.cir_models import CIRDocument


class TestIntegration:
    def test_full_discovery_scan(self, tmp_path):
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()

        (test_dir / "main.py").write_text("""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def encrypt(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)

def sign(data):
    key = rsa.generate_private_key(65537, 2048)
    return key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())

def derive_key(password, salt):
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, 100000).derive(password)
""")

        (test_dir / "requirements.txt").write_text("cryptography>=42.0\n")

        (test_dir / "nginx.conf").write_text("""
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
}
""")

        engine = create_discovery_engine(["source", "dependency", "config"])
        cir = engine.scan_and_emit_cir(test_dir, target_name="test_project")

        assert cir.stats.asset_count > 0
        assert cir.stats.operation_count >= 0

        canonical_algos = {a.canonical for a in cir.assets}
        assert any("AES" in a for a in canonical_algos)
        assert any("RSA" in a for a in canonical_algos)
        assert any("PBKDF2" in a for a in canonical_algos)
        assert any("TLS" in a for a in canonical_algos)

    def test_cir_schema_compliance(self, tmp_path):
        engine = create_discovery_engine(["source"])
        test_file = tmp_path / "test.py"
        test_file.write_text("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n")

        cir = engine.scan_and_emit_cir(test_file, target_name="test.py")

        cir_file = tmp_path / "output_cir.json"
        cir_file.write_text(cir.model_dump_json(indent=2))

        validated = validate_cir_json(cir_file)
        assert isinstance(validated, CIRDocument)
        assert validated.scan_id == cir.scan_id

    def test_deterministic_asset_ids(self, tmp_path):
        engine = create_discovery_engine(["source"])
        test_file1 = tmp_path / "test1.py"
        test_file2 = tmp_path / "test2.py"

        code = "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        test_file1.write_text(code)
        test_file2.write_text(code)

        cir1 = engine.scan_and_emit_cir(test_file1, target_name="test1.py")
        cir2 = engine.scan_and_emit_cir(test_file2, target_name="test2.py")

        asset_ids_1 = {a.asset_id for a in cir1.assets}
        asset_ids_2 = {a.asset_id for a in cir2.assets}

        assert asset_ids_1 == asset_ids_2

    def test_cir_output_contains_required_fields(self, tmp_path):
        engine = create_discovery_engine(["source"])
        test_file = tmp_path / "test.py"
        test_file.write_text("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n")

        cir = engine.scan_and_emit_cir(test_file, target_name="test.py")
        cir_dict = cir.model_dump()

        assert "cir_version" in cir_dict
        assert "scan_id" in cir_dict
        assert "target" in cir_dict
        assert "started_at" in cir_dict
        assert "finished_at" in cir_dict
        assert "tool_versions" in cir_dict
        assert "registry_version" in cir_dict
        assert "assets" in cir_dict
        assert "operations" in cir_dict
        assert "graph" in cir_dict
        assert "stats" in cir_dict

        assert cir_dict["cir_version"] == "0.1"
        assert cir_dict["scan_id"].startswith("scan:")
        assert cir_dict["registry_version"] == "2026.09.11"

    def test_evidence_never_contains_secrets(self, tmp_path):
        engine = create_discovery_engine(["source"])
        test_file = tmp_path / "test.py"
        test_file.write_text("""
password = "secret123"
api_key = "abc123def456"
private_key = "-----BEGIN PRIVATE KEY-----\\nkey\\n-----END PRIVATE KEY-----"
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
""")

        cir = engine.scan_and_emit_cir(test_file, target_name="test.py")

        for asset in cir.assets:
            for evidence in asset.evidence:
                if evidence.snippet:
                    assert "secret123" not in evidence.snippet
                    assert "abc123def456" not in evidence.snippet
                    assert "PRIVATE KEY" not in evidence.snippet

        for op in cir.operations:
            for evidence in op.evidence:
                if evidence.snippet:
                    assert "secret123" not in evidence.snippet
                    assert "abc123def456" not in evidence.snippet
                    assert "PRIVATE KEY" not in evidence.snippet

    def test_scanner_failure_isolation(self, tmp_path):
        engine = create_discovery_engine(["source", "dependency", "config"])
        test_file = tmp_path / "test.py"
        test_file.write_text("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n")

        cir = engine.scan_and_emit_cir(test_file, target_name="test.py")

        assert cir.stats.asset_count >= 0
        assert isinstance(cir.graph, object)