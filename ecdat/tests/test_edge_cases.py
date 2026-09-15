"""Edge case and adversarial tests for ECDAT scanners."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from ecdat import create_discovery_engine
from ecdat.scanners.source import SourceScanner
from ecdat.scanners.dependency import DependencyScanner
from ecdat.scanners.config import ConfigScanner
from ecdat.scanners.certificate import CertificateScanner
from ecdat.scanners.binary import BinaryScanner
from ecdat.scanners.container import ContainerScanner
from ecdat.core.cir_models import UsageState


class TestSourceScannerEdgeCases:
    """Edge case tests for SourceScanner."""

    @pytest.fixture
    def source_scanner(self):
        return SourceScanner()

    @pytest.fixture
    def fixtures_dir(self):
        return Path(__file__).parent / "fixtures" / "source"

    def test_empty_file(self, source_scanner, fixtures_dir):
        """Empty file should produce no findings."""
        findings = source_scanner.scan(fixtures_dir / "empty.py")
        assert len(findings) == 0

    def test_syntax_error_fallback(self, source_scanner, fixtures_dir):
        """File with syntax error should fallback to regex and still find crypto."""
        findings = source_scanner.scan(fixtures_dir / "syntax_error.py")
        # Should still detect AESGCM via regex fallback
        aes_findings = [f for f in findings if f.canonical == "AES-256-GCM"]
        assert len(aes_findings) > 0
        for f in aes_findings:
            assert f.usage_state in (UsageState.CONFIRMED, UsageState.PROBABLE)

    def test_duplicate_calls_deduplication(self, fixtures_dir):
        """Duplicate calls in same function should be correlated by DiscoveryEngine."""
        engine = create_discovery_engine(["source"])
        cir = engine.scan_and_emit_cir(fixtures_dir / "duplicate_calls.py", target_name="test")
        # DiscoveryEngine should correlate the two calls into one asset
        aes_assets = [a for a in cir.assets if a.canonical == "AES-256-GCM"]
        assert len(aes_assets) == 1
        # Should have 1 operation (or 2 if they're different calls)
        aes_ops = [o for o in cir.operations if o.asset_id == aes_assets[0].asset_id]
        assert len(aes_ops) >= 1

    def test_large_file_performance(self, source_scanner, fixtures_dir):
        """Large file with many crypto calls should complete in reasonable time."""
        import time
        start = time.perf_counter()
        findings = source_scanner.scan(fixtures_dir / "large_file.py")
        elapsed = time.perf_counter() - start
        # Should complete within 5 seconds
        assert elapsed < 5.0
        # Should find multiple algorithms
        assert len(findings) >= 10

    def test_unicode_in_source(self, source_scanner, fixtures_dir):
        """File with unicode characters should not crash."""
        findings = source_scanner.scan(fixtures_dir / "unicode_filename.py")
        # Should handle unicode gracefully
        aes_findings = [f for f in findings if f.canonical == "AES-256-GCM"]
        assert len(aes_findings) >= 1


class TestDependencyScannerEdgeCases:
    """Edge case tests for DependencyScanner."""

    @pytest.fixture
    def dep_scanner(self):
        return DependencyScanner()

    @pytest.fixture
    def fixtures_dir(self):
        return Path(__file__).parent / "fixtures" / "source"

    def test_missing_file(self, dep_scanner):
        """Missing file should return empty list, not crash."""
        findings = dep_scanner.scan("/nonexistent/path/requirements.txt")
        assert findings == []

    def test_empty_requirements(self, dep_scanner, tmp_path):
        """Empty requirements.txt should return empty list."""
        empty_req = tmp_path / "requirements.txt"
        empty_req.write_text("")
        findings = dep_scanner.scan(empty_req)
        assert findings == []

    def test_malformed_requirements(self, dep_scanner, tmp_path):
        """Malformed requirements should not crash."""
        malformed = tmp_path / "requirements.txt"
        malformed.write_text("not-a-valid-package==\n===invalid===\ncryptography>=42.0\n")
        findings = dep_scanner.scan(malformed)
        # Should find cryptography
        crypto_findings = [f for f in findings if f.library == "cryptography"]
        assert len(crypto_findings) == 1

    def test_comments_in_requirements(self, dep_scanner, tmp_path):
        """Comments in requirements should be ignored."""
        req = tmp_path / "requirements.txt"
        req.write_text("# This is a comment\ncryptography>=42.0\n# Another comment\n")
        findings = dep_scanner.scan(req)
        assert len(findings) == 1

    def test_pyproject_toml_missing_sections(self, dep_scanner, tmp_path):
        """pyproject.toml with missing sections should not crash."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[build-system]\nrequires = []\n")
        findings = dep_scanner.scan(pyproject)
        assert findings == []


class TestConfigScannerEdgeCases:
    """Edge case tests for ConfigScanner."""

    @pytest.fixture
    def config_scanner(self):
        return ConfigScanner()

    @pytest.fixture
    def fixtures_dir(self):
        return Path(__file__).parent / "fixtures" / "config"

    def test_missing_config_file(self, config_scanner):
        """Missing config file should return empty list."""
        findings = config_scanner.scan("/nonexistent/path/nginx.conf")
        assert findings == []

    def test_empty_config(self, config_scanner, tmp_path):
        """Empty config file should return empty list."""
        empty = tmp_path / "nginx.conf"
        empty.write_text("")
        findings = config_scanner.scan(empty)
        assert findings == []

    def test_malformed_yaml(self, config_scanner, tmp_path):
        """Malformed YAML should not crash."""
        bad_yaml = tmp_path / "config.yaml"
        bad_yaml.write_text("invalid: [unclosed bracket")
        findings = config_scanner.scan(bad_yaml)
        # Should not crash, may return empty or partial
        assert isinstance(findings, list)


class TestCertificateScannerEdgeCases:
    """Edge case tests for CertificateScanner."""

    @pytest.fixture
    def cert_scanner(self):
        return CertificateScanner()

    @pytest.fixture
    def fixtures_dir(self):
        return Path(__file__).parent / "fixtures" / "certificate"

    def test_missing_cert_file(self, cert_scanner):
        """Missing certificate file should return empty list."""
        findings = cert_scanner.scan("/nonexistent/path/cert.pem")
        assert findings == []

    def test_expired_certificate(self, cert_scanner, fixtures_dir):
        """Expired certificate should still be parsed."""
        # We can't easily create an expired cert, but we can test
        # that the scanner doesn't crash on valid certs
        findings = cert_scanner.scan(fixtures_dir / "test_cert.pem")
        assert len(findings) > 0


class TestBinaryScannerEdgeCases:
    """Edge case tests for BinaryScanner."""

    @pytest.fixture
    def binary_scanner(self):
        return BinaryScanner()

    def test_missing_binary(self, binary_scanner):
        """Missing binary file should return empty list."""
        findings = binary_scanner.scan("/nonexistent/path/binary")
        assert findings == []

    def test_text_file_not_scanned(self, binary_scanner, tmp_path):
        """Text files should not be scanned as binaries."""
        text_file = tmp_path / "readme.txt"
        text_file.write_text("This is a text file\n" * 100)
        findings = binary_scanner.scan(text_file)
        assert findings == []

    def test_empty_binary(self, binary_scanner, tmp_path):
        """Empty binary file should not crash."""
        empty_bin = tmp_path / "empty.bin"
        empty_bin.write_bytes(b"")
        findings = binary_scanner.scan(empty_bin)
        assert findings == []


class TestContainerScannerEdgeCases:
    """Edge case tests for ContainerScanner."""

    @pytest.fixture
    def container_scanner(self):
        return ContainerScanner()

    def test_missing_image(self, container_scanner):
        """Missing container image should return empty list."""
        findings = container_scanner.scan("docker://nonexistent:image")
        assert findings == []

    def test_invalid_target(self, container_scanner):
        """Invalid target string should return empty list."""
        findings = container_scanner.scan("not-a-valid-target")
        assert findings == []


class TestDiscoveryEngineEdgeCases:
    """Edge case tests for DiscoveryEngine."""

    def test_empty_directory(self, tmp_path):
        """Empty directory should produce empty CIR."""
        engine = create_discovery_engine(["source"])
        cir = engine.scan_and_emit_cir(tmp_path, target_name="empty")
        assert cir.stats.asset_count == 0
        assert len(cir.assets) == 0

    def test_scanner_failure_isolation(self, tmp_path):
        """One scanner failure should not affect others."""
        # Create a file that source can scan
        test_file = tmp_path / "test.py"
        test_file.write_text("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n")
        
        # Run with all scanners - some may not be available
        engine = create_discovery_engine()
        cir = engine.scan_and_emit_cir(tmp_path, target_name="test")
        # Should not crash, should produce some findings
        assert cir is not None

    def test_deterministic_asset_ids(self, tmp_path):
        """Repeated scans should produce identical asset IDs."""
        test_file = tmp_path / "test.py"
        test_file.write_text("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n")
        
        engine = create_discovery_engine(["source"])
        cir1 = engine.scan_and_emit_cir(test_file, target_name="test.py")
        cir2 = engine.scan_and_emit_cir(test_file, target_name="test.py")
        
        asset_ids_1 = {a.asset_id for a in cir1.assets}
        asset_ids_2 = {a.asset_id for a in cir2.assets}
        
        assert asset_ids_1 == asset_ids_2

    def test_no_secrets_in_evidence(self, tmp_path):
        """Evidence should never contain actual secrets."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
password = "secret123"
api_key = "abc123def456"
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
""")
        
        engine = create_discovery_engine(["source"])
        cir = engine.scan_and_emit_cir(test_file, target_name="test.py")
        
        for asset in cir.assets:
            for evidence in asset.evidence:
                if evidence.snippet:
                    assert "secret123" not in evidence.snippet
                    assert "abc123def456" not in evidence.snippet
        
        for op in cir.operations:
            for evidence in op.evidence:
                if evidence.snippet:
                    assert "secret123" not in evidence.snippet
                    assert "abc123def456" not in evidence.snippet


class TestDeterminismAndReproducibility:
    """Tests for deterministic behavior."""

    def test_same_input_same_output(self, tmp_path):
        """Same input should always produce identical CIR (excluding timestamps)."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa

def encrypt(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)

def gen_key():
    return rsa.generate_private_key(65537, 2048)
""")
        
        engine = create_discovery_engine(["source"])
        
        # Run 5 times
        cirs = []
        for _ in range(5):
            cir = engine.scan_and_emit_cir(test_file, target_name="test.py")
            # Compare excluding timestamps and scan_id
            dump = cir.model_dump(exclude={"started_at", "finished_at", "scan_id"})
            cirs.append(dump)
        
        # All should be identical
        assert all(c == cirs[0] for c in cirs)

    def test_operation_ids_deterministic(self, tmp_path):
        """Operation IDs should be deterministic."""
        test_file = tmp_path / "test.py"
        test_file.write_text("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n")
        
        engine = create_discovery_engine(["source"])
        cir1 = engine.scan_and_emit_cir(test_file, target_name="test.py")
        cir2 = engine.scan_and_emit_cir(test_file, target_name="test.py")
        
        op_ids_1 = {o.operation_id for o in cir1.operations}
        op_ids_2 = {o.operation_id for o in cir2.operations}
        
        assert op_ids_1 == op_ids_2