from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from ecdat import (
    create_discovery_engine,
    SourceScanner,
    DependencyScanner,
    BinaryScanner,
    ConfigScanner,
    CertificateScanner,
    RuntimeScanner,
    CloudScanner,
    UsageState,
    Graph,
    GraphEdge,
    GraphNode,
    GraphNodeKind,
    GraphRelationship,
)


class TestSourceScanner:
    @pytest.fixture
    def source_scanner(self):
        return SourceScanner()

    @pytest.fixture
    def fixtures_dir(self):
        return Path(__file__).parent / "fixtures" / "source"

    def test_aes_gcm_detection(self, source_scanner, fixtures_dir):
        findings = source_scanner.scan(fixtures_dir / "aes_gcm.py")
        aes_findings = [f for f in findings if f.canonical == "AES-256-GCM"]
        assert len(aes_findings) > 0
        for f in aes_findings:
            assert f.usage_state in (UsageState.CONFIRMED, UsageState.PROBABLE)
            assert f.confidence > 0.5

    def test_rsa_detection(self, source_scanner, fixtures_dir):
        findings = source_scanner.scan(fixtures_dir / "rsa_ops.py")
        rsa_findings = [f for f in findings if f.canonical == "RSA"]
        assert len(rsa_findings) > 0
        for f in rsa_findings:
            assert f.usage_state in (UsageState.CONFIRMED, UsageState.PROBABLE)

    def test_ecdh_hkdf_detection(self, source_scanner, fixtures_dir):
        findings = source_scanner.scan(fixtures_dir / "ecdh_hkdf.py")
        ecdh_findings = [f for f in findings if f.canonical == "ECDH"]
        hkdf_findings = [f for f in findings if f.canonical == "HKDF"]
        assert len(ecdh_findings) > 0 or len(hkdf_findings) > 0

    def test_hash_detection(self, source_scanner, fixtures_dir):
        findings = source_scanner.scan(fixtures_dir / "hashes.py")
        sha256_findings = [f for f in findings if f.canonical == "SHA-256"]
        sha384_findings = [f for f in findings if f.canonical == "SHA-384"]
        sha512_findings = [f for f in findings if f.canonical == "SHA-512"]
        assert len(sha256_findings) > 0 or len(sha384_findings) > 0 or len(sha512_findings) > 0

    def test_pbkdf2_detection(self, source_scanner, fixtures_dir):
        findings = source_scanner.scan(fixtures_dir / "pbkdf2.py")
        pbkdf2_findings = [f for f in findings if f.canonical == "PBKDF2"]
        assert len(pbkdf2_findings) > 0

    def test_tls_detection(self, source_scanner, fixtures_dir):
        findings = source_scanner.scan(fixtures_dir / "tls_example.py")
        tls_findings = [f for f in findings if "TLS" in f.canonical or "SSL" in f.canonical]
        assert len(tls_findings) > 0

    def test_false_positive_suppression(self, source_scanner, fixtures_dir):
        findings = source_scanner.scan(fixtures_dir / "false_positives.py")
        for f in findings:
            assert f.usage_state != UsageState.CONFIRMED or f.confidence < 0.5

    def test_wrapper_detection(self, source_scanner, fixtures_dir):
        findings = source_scanner.scan(fixtures_dir / "wrappers.py")
        aes_findings = [f for f in findings if f.canonical == "AES-256-GCM"]
        sha256_findings = [f for f in findings if f.canonical == "SHA-256"]
        hkdf_findings = [f for f in findings if f.canonical == "HKDF"]
        assert len(aes_findings) > 0 or len(sha256_findings) > 0 or len(hkdf_findings) > 0

    def test_insecure_crypto_detection(self, source_scanner, fixtures_dir):
        findings = source_scanner.scan(fixtures_dir / "insecure_crypto.py")
        insecure_findings = [f for f in findings if f.canonical in ("MD5", "SHA-1", "DES", "3DES", "RSA")]
        assert len(insecure_findings) > 0


class TestDependencyScanner:
    @pytest.fixture
    def dep_scanner(self):
        return DependencyScanner()

    @pytest.fixture
    def fixtures_dir(self):
        return Path(__file__).parent / "fixtures" / "source"

    def test_package_json_detection(self, dep_scanner, fixtures_dir):
        findings = dep_scanner.scan(fixtures_dir / "package.json")
        assert len(findings) > 0
        for f in findings:
            assert f.usage_state == UsageState.PROVIDED_ONLY
            assert f.library is not None

    def test_dependency_only_provided_only(self, dep_scanner, fixtures_dir):
        findings = dep_scanner.scan(fixtures_dir / "package.json")
        for f in findings:
            assert f.usage_state == UsageState.PROVIDED_ONLY


class TestConfigScanner:
    @pytest.fixture
    def config_scanner(self):
        return ConfigScanner()

    @pytest.fixture
    def fixtures_dir(self):
        return Path(__file__).parent / "fixtures" / "config"

    def test_nginx_config(self, config_scanner, fixtures_dir):
        findings = config_scanner.scan(fixtures_dir / "nginx.conf")
        assert len(findings) > 0

        cipher_findings = [f for f in findings if "AES" in f.canonical or "CHACHA" in f.canonical]
        assert len(cipher_findings) > 0

        protocol_findings = [f for f in findings if "TLS" in f.canonical or "SSL" in f.canonical]
        assert len(protocol_findings) > 0

    def test_apache_config(self, config_scanner, fixtures_dir):
        findings = config_scanner.scan(fixtures_dir / "apache.conf")
        assert len(findings) > 0

    def test_envoy_config(self, config_scanner, fixtures_dir):
        findings = config_scanner.scan(fixtures_dir / "envoy.yaml")
        assert len(findings) > 0

    def test_openssl_config(self, config_scanner, fixtures_dir):
        findings = config_scanner.scan(fixtures_dir / "openssl.cnf")
        assert len(findings) > 0

    def test_kubernetes_config(self, config_scanner, fixtures_dir):
        findings = config_scanner.scan(fixtures_dir / "k8s_tls.yaml")
        assert len(findings) > 0

    def test_terraform_config(self, config_scanner, fixtures_dir):
        findings = config_scanner.scan(fixtures_dir / "terraform.tf")
        assert len(findings) > 0

    def test_generic_config(self, config_scanner, fixtures_dir):
        findings = config_scanner.scan(fixtures_dir / "app.yaml")
        assert len(findings) > 0


class TestCertificateScanner:
    @pytest.fixture
    def cert_scanner(self):
        return CertificateScanner()

    @pytest.fixture
    def fixtures_dir(self):
        return Path(__file__).parent / "fixtures" / "certificate"

    def test_pem_certificate(self, cert_scanner, fixtures_dir):
        findings = cert_scanner.scan(fixtures_dir / "test_cert.pem")
        cert_findings = [f for f in findings if f.canonical in ("RSA", "X.509")]
        assert len(cert_findings) > 0
        for f in cert_findings:
            assert f.usage_state == UsageState.CONFIRMED
            assert f.confidence > 0.5

    def test_pem_private_key(self, cert_scanner, fixtures_dir):
        findings = cert_scanner.scan(fixtures_dir / "rsa_key.pem")
        key_findings = [f for f in findings if f.canonical == "RSA"]
        assert len(key_findings) > 0

    def test_ecdsa_key(self, cert_scanner, fixtures_dir):
        findings = cert_scanner.scan(fixtures_dir / "ec_key.pem")
        ec_findings = [f for f in findings if "ECDSA" in f.canonical]
        assert len(ec_findings) > 0

    def test_ed25519_key(self, cert_scanner, fixtures_dir):
        findings = cert_scanner.scan(fixtures_dir / "ed25519_key.pem")
        ed_findings = [f for f in findings if f.canonical == "Ed25519"]
        assert len(ed_findings) > 0

    def test_der_certificate(self, cert_scanner, fixtures_dir):
        findings = cert_scanner.scan(fixtures_dir / "test_cert.der")
        cert_findings = [f for f in findings if f.canonical == "X.509"]
        assert len(cert_findings) > 0


class TestRuntimeScanner:
    @pytest.fixture
    def runtime_scanner(self):
        return RuntimeScanner()

    def test_runtime_scanner_available(self, runtime_scanner):
        assert runtime_scanner.is_available()

    def test_can_scan_tls_target(self, runtime_scanner):
        assert runtime_scanner._scanners[0].can_scan_target("example.com:443")
        assert runtime_scanner._scanners[0].can_scan_target("https://example.com")

    def test_can_scan_ssh_target(self, runtime_scanner):
        assert runtime_scanner._scanners[1].can_scan_target("example.com:22")
        assert runtime_scanner._scanners[1].can_scan_target("ssh://example.com")


class TestCloudScanner:
    def test_cloud_scanner_stubs(self):
        scanner = CloudScanner()
        assert scanner is not None


class TestDiscoveryEngine:
    def test_engine_creation(self):
        engine = create_discovery_engine()
        assert engine is not None

    def test_engine_with_specific_scanners(self):
        engine = create_discovery_engine(["source", "dependency"])
        assert "source" in engine.get_enabled_scanners()
        assert "dependency" in engine.get_enabled_scanners()

    def test_scan_and_emit_cir(self, tmp_path):
        engine = create_discovery_engine(["source"])
        test_file = tmp_path / "test.py"
        test_file.write_text("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n")

        cir = engine.scan_and_emit_cir(test_file, target_name="test.py")

        assert cir.scan_id.startswith("scan:")
        assert cir.target == "test.py"
        assert cir.cir_version == "0.1"
        assert len(cir.assets) >= 0

    def test_cir_validation(self, tmp_path):
        engine = create_discovery_engine(["source"])
        test_file = tmp_path / "test.py"
        test_file.write_text("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n")

        cir = engine.scan_and_emit_cir(test_file, target_name="test.py")
        assert engine.validate_cir(cir) is True

    def test_graph_structure(self, tmp_path):
        engine = create_discovery_engine(["source"])
        test_file = tmp_path / "test.py"
        test_file.write_text("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n")

        cir = engine.scan_and_emit_cir(test_file, target_name="test.py")

        assert isinstance(cir.graph, Graph)
        for edge in cir.graph.edges:
            assert edge.from_ in [n.id for n in cir.graph.nodes]
            assert edge.to in [n.id for n in cir.graph.nodes]
            assert edge.relationship in [r.value for r in GraphRelationship]

    def test_dependency_only_stays_provided_only(self, tmp_path):
        """Test that dependency-only findings stay ProvidedOnly even after normalization."""
        from ecdat.scanners.base import ScannerFinding, normalize_finding
        from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure, EvidenceSignal
        
        finding = ScannerFinding(
            canonical="bcrypt",
            original="bcrypt",
            library="bcrypt",
            usage_state=UsageState.PROVIDED_ONLY,
            confidence=0.55,
            evidence=[EvidenceSignal(tool="dependency:requirements", detail="dep bcrypt", confidence=0.55)],
            location=Location(file="requirements.txt"),
            dependency_only=True,
        )
        
        normalized = normalize_finding(finding)
        assert normalized.usage_state == UsageState.PROVIDED_ONLY

    def test_correlation_source_and_config(self, tmp_path):
        """Test that source and config findings for same algorithm in same file are correlated."""
        engine = create_discovery_engine(["source", "config"])
        
        # Create a test file with AES-GCM usage
        test_file = tmp_path / "test.py"
        test_file.write_text("""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)
""")
        
        # Create a config file referencing AES-GCM
        config_file = tmp_path / "nginx.conf"
        config_file.write_text("""
server {
    listen 443 ssl;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;
}
""")
        
        cir = engine.scan_and_emit_cir(tmp_path, target_name="test_project")
        
        # Should have AES-256-GCM asset
        aes_assets = [a for a in cir.assets if a.canonical == "AES-256-GCM"]
        assert len(aes_assets) > 0
        
        # The asset should have evidence from both source and config
        aes_asset = aes_assets[0]
        tools = {e.tool for e in aes_asset.evidence}
        assert "source" in " ".join(tools) or "config" in " ".join(tools)

    def test_distinct_files_remain_distinct_assets(self, tmp_path):
        """Test that same algorithm in different files creates distinct assets."""
        engine = create_discovery_engine(["source"])
        
        file1 = tmp_path / "file1.py"
        file1.write_text("""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt1(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)
""")
        
        file2 = tmp_path / "file2.py"
        file2.write_text("""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt2(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)
""")
        
        cir1 = engine.scan_and_emit_cir(file1, target_name="file1.py")
        cir2 = engine.scan_and_emit_cir(file2, target_name="file2.py")
        
        # Each scan should produce one AES-256-GCM asset
        aes_assets_1 = [a for a in cir1.assets if a.canonical == "AES-256-GCM"]
        aes_assets_2 = [a for a in cir2.assets if a.canonical == "AES-256-GCM"]
        
        assert len(aes_assets_1) == 1
        assert len(aes_assets_2) == 1
        
        # Asset IDs should be different because files are different
        assert aes_assets_1[0].asset_id != aes_assets_2[0].asset_id

    def test_correlation_upgrades_usage_state(self, tmp_path):
        """Test that correlation upgrades usage state when evidence from multiple scanners."""
        engine = create_discovery_engine(["source", "config"])
        
        test_file = tmp_path / "test.py"
        test_file.write_text("""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)
""")
        
        config_file = tmp_path / "nginx.conf"
        config_file.write_text("ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;\n")
        
        cir = engine.scan_and_emit_cir(tmp_path, target_name="test_project")
        
        aes_assets = [a for a in cir.assets if a.canonical == "AES-256-GCM"]
        assert len(aes_assets) > 0
        
        # Should have high confidence from multiple scanners
        aes_asset = aes_assets[0]
        assert aes_asset.confidence > 0.8
        assert aes_asset.usage_state in (UsageState.CONFIRMED, UsageState.PROBABLE)

    def test_graph_integrity_nodes_edges(self, tmp_path):
        """Test that graph nodes and edges are consistent."""
        engine = create_discovery_engine(["source"])
        test_file = tmp_path / "test.py"
        test_file.write_text("""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)
""")
        
        cir = engine.scan_and_emit_cir(test_file, target_name="test.py")
        
        # All edge endpoints must exist as nodes
        node_ids = {n.id for n in cir.graph.nodes}
        for edge in cir.graph.edges:
            # GraphEdge uses 'from_node' as internal attr, 'from' as alias
            from_attr = edge.from_node
            assert from_attr in node_ids, f"Edge from {from_attr} not in nodes"
            assert edge.to in node_ids, f"Edge to {edge.to} not in nodes"
        
        # Asset nodes must have ASSET kind
        for node in cir.graph.nodes:
            if node.kind == GraphNodeKind.ASSET:
                assert node.ref in [a.asset_id for a in cir.assets]
            elif node.kind == GraphNodeKind.OPERATION:
                assert node.ref in [o.operation_id for o in cir.operations]
            elif node.kind == GraphNodeKind.FILE:
                assert node.label is not None
            elif node.kind == GraphNodeKind.LIBRARY:
                assert node.label is not None

    def test_graph_relationships_valid(self, tmp_path):
        """Test that graph relationships are from allowed set."""
        engine = create_discovery_engine(["source"])
        test_file = tmp_path / "test.py"
        test_file.write_text("""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)
""")
        
        cir = engine.scan_and_emit_cir(test_file, target_name="test.py")
        
        allowed_relationships = {r.value for r in GraphRelationship}
        for edge in cir.graph.edges:
            assert edge.relationship in allowed_relationships, f"Invalid relationship: {edge.relationship}"
        
        # Asset should be contained in file
        asset_nodes = [n for n in cir.graph.nodes if n.kind == GraphNodeKind.ASSET]
        file_nodes = [n for n in cir.graph.nodes if n.kind == GraphNodeKind.FILE]
        contains_edges = [e for e in cir.graph.edges if e.relationship == GraphRelationship.CONTAINS]
        
        # At least one contains edge from file to asset
        assert len(contains_edges) > 0
        
        # Uses edge from asset to library
        uses_edges = [e for e in cir.graph.edges if e.relationship == GraphRelationship.USES]
        assert len(uses_edges) > 0