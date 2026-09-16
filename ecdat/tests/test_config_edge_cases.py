"""Edge case tests for ConfigScanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from ecdat.scanners.config import ConfigScanner
from ecdat.core.cir_models import UsageState


class TestConfigScannerEdgeCases:
    @pytest.fixture
    def config_scanner(self):
        return ConfigScanner()

    @pytest.fixture
    def fixtures_dir(self):
        return Path(__file__).parent / "fixtures" / "config"

    def test_missing_config_file(self, config_scanner):
        findings = config_scanner.scan("/nonexistent/path/nginx.conf")
        assert findings == []

    def test_empty_config(self, config_scanner, tmp_path):
        empty = tmp_path / "nginx.conf"
        empty.write_text("")
        findings = config_scanner.scan(empty)
        assert findings == []

    def test_malformed_yaml(self, config_scanner, tmp_path):
        bad_yaml = tmp_path / "config.yaml"
        bad_yaml.write_text("invalid: [unclosed bracket")
        findings = config_scanner.scan(bad_yaml)
        assert isinstance(findings, list)

    def test_nginx_invalid_cipher(self, config_scanner, tmp_path):
        # Invalid cipher suite should not crash
        config = tmp_path / "nginx.conf"
        config.write_text("ssl_ciphers INVALID-CIPHER;\n")
        findings = config_scanner.scan(config)
        assert isinstance(findings, list)

    def test_apache_malformed(self, config_scanner, tmp_path):
        config = tmp_path / "apache.conf"
        config.write_text("SSLProtocol\nSSLCipherSuite\n")
        findings = config_scanner.scan(config)
        assert isinstance(findings, list)

    def test_envoy_empty_listener(self, config_scanner, tmp_path):
        config = tmp_path / "envoy.yaml"
        config.write_text("static_resources:\n  listeners: []\n")
        findings = config_scanner.scan(config)
        assert isinstance(findings, list)

    def test_openssl_malformed(self, config_scanner, tmp_path):
        config = tmp_path / "openssl.cnf"
        config.write_text("MinProtocol = \nMaxProtocol = \n")
        findings = config_scanner.scan(config)
        assert isinstance(findings, list)

    def test_kubernetes_invalid_secret(self, config_scanner, tmp_path):
        config = tmp_path / "secret.yaml"
        config.write_text("apiVersion: v1\nkind: Secret\nmetadata:\n  name: test\n")
        findings = config_scanner.scan(config)
        assert isinstance(findings, list)

    def test_terraform_malformed(self, config_scanner, tmp_path):
        config = tmp_path / "main.tf"
        config.write_text('resource "aws_alb_listener" "test" {\n  port = 443\n  protocol = "HTTPS"\n')
        findings = config_scanner.scan(config)
        assert isinstance(findings, list)

    def test_generic_config_with_secrets(self, config_scanner, tmp_path):
        config = tmp_path / "app.yaml"
        config.write_text("password: secret123\napi_key: abc123\n")
        findings = config_scanner.scan(config)
        # Should redact secrets in evidence
        for f in findings:
            for e in f.evidence:
                if e.snippet:
                    assert "secret123" not in e.snippet
                    assert "abc123" not in e.snippet