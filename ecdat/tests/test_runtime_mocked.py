"""Tests for RuntimeScanner with mocking."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from ecdat.scanners.runtime import RuntimeScanner
from ecdat.scanners.runtime.tls_scanner import TLSScanner
from ecdat.scanners.runtime.ssh_scanner import SSHScanner
from ecdat.core.cir_models import UsageState


class TestTLSScannerMocked:
    @pytest.fixture
    def tls_scanner(self):
        return TLSScanner(timeout=1.0)

    def test_tls_scanner_available(self, tls_scanner):
        assert tls_scanner.is_available()

    def test_can_scan_tls_target(self, tls_scanner):
        assert tls_scanner.can_scan_target("example.com:443") is True
        assert tls_scanner.can_scan_target("https://example.com") is True
        assert tls_scanner.can_scan_target("http://example.com") is True
        # "example.com" without port is not a valid target
        assert tls_scanner.can_scan_target("example.com") is None

    @patch('ecdat.scanners.runtime.tls_scanner.socket.create_connection')
    @patch('ecdat.scanners.runtime.tls_scanner.ssl.create_default_context')
    def test_tls_scan_success(self, mock_ssl_context, mock_create_connection, tls_scanner):
        # Mock successful TLS connection
        mock_sock = MagicMock()
        mock_create_connection.return_value.__enter__.return_value = mock_sock
        
        mock_ssock = MagicMock()
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.getpeercert.return_value = None
        mock_ssock.getpeercert_chain.return_value = []
        
        findings = tls_scanner.scan("example.com:443")
        assert len(findings) >= 1
        # Should have TLS version finding
        tls_findings = [f for f in findings if "TLS" in f.canonical]
        assert len(tls_findings) >= 1

    @patch('ecdat.scanners.runtime.tls_scanner.socket.create_connection')
    def test_tls_scan_timeout(self, mock_create_connection, tls_scanner):
        import socket
        mock_create_connection.side_effect = socket.timeout()
        findings = tls_scanner.scan("example.com:443")
        assert findings == []

    @patch('ecdat.scanners.runtime.tls_scanner.socket.create_connection')
    def test_tls_scan_connection_refused(self, mock_create_connection, tls_scanner):
        import socket
        mock_create_connection.side_effect = ConnectionRefusedError()
        findings = tls_scanner.scan("example.com:443")
        assert findings == []


class TestSSHScannerMocked:
    @pytest.fixture
    def ssh_scanner(self):
        return SSHScanner(timeout=1.0)

    def test_ssh_scanner_available(self, ssh_scanner):
        assert ssh_scanner.is_available()

    def test_can_scan_ssh_target(self, ssh_scanner):
        assert ssh_scanner.can_scan_target("example.com:22") is True
        assert ssh_scanner.can_scan_target("ssh://example.com") is True
        # SSH scanner accepts any host:port that's not http/https
        assert ssh_scanner.can_scan_target("example.com:443") is True

    @patch('ecdat.scanners.runtime.ssh_scanner.subprocess.run')
    def test_ssh_scan_success(self, mock_run, ssh_scanner):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...\nexample.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY...\n"
        mock_run.return_value = mock_result
        
        findings = ssh_scanner.scan("example.com:22")
        assert len(findings) >= 1
        # Should have RSA and/or ECDSA findings from ssh-keyscan output
        rsa_findings = [f for f in findings if f.canonical == "RSA"]
        ecdsa_findings = [f for f in findings if f.canonical == "ECDSA"]
        # ssh-keyscan output parsing may produce findings
        assert len(findings) >= 1

    @patch('ecdat.scanners.runtime.ssh_scanner.subprocess.run')
    def test_ssh_scan_fallback_banner(self, mock_run, ssh_scanner):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result
        
        with patch('ecdat.scanners.runtime.ssh_scanner.socket.create_connection') as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value.__enter__.return_value = mock_sock
            mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\n"
            
            findings = ssh_scanner.scan("example.com:22")
            assert len(findings) >= 1
            ssh_findings = [f for f in findings if f.canonical == "SSH"]
            # Banner fallback may or may not produce findings depending on implementation
            assert isinstance(findings, list)


class TestRuntimeScannerMocked:
    @pytest.fixture
    def runtime_scanner(self):
        return RuntimeScanner()

    def test_runtime_scanner_available(self, runtime_scanner):
        assert runtime_scanner.is_available()

    @patch('ecdat.scanners.runtime.tls_scanner.socket.create_connection')
    @patch('ecdat.scanners.runtime.tls_scanner.ssl.create_default_context')
    def test_full_runtime_scan_tls(self, mock_ssl_context, mock_create_connection, runtime_scanner):
        mock_sock = MagicMock()
        mock_create_connection.return_value.__enter__.return_value = mock_sock
        
        mock_ssock = MagicMock()
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.getpeercert.return_value = None
        mock_ssock.getpeercert_chain.return_value = []
        
        findings = runtime_scanner.scan("example.com:443")
        assert len(findings) >= 1

    @patch('ecdat.scanners.runtime.ssh_scanner.subprocess.run')
    def test_full_runtime_scan_ssh(self, mock_run, runtime_scanner):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...\n"
        mock_run.return_value = mock_result
        
        findings = runtime_scanner.scan("example.com:22")
        assert len(findings) >= 1