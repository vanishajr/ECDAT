"""Edge case tests for CertificateScanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from ecdat.scanners.certificate import CertificateScanner
from ecdat.core.cir_models import UsageState


class TestCertificateScannerEdgeCases:
    @pytest.fixture
    def cert_scanner(self):
        return CertificateScanner()

    @pytest.fixture
    def fixtures_dir(self):
        return Path(__file__).parent / "fixtures" / "certificate"

    def test_missing_cert_file(self, cert_scanner):
        findings = cert_scanner.scan("/nonexistent/path/cert.pem")
        assert findings == []

    def test_expired_certificate(self, cert_scanner, fixtures_dir):
        findings = cert_scanner.scan(fixtures_dir / "test_cert.pem")
        assert len(findings) > 0

    def test_private_key_redaction(self, cert_scanner, fixtures_dir):
        """Private keys should be redacted in evidence snippets."""
        findings = cert_scanner.scan(fixtures_dir / "rsa_key.pem")
        for f in findings:
            for e in f.evidence:
                if e.snippet:
                    # Private key should be redacted
                    assert "[REDACTED]" in e.snippet or "PRIVATE KEY" not in e.snippet.upper()

    def test_certificate_evidence_redaction(self, cert_scanner, fixtures_dir):
        """Certificate evidence should not contain raw private key material."""
        findings = cert_scanner.scan(fixtures_dir / "rsa_key.pem")
        for f in findings:
            for e in f.evidence:
                if e.snippet:
                    # Header may be present but key material should be redacted
                    assert "[REDACTED]" in e.snippet

    def test_der_certificate(self, cert_scanner, fixtures_dir):
        findings = cert_scanner.scan(fixtures_dir / "test_cert.der")
        assert len(findings) > 0
        for f in findings:
            assert f.canonical == "X.509"
            assert f.usage_state == UsageState.CONFIRMED

    def test_ec_key(self, cert_scanner, fixtures_dir):
        findings = cert_scanner.scan(fixtures_dir / "ec_key.pem")
        ec_findings = [f for f in findings if "ECDSA" in f.canonical]
        assert len(ec_findings) > 0

    def test_ed25519_key(self, cert_scanner, fixtures_dir):
        findings = cert_scanner.scan(fixtures_dir / "ed25519_key.pem")
        ed_findings = [f for f in findings if f.canonical == "Ed25519"]
        assert len(ed_findings) > 0

    def test_public_key_redaction(self, cert_scanner, fixtures_dir):
        """Public keys should be handled safely."""
        findings = cert_scanner.scan(fixtures_dir / "rsa_pubkey.pem")
        for f in findings:
            for e in f.evidence:
                if e.snippet:
                    # Should not expose full key material
                    assert len(e.snippet) < 500