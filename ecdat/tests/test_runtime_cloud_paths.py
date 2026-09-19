"""Phase 7 runtime/cloud regression: real probes, honest capability, opt-in.

Localhost TLS server (generated cert) proves the stdlib runtime path
records endpoint/protocol/cipher/chain-metadata/exposure/timestamp/
tool-version evidence; SSH shape is asserted without network; cloud
tests prove opt-in gating, loud credential errors, AWS mapping depth,
and Azure/GCP honesty. No external network is ever touched.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ecdat.scanners.runtime import RuntimeScanner
from ecdat.scanners.runtime.tls_scanner import TLSScanner
from ecdat.scanners.runtime.ssh_scanner import SSHScanner


def _serve_tls(cert_path: Path, key_path: Path) -> tuple[str, int, threading.Thread]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(10)
    host, port = server.getsockname()

    def _once() -> None:
        try:
            conn, _ = server.accept()
            try:
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(64)
            except Exception:
                pass
        except Exception:
            pass
        finally:
            server.close()

    thread = threading.Thread(target=_once, daemon=True)
    thread.start()
    return host, port, thread


@pytest.fixture()
def tls_endpoint(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "phase7.test")]))
            .issuer_name(x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "phase7.test")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256()))
    key_path = tmp_path / "server.key"
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    cert_path = tmp_path / "server.crt"
    der = cert.public_bytes(serialization.Encoding.DER)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    host, port, thread = _serve_tls(cert_path, key_path)
    fingerprint = "SHA256:" + ":".join(
        f"{b:02X}" for b in hashlib.sha256(der).digest())
    yield {"host": host, "port": port, "thread": thread,
           "fingerprint": fingerprint}
    thread.join(timeout=10)


def test_tls_probe_records_full_evidence(tls_endpoint):
    target = f"{tls_endpoint['host']}:{tls_endpoint['port']}"
    findings = TLSScanner(timeout=10.0).scan(target)
    assert findings, "localhost TLS probe must yield evidence"
    version = next(f for f in findings if f.original in
                   ("TLSv1.3", "TLSv1.2", "TLSv1", "TLSv1.1"))
    assert version.usage_state.value == "Confirmed"
    assert version.confidence >= 0.9
    notes = " ".join((f.context.notes or "") if f.context else ""
                     for f in findings)
    assert f"endpoint={target}" in notes
    assert "probed_at=" in notes
    assert "tool=" in notes
    assert f"fingerprint={tls_endpoint['fingerprint']}" in notes
    assert any(str(f.location.uri or "").startswith("tls://")
               for f in findings)


def test_tls_closed_port_is_clean():
    assert TLSScanner(timeout=2.0).scan("127.0.0.1:1") == []


def test_ssh_closed_port_is_clean():
    assert SSHScanner(timeout=2.0).scan("127.0.0.1:1") == []


def test_ssh_finding_shape_without_network():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    blob = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    wire = base64.b64encode(blob).decode()
    scanner = SSHScanner(timeout=1.0)
    findings = scanner._create_findings({
        "banner": "SSH-2.0-OpenSSH_9.0",
        "keys": [{"host": "h", "key_type": "ssh-rsa", "key_data": wire}],
        "host": "h", "port": 22})
    assert len(findings) == 2
    host_key = next(f for f in findings if f.canonical == "RSA")
    notes = host_key.context.notes or ""
    assert "endpoint=h:22" in notes and "probed_at=" in notes
    assert "fingerprint=SHA256:" in notes
    expected = "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()).decode().rstrip("=")
    assert expected in notes


def test_runtime_requires_explicit_selection():
    from ecdat.adapters import scanner_policy as policy
    assert "runtime" not in policy.resolve_scanners(None)
    from ecdat.core.orchestrator import ScanRequest, get_orchestrator
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "a.py").write_text("x = 1\n")
        plan = get_orchestrator().plan(ScanRequest(target=tmp))
    assert "runtime" not in plan.scanners
    assert "cloud" not in plan.scanners


def test_external_runtime_tools_reported():
    from ecdat.scanners.runtime import scanner as runtime_mod
    status = getattr(runtime_mod, "external_tool_status", lambda: {})()
    assert set(status) >= {"sslyze", "testssl"}
    assert all(v in ("available", "unavailable") for v in status.values())


def test_cloud_requires_explicit_opt_in_and_creds():
    from ecdat.adapters import scanner_policy as policy
    assert "cloud" not in policy.resolve_scanners(None)
    from ecdat.adapters.pipeline import RealScanError
    from ecdat.core.orchestrator import ScanRequest, get_orchestrator
    with pytest.raises(RealScanError) as exc:
        get_orchestrator().scan(ScanRequest(
            target="aws:default:services=kms,acm", scanners=["cloud"],
            caller="phase7-cloud"))
    assert "Traceback" not in str(exc.value)
    message = str(exc.value).lower()
    assert "cloud" in message and (
        "credential" in message or "unavailable" in message
        or "sdk" in message)


def test_aws_mapping_depth_without_network():
    from ecdat.scanners.cloud.aws_scanner import AWSScanner
    scanner = AWSScanner.__new__(AWSScanner)
    assert scanner._map_kms_key_spec("RSA_2048") == ("RSA", "RSA-2048")
    assert scanner._map_kms_key_spec("ECC_NIST_P256") == ("ECDSA", "ECDSA-P256")
    assert scanner._get_kms_key_size("RSA_4096") == 4096
    assert scanner._get_acm_key_size("EC_prime256v1") == 256
    assert scanner._get_kms_key_size("NOPE") is None


def test_azure_gcp_honest_narrow():
    from ecdat.scanners.cloud.azure_scanner import AzureScanner
    from ecdat.scanners.cloud.gcp_scanner import GCPScanner
    for scanner in (AzureScanner(), GCPScanner()):
        assert scanner.is_available() is False
        assert scanner.scan("anything") == []
        assert "not-implemented" in scanner.get_tool_version()
