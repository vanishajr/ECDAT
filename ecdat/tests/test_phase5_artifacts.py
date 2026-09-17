"""Phase 5 regression: dependencies, configs, certs, Dockerfiles, BOMs.

Native C/C++ manifests, crypto-capability notes, optional Syft/cdxgen
hooks, Dockerfile definition evidence in default scans, graph-linkable
service context, secret-safe certificate metadata, and CycloneDX/SPDX
import as ProvidedOnly inventory evidence.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _dep_files(root: Path) -> None:
    (root / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\n"
        "project(demo)\n"
        "find_package(OpenSSL 3.0 REQUIRED)\n"
        "target_link_libraries(demo PRIVATE ssl crypto sodium)\n")
    (root / "conanfile.txt").write_text(
        "[requires]\nopenssl/3.1.2\nlibsodium/1.0.18\n")
    (root / "vcpkg.json").write_text(
        '{"dependencies": ["openssl", {"name": "libsodium"}]}')
    (root / "meson.build").write_text(
        "project('d', 'c')\ndep = dependency('openssl')\n")
    (root / "configure.ac").write_text(
        "AC_INIT([d], [1.0])\nAC_CHECK_LIB([ssl], [SSL_new])\n"
        "PKG_CHECK_MODULES([CRYPTO], [libcrypto])\n")
    (root / "openssl.pc").write_text("Name: openssl\nVersion: 3.1.2\n")


def _bom_files(root: Path) -> None:
    (root / "bom.json").write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [
            {"type": "library", "name": "openssl", "version": "3.1.2"},
            {"type": "library", "name": "left-pad", "version": "1.0.0"},
            {"type": "library", "name": "custom",
             "cryptoProperties": {"cipher": "AES-256-GCM"}},
        ]}))
    (root / "bom.xml").write_text(
        '<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5">'
        "<components>"
        '<component type="library"><name>libsodium</name>'
        "<version>1.0.18</version></component>"
        "</components></bom>")
    (root / "project.spdx.json").write_text(json.dumps({
        "spdxVersion": "SPDX-2.3",
        "packages": [{"name": "openssl", "versionInfo": "3.1.2"},
                     {"name": "lodash", "versionInfo": "4.0.0"}]}))
    (root / "project.spdx").write_text(
        "SPDXVersion: SPDX-2.3\n"
        "PackageName: openssl\nPackageVersion: 3.1.2\n\n"
        "PackageName: lodash\nPackageVersion: 4.0.0\n")
    (root / "random.json").write_text(json.dumps({"hello": "world"}))


def _docker_files(root: Path) -> None:
    (root / "Dockerfile").write_text(
        "FROM nginx:1.25\n"
        "RUN apt-get update && apt-get install -y openssl ca-certificates \\\n"
        "    && rm -rf /var/lib/apt/lists/*\n"
        "COPY server.crt /etc/nginx/server.crt\n"
        "COPY nginx.conf /etc/nginx/nginx.conf\n"
        "EXPOSE 443\n")
    (root / "nginx.conf").write_text(
        "server {\n    listen 443 ssl;\n"
        "    server_name shop.example.com;\n"
        "    ssl_certificate /etc/nginx/server.crt;\n"
        "    ssl_certificate_key /etc/nginx/server.key;\n"
        "    ssl_protocols TLSv1.2 TLSv1.3;\n"
        "}\n")


def _service_configs(root: Path) -> None:
    (root / "httpd.conf").write_text(
        "<VirtualHost *:443>\n    ServerName shop.example.com\n"
        "    SSLCertificateFile /etc/pki/server.crt\n"
        "    SSLCertificateKeyFile /etc/pki/server.key\n"
        "</VirtualHost>\n")
    (root / "main.tf").write_text(
        'resource "aws_lb_listener" "web" {\n  port = 443\n}\n'
        'resource "aws_kms_key" "data" {\n'
        '  key_id = "alias/app-data"\n}\n'
        'resource "aws_acm_certificate" "web" {\n'
        '  certificate_arn = "arn:aws:acm:us-east-1:123:certificate/abc"\n}\n')
    (root / "k8s-deploy.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\n"
        "metadata:\n  name: web\n---\n"
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: web-svc\n---\n"
        "apiVersion: networking.k8s.io/v1\nkind: Ingress\n"
        "metadata:\n  name: web-ingress\nspec:\n"
        "  tls:\n  - hosts:\n    - shop.example.com\n"
        "    secretName: web-tls\n"
        "  rules:\n  - host: shop.example.com\n")
    (root / ".env").write_text(
        "SERVICE_NAME=billing\nPORT=8443\n"
        "TLS_CERT_PATH=/etc/tls/server.crt\n")


def _make_cert(tmp_path: Path) -> tuple[Path, Path, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "phase5.test")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject)
            .issuer_name(issuer).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256()))
    key_path = tmp_path / "server.key"
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
    key_path.write_text(key_pem)
    cert_path = tmp_path / "server.crt"
    cert_path.write_text(
        cert.public_bytes(serialization.Encoding.PEM).decode())
    return key_path, cert_path, key_pem


def test_package_registry_single_source():
    import ecdat.scanners.dependency.scanner as dep_mod
    import ecdat.scanners.dependency.crypto_packages as pkg_mod
    assert dep_mod.CRYPTO_PACKAGES is pkg_mod.CRYPTO_PACKAGES
    from ecdat.scanners.dependency.crypto_packages import capabilities_for
    assert "RSA" in capabilities_for("openssl")
    assert "AES" in capabilities_for("OpenSSL")
    assert "X25519" in capabilities_for("libsodium")
    assert capabilities_for("left-pad") == ()
    assert capabilities_for("") == ()


def test_native_manifests(tmp_path):
    from ecdat.scanners.dependency import DependencyScanner
    _dep_files(tmp_path)
    findings = DependencyScanner().scan(tmp_path)
    by_tool: dict[str, list] = {}
    for finding in findings:
        by_tool.setdefault(finding.evidence[0].tool, []).append(finding)
    assert by_tool["dependency:cmake"]
    assert by_tool["dependency:conan"]
    assert by_tool["dependency:vcpkg"]
    assert by_tool["dependency:meson"]
    assert by_tool["dependency:autotools"]
    assert by_tool["dependency:pkgconfig"]
    canonicals = {f.canonical for f in findings}
    assert "OpenSSL" in canonicals
    assert "libsodium" in canonicals
    conan_openssl = [f for f in by_tool["dependency:conan"]
                     if f.library == "openssl"][0]
    assert conan_openssl.implementation.version == "3.1.2"
    assert all(f.usage_state.value == "ProvidedOnly" for f in findings)
    assert all(f.dependency_only for f in findings)
    openssl_notes = next(
        f.context.notes for f in findings if f.library == "openssl")
    assert "provides=" in openssl_notes and "RSA" in openssl_notes


def test_dependency_capabilities_do_not_explode(tmp_path):
    from ecdat.scanners.dependency import DependencyScanner
    (tmp_path / "requirements.txt").write_text("openssl==23.0.0\n")
    findings = DependencyScanner().scan(tmp_path)
    assert len(findings) == 1  # one dep, one finding, capabilities in notes
    assert "provides=" in (findings[0].context.notes or "")


def test_external_tools_graceful_without_binaries(tmp_path):
    from ecdat.scanners.dependency import DependencyScanner
    (tmp_path / "requirements.txt").write_text("requests==2.0\n")
    scanner = DependencyScanner()
    scanner.scan(tmp_path)
    stats = scanner.last_stats()
    assert stats["syft"] in ("unavailable",) or \
        stats["syft"].startswith(("available", "failed", "error"))
    assert stats["cdxgen"] in ("unavailable",) or \
        stats["cdxgen"].startswith(("available", "failed", "error"))


def test_bom_import(tmp_path):
    from ecdat.scanners.dependency import DependencyScanner
    _bom_files(tmp_path)
    findings = DependencyScanner().scan(tmp_path / "bom.json")
    tools = {f.evidence[0].tool for f in findings}
    assert tools == {"dependency:bom-cyclonedx"}
    by_lib = {f.library: f for f in findings}
    assert by_lib["openssl"].implementation.version == "3.1.2"
    assert "left-pad" not in by_lib  # unknown components stay silent
    assert by_lib["custom"].canonical == "AES-256-GCM"  # cryptoProperties
    assert all(f.usage_state.value == "ProvidedOnly" for f in findings)
    assert all(f.dependency_only for f in findings)

    xml_findings = DependencyScanner().scan(tmp_path / "bom.xml")
    assert {f.library for f in xml_findings} == {"libsodium"}
    assert xml_findings[0].evidence[0].tool == "dependency:bom-cyclonedx"

    spdx_json = DependencyScanner().scan(tmp_path / "project.spdx.json")
    assert {f.library for f in spdx_json} == {"openssl"}
    spdx_tv = DependencyScanner().scan(tmp_path / "project.spdx")
    assert {f.library for f in spdx_tv} == {"openssl"}
    assert all(f.evidence[0].tool == "dependency:bom-spdx"
               for f in spdx_json + spdx_tv)

    junk = DependencyScanner().scan(tmp_path / "random.json")
    assert junk == []


def test_dockerfile_evidence_in_default_scan(tmp_path):
    from ecdat.scanners.config import ConfigScanner
    _docker_files(tmp_path)
    findings = [f for f in ConfigScanner().scan(tmp_path)
                if f.evidence and f.evidence[0].tool == "config:dockerfile"]
    assert len(findings) >= 4  # base image, installs, cert copy, config copy
    assert all(f.usage_state.value == "ProvidedOnly" for f in findings)
    assert all(f.dependency_only for f in findings)
    assert all("not deployed image" in f.evidence[0].detail
               for f in findings)
    details = " ".join(f.evidence[0].detail for f in findings)
    assert "nginx:1.25" in details and "server.crt" in details
    assert any("exposed-ports=443" in (f.context.notes or "")
               for f in findings)


def test_dockerfile_alone_never_confirmed(tmp_path):
    from ecdat.scanners.config import ConfigScanner
    (tmp_path / "Dockerfile").write_text(
        "FROM openssl:3.2\nRUN openssl version\n")
    findings = ConfigScanner().scan(tmp_path / "Dockerfile")
    assert findings
    assert not any(f.usage_state.value == "Confirmed" for f in findings)
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "Dockerfile").write_text("FROM python:3.12-slim\nRUN pip install x\n")
    assert ConfigScanner().scan(plain) == []  # no crypto, no noise


def test_no_cross_file_note_leak(tmp_path):
    """Regression: per-file notes must not bleed into sibling findings."""
    from ecdat.scanners.config import ConfigScanner
    _docker_files(tmp_path)
    findings = [f for f in ConfigScanner().scan(tmp_path)
                if f.evidence and f.evidence[0].tool == "config:dockerfile"]
    copy_conf = next(f for f in findings
                     if "nginx.conf ->" in f.evidence[0].detail)
    assert "config_ref=nginx.conf" in (copy_conf.context.notes or "")
    assert "server.crt" not in (copy_conf.context.notes or "")


def test_service_context_notes(tmp_path):
    from ecdat.scanners.config import ConfigScanner
    _docker_files(tmp_path)
    _service_configs(tmp_path)
    findings = ConfigScanner().scan(tmp_path)
    by_file: dict[str, list] = {}
    for finding in findings:
        by_file.setdefault(Path(finding.location.file).name, []).append(finding)

    nginx_notes = {f.context.notes or "" for f in by_file["nginx.conf"]}
    assert any("service=shop.example.com" in n for n in nginx_notes)
    assert any("listener=443 ssl" in n for n in nginx_notes)
    assert any("cert_ref=/etc/nginx/server.crt" in n for n in nginx_notes)
    assert any("key_ref=/etc/nginx/server.key" in n for n in nginx_notes)

    apache_notes = {f.context.notes or "" for f in by_file["httpd.conf"]}
    assert any("service=shop.example.com" in n for n in apache_notes)
    assert any("cert_ref=/etc/pki/server.crt" in n for n in apache_notes)

    tf_notes = {f.context.notes or "" for f in by_file["main.tf"]}
    assert any("aws_lb_listener.web" in n for n in tf_notes)
    assert any("arn:aws:acm" in n for n in tf_notes)

    k8s_notes = {f.context.notes or "" for f in by_file["k8s-deploy.yaml"]}
    assert any("service=" in n and "web" in n for n in k8s_notes)
    assert any("cert_ref=web-tls" in n for n in k8s_notes)
    assert any("https://shop.example.com" in n for n in k8s_notes)

    env_notes = {f.context.notes or "" for f in by_file[".env"]}
    assert any("service=billing" in n for n in env_notes)
    assert any("cert_ref=/etc/tls/server.crt" in n for n in env_notes)


def test_cert_metadata_secret_safe_and_linked(tmp_path):
    from ecdat.scanners.certificate import CertificateScanner
    key_path, cert_path, key_pem = _make_cert(tmp_path)
    findings = CertificateScanner().scan(tmp_path)
    assert findings, "expected cert/key findings"
    blob = " ".join(
        (e.snippet or "") + " " + (e.detail or "")
        + " " + ((f.context.notes or "") if f.context else "")
        for f in findings for e in f.evidence)
    key_body = key_pem.strip().splitlines()[1]
    assert key_pem not in blob  # no raw private-key material anywhere
    assert key_body not in blob  # no private key bytes anywhere
    assert "[REDACTED" in blob  # private-key snippets redacted by design
    cert_notes = " ".join((f.context.notes or "") if f.context else ""
                          for f in findings)
    assert "fingerprint=SHA256:" in cert_notes
    key_size = {f.key_size for f in findings if f.key_size}
    assert 2048 in key_size


def test_jwk_private_material_never_stored(tmp_path):
    from ecdat.scanners.certificate import CertificateScanner
    secret_d = "s3cr3t-d-value-abc123"
    (tmp_path / "keys.jwk").write_text(json.dumps({
        "keys": [{"kty": "oct", "k": "c2VjcmV0LWtleQ", "kid": "s1"},
                 {"kty": "RSA", "n": "bm9uY2U", "e": "AQAB",
                  "d": secret_d, "kid": "s2"}]}))
    findings = CertificateScanner().scan(tmp_path)
    blob = " ".join(
        (e.snippet or "") + " " + (e.detail or "")
        + " " + ((f.context.notes or "") if f.context else "")
        for f in findings for e in f.evidence)
    assert secret_d not in blob
    assert "c2VjcmV0LWtleQ" not in blob  # symmetric secret gone too
    assert any("fingerprint=SHA256:" in ((f.context.notes or "")
                                        if f.context else "")
               for f in findings)


def test_config_cert_linkage_keys(tmp_path):
    """The nginx cert path and the on-disk cert share join keys."""
    from ecdat.scanners.config import ConfigScanner
    from ecdat.scanners.certificate import CertificateScanner
    _make_cert(tmp_path)
    (tmp_path / "nginx.conf").write_text(
        "server {\n    listen 443 ssl;\n"
        "    server_name shop.example.com;\n"
        "    ssl_certificate /etc/nginx/server.crt;\n"
        "    ssl_certificate_key /etc/nginx/server.key;\n"
        "}\n")
    (tmp_path / "server.crt").rename(tmp_path / "server.crt")
    config = ConfigScanner().scan(tmp_path / "nginx.conf")
    certs = CertificateScanner().scan(tmp_path / "server.crt")
    assert config and certs
    config_refs = {n for f in config for n in
                   (f.context.notes or "").split("; ")}
    assert any(n == "cert_ref=/etc/nginx/server.crt" for n in config_refs)
    assert Path(certs[0].location.file).name == "server.crt"
    assert "fingerprint=SHA256:" in (certs[0].context.notes or "")
