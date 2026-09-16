from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class PKCS12Scanner(Scanner[ScannerFinding]):
    name = "certificate-pkcs12"
    version = "0.1.0"

    def __init__(self) -> None:
        pass

    def can_scan_file(self, path: Path) -> bool:
        return path.suffix.lower() in (".p12", ".pfx")

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return "pkcs12-parser"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        findings: list[ScannerFinding] = []

        if target_path.is_file():
            findings.extend(self._scan_file(target_path, kwargs.get("password", "")))
        else:
            for p12_file in target_path.rglob("*"):
                if p12_file.is_file() and self.can_scan_file(p12_file):
                    findings.extend(self._scan_file(p12_file, kwargs.get("password", "")))

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _scan_file(self, file_path: Path, password: str = "") -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448, x25519, x448

            content = file_path.read_bytes()
            key, cert, additional_certs = serialization.pkcs12.load_key_and_certificates(
                content, password.encode() if password else None
            )

            if key:
                canonical, original, key_size, curve = self._identify_key(key)
                findings.append(ScannerFinding(
                    canonical=canonical,
                    original=original,
                    key_size=key_size,
                    curve=curve,
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=0.9,
                    evidence=[create_evidence_signal(
                        tool="certificate-pkcs12",
                        detail=f"PKCS#12 private key: {original}, size={key_size}, curve={curve}",
                        confidence=0.9,
                        snippet="PKCS#12 private key [REDACTED]",
                    )],
                    location=Location(file=str(file_path)),
                    implementation=Implementation(library="PKCS#12", provider="cryptography"),
                    context=Context(exposure=Exposure.INTERNAL),
                ))

            if cert:
                findings.extend(self._parse_certificate(cert, file_path))

            for add_cert in additional_certs or []:
                findings.extend(self._parse_certificate(add_cert, file_path))

        except Exception as e:
            try:
                import subprocess
                for pw in [password, "", "changeit", "changeme", "password", "secret"]:
                    if pw == password:
                        continue
                    result = subprocess.run(
                        ["openssl", "pkcs12", "-in", str(file_path), "-nodes", "-passin", f"pass:{pw}"],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    if result.returncode == 0 and "-----BEGIN" in result.stdout:
                        findings.extend(self._parse_openssl_output(result.stdout, file_path))
                        break
            except Exception:
                pass

        return findings

    def _parse_certificate(self, cert, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        canonical = "X.509"
        sig_algo = cert.signature_algorithm_oid._name
        canonical, original = normalize_algorithm(self._map_signature_algorithm(sig_algo))
        key_size = self._get_key_size(cert.public_key())

        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        not_before = cert.not_valid_before_utc.isoformat() if cert.not_valid_before_utc else "unknown"
        not_after = cert.not_valid_after_utc.isoformat() if cert.not_valid_after_utc else "unknown"
        serial = format(cert.serial_number, "x")

        findings.append(ScannerFinding(
            canonical=canonical,
            original=original,
            key_size=key_size,
            usage_state=UsageState.PROVIDED_ONLY,
            confidence=0.8,
            evidence=[create_evidence_signal(
                tool="certificate-pkcs12",
                detail=f"PKCS#12 Certificate: subject={subject}, issuer={issuer}, serial={serial}, valid={not_before} to {not_after}, sig_algo={sig_algo}",
                confidence=0.8,
                snippet=f"Certificate: {subject}",
            )],
            location=Location(file=str(file_path)),
            implementation=Implementation(library="X.509", version="1.0", provider="cryptography", api="PKCS#12"),
            context=Context(exposure=Exposure.INTERNAL),
        ))

        return findings

    def _parse_openssl_output(self, output: str, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        if "-----BEGIN PRIVATE KEY-----" in output or "-----BEGIN RSA PRIVATE KEY-----" in output:
            findings.append(ScannerFinding(
                canonical="Private Key",
                original="PKCS#12 Private Key",
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.8,
                evidence=[create_evidence_signal(
                    tool="certificate-pkcs12",
                    detail="PKCS#12 private key extracted via OpenSSL",
                    confidence=0.8,
                    snippet="Private key [REDACTED]",
                )],
                location=Location(file=str(file_path)),
                implementation=Implementation(library="PKCS#12", provider="openssl"),
                context=Context(exposure=Exposure.INTERNAL),
            ))

        if "-----BEGIN CERTIFICATE-----" in output:
            findings.append(ScannerFinding(
                canonical="X.509",
                original="PKCS#12 Certificate",
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.7,
                evidence=[create_evidence_signal(
                    tool="certificate-pkcs12",
                    detail="PKCS#12 certificate extracted via OpenSSL",
                    confidence=0.7,
                    snippet="Certificate extracted",
                )],
                location=Location(file=str(file_path)),
                implementation=Implementation(library="X.509", provider="openssl"),
                context=Context(exposure=Exposure.INTERNAL),
            ))

        return findings

    def _map_signature_algorithm(self, sig_algo: str) -> str:
        mapping = {
            "RSAWithSHA256": "RSA",
            "RSAWithSHA384": "RSA",
            "RSAWithSHA512": "RSA",
            "RSAWithSHA1": "RSA",
            "ECDSAWithSHA256": "ECDSA",
            "ECDSAWithSHA384": "ECDSA",
            "ECDSAWithSHA512": "ECDSA",
            "ECDSAWithSHA1": "ECDSA",
            "ED25519": "Ed25519",
            "ED448": "Ed448",
            "DSAWithSHA256": "DSA",
        }
        return mapping.get(sig_algo, sig_algo)

    def _get_key_size(self, public_key) -> int | None:
        from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448, x25519, x448

        if isinstance(public_key, rsa.RSAPublicKey):
            return public_key.key_size
        elif isinstance(public_key, dsa.DSAPublicKey):
            return public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return public_key.curve.key_size
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            return 256
        elif isinstance(public_key, ed448.Ed448PublicKey):
            return 448
        elif isinstance(public_key, x25519.X25519PublicKey):
            return 256
        elif isinstance(public_key, x448.X448PublicKey):
            return 448
        return None

    def _identify_key(self, key) -> tuple[str, str, int | None, str | None]:
        from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448, x25519, x448

        if isinstance(key, rsa.RSAPrivateKey):
            return "RSA", "RSA", key.key_size, None
        elif isinstance(key, dsa.DSAPrivateKey):
            return "DSA", "DSA", key.key_size, None
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            curve_name = key.curve.name
            return "ECDSA/ECDH", "ECDSA", key.curve.key_size, curve_name
        elif isinstance(key, ed25519.Ed25519PrivateKey):
            return "Ed25519", "Ed25519", 256, None
        elif isinstance(key, ed448.Ed448PrivateKey):
            return "Ed448", "Ed448", 448, None
        elif isinstance(key, x25519.X25519PrivateKey):
            return "X25519", "X25519", 256, None
        elif isinstance(key, x448.X448PrivateKey):
            return "X448", "X448", 448, None
        return "Private Key", "Unknown", None, None