from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, ScannerRegistry, create_evidence_signal
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


def _cert_note(cert: object) -> str | None:
    """Fingerprint join key for graph linkage (never raises, no secrets)."""
    try:
        from ecdat.scanners.certificate.cert_metadata import (
            cert_fingerprint_note)
        note = cert_fingerprint_note(cert)
        return note or None
    except Exception:
        return None


class DERScanner(Scanner[ScannerFinding]):
    name = "certificate-der"
    version = "0.1.0"

    def can_scan_file(self, path: Path) -> bool:
        return path.suffix.lower() in (".der", ".cer", ".crt")

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return "der-parser"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        findings: list[ScannerFinding] = []

        if target_path.is_file():
            findings.extend(self._scan_file(target_path))
        else:
            for der_file in target_path.rglob("*"):
                if der_file.is_file() and self.can_scan_file(der_file):
                    findings.extend(self._scan_file(der_file))

        return findings

    def _scan_file(self, file_path: Path) -> list[ScannerFinding]:
        try:
            content = file_path.read_bytes()
        except Exception:
            return []

        findings: list[ScannerFinding] = []

        # Try to parse as certificate
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization

            cert = x509.load_der_x509_certificate(content)

            canonical = "X.509"
            sig_algo = cert.signature_algorithm_oid._name
            sig_canonical, sig_original = normalize_algorithm(self._map_signature_algorithm(sig_algo))
            key_size = self._get_key_size(cert.public_key())

            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            not_before = cert.not_valid_before_utc.isoformat() if cert.not_valid_before_utc else "unknown"
            not_after = cert.not_valid_after_utc.isoformat() if cert.not_valid_after_utc else "unknown"
            serial = format(cert.serial_number, "x")

            category = get_category(canonical)
            if is_library_only(canonical) or category == "library":
                usage_state = UsageState.PROVIDED_ONLY
                confidence = 0.6
            else:
                usage_state = UsageState.CONFIRMED
                confidence = 0.9

            findings.append(ScannerFinding(
                canonical=canonical,
                original=sig_original,
                key_size=key_size,
                usage_state=usage_state,
                confidence=confidence,
                evidence=[create_evidence_signal(
                    tool="certificate-der",
                    detail=f"X.509 Certificate (DER): subject={subject}, issuer={issuer}, serial={serial}, valid={not_before} to {not_after}, sig_algo={sig_algo}",
                    confidence=confidence,
                    snippet=f"Certificate: {subject}",
                )],
                location=Location(file=str(file_path)),
                implementation=Implementation(library="x509", version="1.0", provider="cryptography", api="DER"),
                context=Context(exposure=Exposure.INTERNAL,
                                notes=_cert_note(cert)),
            ))
            return findings

        except Exception:
            pass

        # Try to parse as private key
        try:
            from cryptography.hazmat.primitives import serialization
            key = serialization.load_der_private_key(content, password=None)
            findings.extend(self._parse_private_key(key, file_path))
            return findings
        except Exception:
            pass

        # Try to parse as public key
        try:
            from cryptography.hazmat.primitives import serialization
            key = serialization.load_der_public_key(content)
            findings.extend(self._parse_public_key(key, file_path))
            return findings
        except Exception:
            pass

        return findings

    def _parse_private_key(self, key, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        canonical, original, key_size, curve = self._identify_private_key(key)

        findings.append(ScannerFinding(
            canonical=canonical,
            original=original,
            key_size=key_size,
            curve=curve,
            usage_state=UsageState.PROVIDED_ONLY,
            confidence=0.9,
            evidence=[create_evidence_signal(
                tool="certificate-der",
                detail=f"Private key found (DER): {original}, size={key_size}, curve={curve}",
                confidence=0.9,
                snippet="DER private key [REDACTED]",
            )],
            location=Location(file=str(file_path)),
            implementation=Implementation(library="private_key", provider="cryptography", api="DER"),
            context=Context(exposure=Exposure.INTERNAL),
        ))
        return findings

    def _parse_public_key(self, key, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        canonical, original, key_size, curve = self._identify_public_key(key)

        findings.append(ScannerFinding(
            canonical=canonical,
            original=original,
            key_size=key_size,
            curve=curve,
            usage_state=UsageState.PROVIDED_ONLY,
            confidence=0.7,
            evidence=[create_evidence_signal(
                tool="certificate-der",
                detail=f"Public key found (DER): {original}, size={key_size}, curve={curve}",
                confidence=0.7,
                snippet="DER public key",
            )],
            location=Location(file=str(file_path)),
            implementation=Implementation(library="public_key", provider="cryptography", api="DER"),
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

    def _identify_private_key(self, key) -> tuple[str, str, int | None, str | None]:
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

    def _identify_public_key(self, key) -> tuple[str, str, int | None, str | None]:
        from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448, x25519, x448

        if isinstance(key, rsa.RSAPublicKey):
            return "RSA", "RSA", key.key_size, None
        elif isinstance(key, dsa.DSAPublicKey):
            return "DSA", "DSA", key.key_size, None
        elif isinstance(key, ec.EllipticCurvePublicKey):
            curve_name = key.curve.name
            return "ECDSA/ECDH", "ECDSA", key.curve.key_size, curve_name
        elif isinstance(key, ed25519.Ed25519PublicKey):
            return "Ed25519", "Ed25519", 256, None
        elif isinstance(key, ed448.Ed448PublicKey):
            return "Ed448", "Ed448", 448, None
        elif isinstance(key, x25519.X25519PublicKey):
            return "X25519", "X25519", 256, None
        elif isinstance(key, x448.X448PublicKey):
            return "X448", "X448", 448, None
        return "Public Key", "Unknown", None, None


ScannerRegistry.register(DERScanner())