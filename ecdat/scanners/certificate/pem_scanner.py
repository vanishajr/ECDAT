from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class PEMScanner(Scanner[ScannerFinding]):
    name = "certificate-pem"
    version = "0.1.0"

    def __init__(self) -> None:
        # Pattern to match full PEM blocks including headers
        self._pem_pattern = re.compile(
            r"(-----BEGIN\s+[A-Z\s]+-----\n.*?\n-----END\s+[A-Z\s]+-----)",
            re.DOTALL
        )
        # Pattern to extract type from PEM header
        self._pem_type_pattern = re.compile(r"-----BEGIN\s+([A-Z\s]+)-----")

    def can_scan_file(self, path: Path) -> bool:
        suffixes = (".pem", ".crt", ".cer", ".key", ".pem", ".crt", ".cer", ".key")
        return path.suffix.lower() in suffixes or "pem" in path.name.lower() or "crt" in path.name.lower() or "cer" in path.name.lower() or "key" in path.name.lower()

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return "pem-parser"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        findings: list[ScannerFinding] = []

        if target_path.is_file():
            findings.extend(self._scan_file(target_path))
        else:
            for pem_file in target_path.rglob("*"):
                if pem_file.is_file() and self.can_scan_file(pem_file):
                    findings.extend(self._scan_file(pem_file))

        # Certificate scanners handle their own normalization
        return findings

    def _scan_file(self, file_path: Path) -> list[ScannerFinding]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        findings: list[ScannerFinding] = []

        for match in self._pem_pattern.finditer(content):
            full_pem = match.group(1).strip()
            pem_type_match = self._pem_type_pattern.search(full_pem)
            pem_type = pem_type_match.group(1).strip() if pem_type_match else "UNKNOWN"

            if "CERTIFICATE" in pem_type and "REQUEST" not in pem_type:
                findings.extend(self._parse_certificate(full_pem, file_path, pem_type))
            elif "CERTIFICATE REQUEST" in pem_type or "CSR" in pem_type:
                findings.extend(self._parse_csr(full_pem, file_path, pem_type))
            elif "PRIVATE KEY" in pem_type:
                findings.extend(self._parse_private_key(full_pem, file_path, pem_type))
            elif "PUBLIC KEY" in pem_type:
                findings.extend(self._parse_public_key(full_pem, file_path, pem_type))
            elif "PKCS" in pem_type and "PRIVATE" not in pem_type:
                findings.extend(self._parse_pkcs(full_pem, file_path, pem_type))

        return findings

    def _parse_certificate(self, pem_data: str, file_path: Path, pem_type: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization

            cert_bytes = pem_data.encode()
            cert = x509.load_pem_x509_certificate(cert_bytes)

            canonical = "X.509"
            sig_algo = cert.signature_algorithm_oid._name
            sig_canonical, sig_original = normalize_algorithm(self._map_signature_algorithm(sig_algo))
            key_size = self._get_key_size(cert.public_key())

            category = get_category(canonical)
            if is_library_only(canonical) or category == "library":
                usage_state = UsageState.PROVIDED_ONLY
                confidence = 0.6
            else:
                usage_state = UsageState.CONFIRMED
                confidence = 0.9

            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            not_before = cert.not_valid_before_utc.isoformat() if cert.not_valid_before_utc else "unknown"
            not_after = cert.not_valid_after_utc.isoformat() if cert.not_valid_after_utc else "unknown"
            serial = format(cert.serial_number, "x")

            findings.append(ScannerFinding(
                canonical=canonical,
                original=sig_original,
                key_size=key_size,
                usage_state=usage_state,
                confidence=confidence,
                evidence=[create_evidence_signal(
                    tool="certificate-pem",
                    detail=f"X.509 Certificate: subject={subject}, issuer={issuer}, serial={serial}, valid={not_before} to {not_after}, sig_algo={sig_algo}",
                    confidence=confidence,
                    snippet=f"Certificate: {subject}",
                )],
                location=Location(file=str(file_path)),
                implementation=Implementation(library="x509", version="1.0", provider="cryptography", api=f"X.509:{sig_canonical}"),
                context=Context(exposure=Exposure.INTERNAL),
            ))

        except Exception as e:
            findings.append(ScannerFinding(
                canonical="X.509",
                original="CERTIFICATE",
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.5,
                evidence=[create_evidence_signal(
                    tool="certificate-pem",
                    detail=f"PEM Certificate found (parse failed): {pem_type}",
                    confidence=0.5,
                    snippet=f"-----BEGIN {pem_type}-----...",
                )],
                location=Location(file=str(file_path)),
                implementation=Implementation(library="x509", provider="pem"),
                context=Context(exposure=Exposure.INTERNAL),
            ))

        return findings

    def _parse_csr(self, pem_data: str, file_path: Path, pem_type: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization

            csr_bytes = pem_data.encode()
            csr = x509.load_pem_x509_csr(csr_bytes)

            canonical = "X.509 CSR"
            sig_algo = csr.signature_algorithm_oid._name
            canonical, original = normalize_algorithm(self._map_signature_algorithm(sig_algo))
            key_size = self._get_key_size(csr.public_key())

            subject = csr.subject.rfc4514_string()

            findings.append(ScannerFinding(
                canonical=canonical,
                original=original,
                key_size=key_size,
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.7,
                evidence=[create_evidence_signal(
                    tool="certificate-pem",
                    detail=f"CSR: subject={subject}, sig_algo={sig_algo}",
                    confidence=0.7,
                    snippet=f"CSR: {subject}",
                )],
                location=Location(file=str(file_path)),
                implementation=Implementation(library="x509", version="1.0", provider="cryptography", api=pem_type),
                context=Context(exposure=Exposure.INTERNAL),
            ))

        except Exception:
            findings.append(ScannerFinding(
                canonical="X.509 CSR",
                original="CERTIFICATE REQUEST",
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.5,
                evidence=[create_evidence_signal(
                    tool="certificate-pem",
                    detail=f"PEM CSR found (parse failed): {pem_type}",
                    confidence=0.5,
                )],
                location=Location(file=str(file_path)),
                implementation=Implementation(library="x509", provider="pem"),
                context=Context(exposure=Exposure.INTERNAL),
            ))

        return findings

    def _parse_private_key(self, pem_data: str, file_path: Path, pem_type: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448, x25519, x448

            key_bytes = pem_data.encode()
            key = serialization.load_pem_private_key(key_bytes, password=None)

            canonical, original, key_size, curve = self._identify_private_key(key)

            findings.append(ScannerFinding(
                canonical=canonical,
                original=original,
                key_size=key_size,
                curve=curve,
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.9,
                evidence=[create_evidence_signal(
                    tool="certificate-pem",
                    detail=f"Private key found: {original}, size={key_size}, curve={curve}",
                    confidence=0.9,
                    snippet=f"-----BEGIN {pem_type}-----... [REDACTED]",
                )],
                location=Location(file=str(file_path)),
                implementation=Implementation(library="private_key", provider="cryptography", api=pem_type),
                context=Context(exposure=Exposure.INTERNAL),
            ))

        except Exception:
            findings.append(ScannerFinding(
                canonical="Private Key",
                original=pem_type,
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.7,
                evidence=[create_evidence_signal(
                    tool="certificate-pem",
                    detail=f"Private key found (parse failed): {pem_type}",
                    confidence=0.7,
                    snippet=f"-----BEGIN {pem_type}-----... [REDACTED]",
                )],
                location=Location(file=str(file_path)),
                implementation=Implementation(library="private_key", provider="pem"),
                context=Context(exposure=Exposure.INTERNAL),
            ))

        return findings

    def _parse_public_key(self, pem_data: str, file_path: Path, pem_type: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448, x25519, x448

            key_bytes = pem_data.encode()
            key = serialization.load_pem_public_key(key_bytes)

            canonical, original, key_size, curve = self._identify_public_key(key)

            findings.append(ScannerFinding(
                canonical=canonical,
                original=original,
                key_size=key_size,
                curve=curve,
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.7,
                evidence=[create_evidence_signal(
                    tool="certificate-pem",
                    detail=f"Public key found: {original}, size={key_size}, curve={curve}",
                    confidence=0.7,
                    snippet=f"-----BEGIN {pem_type}-----...",
                )],
                location=Location(file=str(file_path)),
                implementation=Implementation(library="public_key", provider="cryptography", api=pem_type),
                context=Context(exposure=Exposure.INTERNAL),
            ))

        except Exception:
            findings.append(ScannerFinding(
                canonical="Public Key",
                original=pem_type,
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.5,
                evidence=[create_evidence_signal(
                    tool="certificate-pem",
                    detail=f"Public key found (parse failed): {pem_type}",
                    confidence=0.5,
                )],
                location=Location(file=str(file_path)),
                implementation=Implementation(library="public_key", provider="pem"),
                context=Context(exposure=Exposure.INTERNAL),
            ))

        return findings

    def _parse_pkcs(self, pem_data: str, file_path: Path, pem_type: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        findings.append(ScannerFinding(
            canonical="PKCS",
            original=pem_type,
            usage_state=UsageState.PROVIDED_ONLY,
            confidence=0.6,
            evidence=[create_evidence_signal(
                tool="certificate-pem",
                detail=f"PKCS structure found: {pem_type}",
                confidence=0.6,
                snippet=f"-----BEGIN {pem_type}-----...",
            )],
            location=Location(file=str(file_path)),
            implementation=Implementation(library="pkcs", provider="pem"),
            context=Context(exposure=Exposure.INTERNAL),
        ))

        return findings

    def _map_signature_algorithm(self, sig_algo: str) -> str:
        mapping = {
            "sha256WithRSAEncryption": "RSA",
            "sha384WithRSAEncryption": "RSA",
            "sha512WithRSAEncryption": "RSA",
            "sha1WithRSAEncryption": "RSA",
            "ecdsa-with-SHA256": "ECDSA",
            "ecdsa-with-SHA384": "ECDSA",
            "ecdsa-with-SHA512": "ECDSA",
            "ecdsa-with-SHA1": "ECDSA",
            "ED25519": "Ed25519",
            "ED448": "Ed448",
            "dsaWithSHA256": "DSA",
            "RSAWithSHA256": "RSA",
            "RSAWithSHA384": "RSA",
            "RSAWithSHA512": "RSA",
            "RSAWithSHA1": "RSA",
            "ECDSAWithSHA256": "ECDSA",
            "ECDSAWithSHA384": "ECDSA",
            "ECDSAWithSHA512": "ECDSA",
            "ECDSAWithSHA1": "ECDSA",
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