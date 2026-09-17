from __future__ import annotations

import socket
import ssl
import re
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


@dataclass
class TLSResult:
    host: str
    port: int
    version: str
    cipher: str
    cert_chain: list
    sig_algo: str
    key_size: int | None
    curve: str | None
    fingerprint: str = ""
    probed_at: str = ""


class TLSScanner(Scanner[ScannerFinding]):
    name = "runtime-tls"
    version = "0.1.0"

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def can_scan_target(self, target: str) -> bool:
        return ":" in target or target.startswith(("http://", "https://")) or re.match(r"^[a-zA-Z0-9.-]+:\d+$", target)

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return f"tls-prober-{ssl.OPENSSL_VERSION}"

    def scan(self, target: str, **kwargs) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        host, port = self._parse_target(target)
        if not host:
            return findings

        try:
            result = self._probe_tls(host, port)
            if result:
                findings.extend(self._create_findings(result))
        except Exception:
            pass

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _parse_target(self, target: str) -> tuple[str, int] | tuple[None, None]:
        if target.startswith("https://"):
            target = target[8:]
        elif target.startswith("http://"):
            target = target[7:]

        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 443
            return host, port

        return target, 443

    def _probe_tls(self, host: str, port: int) -> TLSResult | None:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert(binary_form=True)
                    cert_chain = ssock.getpeercert_chain() if hasattr(ssock, 'getpeercert_chain') else []

                    sig_algo = ""
                    key_size = None
                    curve = None
                    fingerprint = ""

                    if cert:
                        from cryptography import x509
                        from cryptography.hazmat.primitives import serialization

                        x509_cert = x509.load_der_x509_certificate(cert)
                        sig_algo = x509_cert.signature_algorithm_oid._name
                        key_size = self._get_key_size(x509_cert.public_key())
                        curve = self._get_curve(x509_cert.public_key())
                        try:
                            from ecdat.scanners.certificate.cert_metadata import (
                                sha256_fingerprint_hex)
                            fingerprint = sha256_fingerprint_hex(cert)
                        except Exception:
                            fingerprint = ""

                    from datetime import datetime, timezone
                    return TLSResult(
                        host=host,
                        port=port,
                        version=version,
                        cipher=cipher[0] if cipher else "",
                        cert_chain=cert_chain,
                        sig_algo=sig_algo,
                        key_size=key_size,
                        curve=curve,
                        fingerprint=fingerprint,
                        probed_at=datetime.now(timezone.utc).isoformat(),
                    )
        except ssl.SSLError:
            pass
        except socket.timeout:
            pass
        except ConnectionRefusedError:
            pass
        except Exception:
            pass

        return None

    def _runtime_notes(self, result: TLSResult, extra: str = "") -> str:
        """Graph-linkable runtime provenance (Phase 7).

        Endpoint identity, tool/version, timestamp, and the leaf-cert
        fingerprint that links this probe to static cert/config evidence.
        """
        notes = (f"endpoint={result.host}:{result.port}; "
                 f"tool={self.get_tool_version()}; "
                 f"probed_at={result.probed_at}")
        if result.fingerprint:
            notes += f"; fingerprint={result.fingerprint}"
        if extra:
            notes += f"; {extra}"
        return notes

    def _create_findings(self, result: TLSResult) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        version_map = {
            "TLSv1.3": "TLS1.3",
            "TLSv1.2": "TLS1.2",
            "TLSv1.1": "TLS1.2",
            "TLSv1": "TLS1.2",
            "SSLv2": "SSL",
            "SSLv3": "SSL",
        }

        canonical_version = version_map.get(result.version, "TLS")
        findings.append(ScannerFinding(
            canonical=canonical_version,
            original=result.version,
            usage_state=UsageState.CONFIRMED,
            confidence=0.95,
            evidence=[create_evidence_signal(
                tool="runtime-tls",
                detail=f"Negotiated TLS version: {result.version}",
                confidence=0.95,
                snippet=f"{result.host}:{result.port} - {result.version}",
            )],
            location=Location(uri=f"tls://{result.host}:{result.port}"),
            implementation=Implementation(library="OpenSSL", provider="runtime-tls", api="TLS handshake"),
            context=Context(exposure=Exposure.INTERNET_FACING,
                            notes=self._runtime_notes(
                                result, f"protocol={result.version}")),
        ))

        if result.cipher:
            cipher = result.cipher
            canonical_cipher, original_cipher = self._parse_cipher(cipher)
            if canonical_cipher:
                is_insecure = self._is_insecure_cipher(cipher)

                if is_library_only(canonical_cipher) or get_category(canonical_cipher) == "library":
                    usage_state = UsageState.PROVIDED_ONLY
                    confidence = 0.5
                elif is_insecure:
                    usage_state = UsageState.CONFIRMED
                    confidence = 0.9
                else:
                    usage_state = UsageState.CONFIRMED
                    confidence = 0.9

                findings.append(ScannerFinding(
                    canonical=canonical_cipher,
                    original=original_cipher,
                    usage_state=usage_state,
                    confidence=confidence,
                    evidence=[create_evidence_signal(
                        tool="runtime-tls",
                        detail=f"Negotiated cipher: {cipher}",
                        confidence=confidence,
                        snippet=f"{result.host}:{result.port} - {cipher}",
                    )],
                    location=Location(uri=f"tls://{result.host}:{result.port}"),
                    implementation=Implementation(library="OpenSSL", provider="runtime-tls", api="Cipher negotiation"),
                    context=Context(exposure=Exposure.INTERNET_FACING,
                                    notes=self._runtime_notes(
                                        result, f"cipher={cipher}")),
                ))

        if result.sig_algo:
            canonical_sig, original_sig = normalize_algorithm(self._map_signature_algorithm(result.sig_algo))
            key_size = result.key_size
            curve = result.curve

            findings.append(ScannerFinding(
                canonical=canonical_sig,
                original=original_sig,
                key_size=key_size,
                curve=curve,
                usage_state=UsageState.CONFIRMED,
                confidence=0.9,
                evidence=[create_evidence_signal(
                    tool="runtime-tls",
                    detail=f"Certificate signature algorithm: {result.sig_algo}, key_size={key_size}, curve={curve}",
                    confidence=0.9,
                    snippet=f"{result.host}:{result.port} - {result.sig_algo}",
                )],
                location=Location(uri=f"tls://{result.host}:{result.port}"),
                implementation=Implementation(library="X.509", provider="runtime-tls", api="Certificate validation"),
                context=Context(exposure=Exposure.INTERNET_FACING,
                                notes=self._runtime_notes(result)),
            ))

        return findings

    def _parse_cipher(self, cipher: str) -> tuple[str, str] | tuple[None, None]:
        cipher_upper = cipher.upper()

        if "CHACHA20-POLY1305" in cipher_upper or "CHACHA20_POLY1305" in cipher_upper:
            return "ChaCha20-Poly1305", cipher
        if "AES-GCM" in cipher_upper or "AES_GCM" in cipher_upper or "AESGCM" in cipher_upper:
            if "256" in cipher_upper:
                return "AES-256-GCM", cipher
            if "128" in cipher_upper:
                return "AES-128-GCM", cipher
            return "AES-256-GCM", cipher
        if "AES-CCM" in cipher_upper or "AES_CCM" in cipher_upper or "AESCCM" in cipher_upper:
            return "AES-CCM", cipher
        if "AES-CBC" in cipher_upper or "AES_CBC" in cipher_upper or "AESCBC" in cipher_upper:
            if "256" in cipher_upper:
                return "AES-256-CBC", cipher
            if "128" in cipher_upper:
                return "AES-128-CBC", cipher
            return "AES-256-CBC", cipher
        if "AES" in cipher_upper:
            return "AES", cipher
        if "CHACHA20" in cipher_upper:
            return "ChaCha20", cipher
        if "3DES" in cipher_upper or "DES-CBC3" in cipher_upper or "DES_EDE3" in cipher_upper:
            return "3DES", cipher
        if "DES" in cipher_upper:
            return "DES", cipher
        if "RC4" in cipher_upper or "ARCFOUR" in cipher_upper:
            return "RC4", cipher
        if "ECDHE_RSA" in cipher_upper:
            return "ECDH", cipher
        if "ECDHE_ECDSA" in cipher_upper:
            return "ECDSA", cipher
        if "DHE_RSA" in cipher_upper:
            return "DH", cipher
        if "RSA" in cipher_upper and "ECDHE" not in cipher_upper and "DHE" not in cipher_upper:
            return "RSA", cipher
        if "ECDSA" in cipher_upper:
            return "ECDSA", cipher

        return None, None

    def _is_insecure_cipher(self, cipher: str) -> bool:
        insecure = ["DES", "3DES", "RC4", "RC2", "MD5", "SHA1", "NULL", "EXPORT", "ANON", "AECDH", "ADH"]
        cipher_upper = cipher.upper()
        return any(insec in cipher_upper for insec in insecure)

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

    def _get_curve(self, public_key) -> str | None:
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, x25519, x448

        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return public_key.curve.name
        return None