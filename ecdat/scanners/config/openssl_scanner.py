from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class OpenSSLConfigScanner(Scanner[ScannerFinding]):
    name = "config-openssl"
    version = "0.1.0"

    def __init__(self) -> None:
        self._min_protocol_pattern = re.compile(r"MinProtocol\s*=\s*(\S+)")
        self._max_protocol_pattern = re.compile(r"MaxProtocol\s*=\s*(\S+)")
        self._cipher_suites_pattern = re.compile(r"CipherSuites\s*=\s*([^\n]+)")
        self._ciphers_pattern = re.compile(r"Ciphers\s*=\s*([^\n]+)")
        self._options_pattern = re.compile(r"Options\s*=\s*([^\n]+)")

    def can_scan_file(self, path: Path) -> bool:
        name = path.name.lower()
        return name in ("openssl.cnf", "openssl.conf", "ssl.cnf") or name.endswith(".cnf")

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return "openssl-config-parser"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        findings: list[ScannerFinding] = []

        if target_path.is_file():
            findings.extend(self._scan_file(target_path))
        else:
            for cnf_file in target_path.rglob("*.cnf"):
                if self.can_scan_file(cnf_file):
                    findings.extend(self._scan_file(cnf_file))

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _scan_file(self, file_path: Path) -> list[ScannerFinding]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        findings: list[ScannerFinding] = []
        lines = content.splitlines()

        for i, line in enumerate(lines):
            line_stripped = line.strip()
            if line_stripped.startswith("#") or line_stripped.startswith(";"):
                continue

            min_proto_match = self._min_protocol_pattern.search(line_stripped)
            if min_proto_match:
                findings.append(self._create_protocol_finding(min_proto_match.group(1), file_path, i + 1, "min"))

            max_proto_match = self._max_protocol_pattern.search(line_stripped)
            if max_proto_match:
                findings.append(self._create_protocol_finding(max_proto_match.group(1), file_path, i + 1, "max"))

            cipher_suites_match = self._cipher_suites_pattern.search(line_stripped)
            if cipher_suites_match:
                findings.extend(self._analyze_cipher_suites(cipher_suites_match.group(1), file_path, i + 1))

            ciphers_match = self._ciphers_pattern.search(line_stripped)
            if ciphers_match:
                findings.extend(self._analyze_ciphers(ciphers_match.group(1), file_path, i + 1))

            options_match = self._options_pattern.search(line_stripped)
            if options_match:
                findings.extend(self._analyze_options(options_match.group(1), file_path, i + 1))

        return findings

    def _create_protocol_finding(self, protocol: str, file_path: Path, line: int, limit: str) -> ScannerFinding:
        proto_lower = protocol.lower().replace(".", "_")

        if "tlsv1.3" in proto_lower or "tlsv1_3" in proto_lower:
            canonical = "TLS1.3"
            usage_state = UsageState.CONFIRMED
            confidence = 0.8
        elif "tlsv1.2" in proto_lower or "tlsv1_2" in proto_lower:
            canonical = "TLS1.2"
            usage_state = UsageState.CONFIRMED
            confidence = 0.8
        elif "tlsv1.1" in proto_lower or "tlsv1_1" in proto_lower:
            canonical = "TLS1.2"
            usage_state = UsageState.CONFIRMED
            confidence = 0.7
        elif "tlsv1" in proto_lower:
            canonical = "TLS1.2"
            usage_state = UsageState.CONFIRMED
            confidence = 0.6
        elif "sslv" in proto_lower:
            canonical = "SSL"
            usage_state = UsageState.CONFIRMED
            confidence = 0.9
        else:
            canonical = "TLS"
            usage_state = UsageState.CONFIRMED
            confidence = 0.5

        return ScannerFinding(
            canonical=canonical,
            original=protocol,
            usage_state=usage_state,
            confidence=confidence,
            evidence=[create_evidence_signal(
                tool="config-openssl",
                detail=f"OpenSSL {limit} protocol: {protocol}",
                confidence=confidence,
                snippet=f"{limit.capitalize()}Protocol = {protocol}",
            )],
            location=Location(file=str(file_path), line=line),
            implementation=Implementation(library="openssl", api=f"{limit.capitalize()}Protocol"),
            context=Context(exposure=Exposure.INTERNET_FACING),
        )

    def _analyze_cipher_suites(self, cipher_string: str, file_path: Path, line: int) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        ciphers = [c.strip() for c in cipher_string.split(":") if c.strip()]

        for cipher in ciphers:
            canonical, original = self._parse_tls13_cipher(cipher)
            if canonical:
                is_insecure = self._is_insecure_cipher(cipher)

                if is_library_only(canonical) or get_category(canonical) == "library":
                    usage_state = UsageState.PROVIDED_ONLY
                    confidence = 0.4
                elif is_insecure:
                    usage_state = UsageState.CONFIRMED
                    confidence = 0.9
                else:
                    usage_state = UsageState.CONFIRMED
                    confidence = 0.8

                findings.append(ScannerFinding(
                    canonical=canonical,
                    original=original,
                    usage_state=usage_state,
                    confidence=confidence,
                    evidence=[create_evidence_signal(
                        tool="config-openssl",
                        detail=f"OpenSSL TLS 1.3 cipher suite: {cipher}",
                        confidence=confidence,
                        snippet=f"CipherSuites = {cipher_string[:200]}",
                    )],
                    location=Location(file=str(file_path), line=line),
                    implementation=Implementation(library="openssl", api="CipherSuites"),
                    context=Context(exposure=Exposure.INTERNET_FACING),
                ))

        return findings

    def _analyze_ciphers(self, cipher_string: str, file_path: Path, line: int) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        ciphers = [c.strip() for c in cipher_string.split(":") if c.strip()]

        for cipher in ciphers:
            canonical, original = self._parse_cipher(cipher)
            if canonical:
                is_insecure = self._is_insecure_cipher(cipher)

                if is_library_only(canonical) or get_category(canonical) == "library":
                    usage_state = UsageState.PROVIDED_ONLY
                    confidence = 0.4
                elif is_insecure:
                    usage_state = UsageState.CONFIRMED
                    confidence = 0.9
                else:
                    usage_state = UsageState.CONFIRMED
                    confidence = 0.8

                findings.append(ScannerFinding(
                    canonical=canonical,
                    original=original,
                    usage_state=usage_state,
                    confidence=confidence,
                    evidence=[create_evidence_signal(
                        tool="config-openssl",
                        detail=f"OpenSSL cipher suite: {cipher}",
                        confidence=confidence,
                        snippet=f"Ciphers = {cipher_string[:200]}",
                    )],
                    location=Location(file=str(file_path), line=line),
                    implementation=Implementation(library="openssl", api="Ciphers"),
                    context=Context(exposure=Exposure.INTERNET_FACING),
                ))

        return findings

    def _analyze_options(self, options_string: str, file_path: Path, line: int) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        insecure_options = ["SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION", "SSL_OP_LEGACY_SERVER_CONNECT", "SSL_OP_NO_SSLv2", "SSL_OP_NO_SSLv3"]

        for opt in insecure_options:
            if opt in options_string:
                findings.append(ScannerFinding(
                    canonical="SSL",
                    original=opt,
                    usage_state=UsageState.CONFIRMED,
                    confidence=0.8,
                    evidence=[create_evidence_signal(
                        tool="config-openssl",
                        detail=f"OpenSSL option: {opt}",
                        confidence=0.8,
                        snippet=f"Options = {options_string[:200]}",
                    )],
                    location=Location(file=str(file_path), line=line),
                    implementation=Implementation(library="openssl", api="Options"),
                    context=Context(exposure=Exposure.INTERNET_FACING),
                ))

        return findings

    def _parse_tls13_cipher(self, cipher: str) -> tuple[str, str] | tuple[None, None]:
        cipher_upper = cipher.upper()

        if "CHACHA20-POLY1305" in cipher_upper or "CHACHA20_POLY1305" in cipher_upper:
            return "ChaCha20-Poly1305", cipher
        if "AES_256_GCM" in cipher_upper or "AES-256-GCM" in cipher_upper:
            return "AES-256-GCM", cipher
        if "AES_128_GCM" in cipher_upper or "AES-128-GCM" in cipher_upper:
            return "AES-128-GCM", cipher
        if "AES_256_CCM" in cipher_upper:
            return "AES-CCM", cipher
        if "AES_128_CCM" in cipher_upper:
            return "AES-CCM", cipher

        return None, None

    def _parse_cipher(self, cipher: str) -> tuple[str, str] | tuple[None, None]:
        cipher_upper = cipher.upper()

        # Extract symmetric cipher from full TLS cipher suite strings
        # e.g., ECDHE-RSA-AES256-GCM-SHA384 -> AES-256-GCM
        if "CHACHA20-POLY1305" in cipher_upper or "CHACHA20_POLY1305" in cipher_upper:
            return "ChaCha20-Poly1305", cipher
        if "AES_256_GCM" in cipher_upper or "AES-256-GCM" in cipher_upper or "AES256-GCM" in cipher_upper:
            return "AES-256-GCM", cipher
        if "AES_128_GCM" in cipher_upper or "AES-128-GCM" in cipher_upper or "AES128-GCM" in cipher_upper:
            return "AES-128-GCM", cipher
        if "AES-GCM" in cipher_upper or "AES_GCM" in cipher_upper:
            if "256" in cipher_upper:
                return "AES-256-GCM", cipher
            if "128" in cipher_upper:
                return "AES-128-GCM", cipher
            return "AES-256-GCM", cipher
        if "AES-CCM" in cipher_upper or "AES_CCM" in cipher_upper:
            return "AES-CCM", cipher
        if "AES_256_CBC" in cipher_upper or "AES-256-CBC" in cipher_upper or "AES256-CBC" in cipher_upper:
            return "AES-256-CBC", cipher
        if "AES_128_CBC" in cipher_upper or "AES-128-CBC" in cipher_upper or "AES128-CBC" in cipher_upper:
            return "AES-128-CBC", cipher
        if "AES-CBC" in cipher_upper or "AES_CBC" in cipher_upper:
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
        if "ECDHE" in cipher_upper and "RSA" in cipher_upper:
            return "ECDH", cipher
        if "ECDHE" in cipher_upper and "ECDSA" in cipher_upper:
            return "ECDSA", cipher
        if "DHE" in cipher_upper and "RSA" in cipher_upper:
            return "DH", cipher
        if "RSA" in cipher_upper:
            return "RSA", cipher
        if "ECDSA" in cipher_upper:
            return "ECDSA", cipher

        return None, None

    def _is_insecure_cipher(self, cipher: str) -> bool:
        insecure = ["DES", "3DES", "RC4", "RC2", "MD5", "SHA1", "NULL", "EXPORT", "ANON", "AECDH", "ADH"]
        cipher_upper = cipher.upper()
        return any(insec in cipher_upper for insec in insecure)