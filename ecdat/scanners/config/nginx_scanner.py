from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class NginxScanner(Scanner[ScannerFinding]):
    name = "config-nginx"
    version = "0.1.0"

    def __init__(self) -> None:
        self._ssl_protocols = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
        self._cipher_pattern = re.compile(r"ssl_ciphers\s+([^;]+);")
        self._protocol_pattern = re.compile(r"ssl_protocols\s+([^;]+);")
        self._cert_pattern = re.compile(r"ssl_certificate\s+([^;]+);")
        self._key_pattern = re.compile(r"ssl_certificate_key\s+([^;]+);")
        self._dhparam_pattern = re.compile(r"ssl_dhparam\s+([^;]+);")

    def can_scan_file(self, path: Path) -> bool:
        name = path.name.lower()
        return name in ("nginx.conf",) or name.endswith(".conf") or "nginx" in name

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return "nginx-config-parser"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        findings: list[ScannerFinding] = []

        if target_path.is_file():
            findings.extend(self._scan_file(target_path))
        else:
            for conf_file in target_path.rglob("*.conf"):
                if self.can_scan_file(conf_file):
                    findings.extend(self._scan_file(conf_file))

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
            if line_stripped.startswith("#"):
                continue

            cipher_match = self._cipher_pattern.search(line_stripped)
            if cipher_match:
                findings.extend(self._analyze_ciphers(cipher_match.group(1), file_path, i + 1))

            protocol_match = self._protocol_pattern.search(line_stripped)
            if protocol_match:
                findings.extend(self._analyze_protocols(protocol_match.group(1), file_path, i + 1))

            cert_match = self._cert_pattern.search(line_stripped)
            if cert_match:
                findings.append(self._create_finding(
                    canonical="X.509",
                    original="ssl_certificate",
                    detail=f"SSL certificate path: {cert_match.group(1)}",
                    file_path=file_path,
                    line=i + 1,
                    confidence=0.7,
                ))

            key_match = self._key_pattern.search(line_stripped)
            if key_match:
                findings.append(self._create_finding(
                    canonical="Private Key",
                    original="ssl_certificate_key",
                    detail=f"SSL private key path: {key_match.group(1)}",
                    file_path=file_path,
                    line=i + 1,
                    confidence=0.8,
                ))

            dhparam_match = self._dhparam_pattern.search(line_stripped)
            if dhparam_match:
                findings.append(self._create_finding(
                    canonical="DH",
                    original="ssl_dhparam",
                    detail=f"DH parameters file: {dhparam_match.group(1)}",
                    file_path=file_path,
                    line=i + 1,
                    confidence=0.6,
                ))

        return findings

    def _analyze_ciphers(self, cipher_string: str, file_path: Path, line: int) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        ciphers = [c.strip() for c in cipher_string.split(":") if c.strip()]

        for cipher in ciphers:
            canonical, original = self._parse_cipher(cipher)
            if canonical:
                category = get_category(canonical)
                is_insecure = self._is_insecure_cipher(cipher)

                if is_library_only(canonical) or category == "library":
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
                        tool="config-nginx",
                        detail=f"Nginx cipher suite: {cipher}",
                        confidence=confidence,
                        snippet=f"ssl_ciphers {cipher_string[:200]};",
                    )],
                    location=Location(file=str(file_path), line=line),
                    implementation=Implementation(library="nginx", api="ssl_ciphers"),
                    context=Context(exposure=Exposure.INTERNET_FACING),
                ))

        return findings

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
        # Key exchange / auth algorithms - return as-is for now
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

    def _analyze_protocols(self, protocol_string: str, file_path: Path, line: int) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        protocols = [p.strip() for p in protocol_string.split() if p.strip()]

        for proto in protocols:
            proto_lower = proto.lower()
            if proto_lower in ("sslv2", "sslv3", "tlsv1", "tlsv1.1"):
                findings.append(ScannerFinding(
                    canonical="SSL",
                    original=proto,
                    usage_state=UsageState.CONFIRMED,
                    confidence=0.9,
                    evidence=[create_evidence_signal(
                        tool="config-nginx",
                        detail=f"Insecure protocol enabled: {proto}",
                        confidence=0.9,
                        snippet=f"ssl_protocols {protocol_string};",
                    )],
                    location=Location(file=str(file_path), line=line),
                    implementation=Implementation(library="nginx", api="ssl_protocols"),
                    context=Context(exposure=Exposure.INTERNET_FACING),
                ))
            elif proto_lower in ("tlsv1.2", "tlsv1.3"):
                canonical = "TLS1.2" if "1.2" in proto_lower else "TLS1.3"
                findings.append(ScannerFinding(
                    canonical=canonical,
                    original=proto,
                    usage_state=UsageState.CONFIRMED,
                    confidence=0.8,
                    evidence=[create_evidence_signal(
                        tool="config-nginx",
                        detail=f"Secure protocol enabled: {proto}",
                        confidence=0.8,
                        snippet=f"ssl_protocols {protocol_string};",
                    )],
                    location=Location(file=str(file_path), line=line),
                    implementation=Implementation(library="nginx", api="ssl_protocols"),
                    context=Context(exposure=Exposure.INTERNET_FACING),
                ))

        return findings

    def _create_finding(self, canonical: str, original: str, detail: str, file_path: Path, line: int, confidence: float) -> ScannerFinding:
        category = get_category(canonical)
        if is_library_only(canonical) or category == "library":
            usage_state = UsageState.PROVIDED_ONLY
        else:
            usage_state = UsageState.CONFIRMED

        return ScannerFinding(
            canonical=canonical,
            original=original,
            usage_state=usage_state,
            confidence=confidence,
            evidence=[create_evidence_signal(
                tool="config-nginx",
                detail=detail,
                confidence=confidence,
            )],
            location=Location(file=str(file_path), line=line),
            implementation=Implementation(library="nginx", api=original),
            context=Context(exposure=Exposure.INTERNET_FACING),
        )