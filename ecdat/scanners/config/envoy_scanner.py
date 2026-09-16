from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class EnvoyScanner(Scanner[ScannerFinding]):
    name = "config-envoy"
    version = "0.1.0"

    def __init__(self) -> None:
        pass

    def can_scan_file(self, path: Path) -> bool:
        name = path.name.lower()
        return name in ("envoy.yaml", "envoy.yml", "envoy.json") or "envoy" in name

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return "envoy-config-parser"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        findings: list[ScannerFinding] = []

        if target_path.is_file():
            findings.extend(self._scan_file(target_path))
        else:
            for conf_file in target_path.rglob("*"):
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

        if file_path.suffix == ".json":
            findings.extend(self._scan_json(content, file_path))
        else:
            findings.extend(self._scan_yaml(content, file_path))

        return findings

    def _scan_json(self, content: str, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            data = json.loads(content)
        except Exception:
            return findings

        if isinstance(data, dict):
            if "static_resources" in data:
                for listener in data["static_resources"].get("listeners", []):
                    findings.extend(self._scan_listener(listener, file_path))
            if "dynamic_resources" in data:
                for lds in data["dynamic_resources"].get("lds_config", {}).get("path", []):
                    pass

        return findings

    def _scan_yaml(self, content: str, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            import yaml
            data = yaml.safe_load(content)
        except Exception:
            return findings

        if isinstance(data, dict):
            if "static_resources" in data:
                for listener in data["static_resources"].get("listeners", []):
                    findings.extend(self._scan_listener(listener, file_path))
            if "listeners" in data:
                for listener in data["listeners"]:
                    findings.extend(self._scan_listener(listener, file_path))

        return findings

    def _scan_listener(self, listener: dict, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        for filter_chain in listener.get("filter_chains", []):
            transport_socket = filter_chain.get("transport_socket", {})
            if transport_socket.get("name") == "envoy.transport_sockets.tls":
                config = transport_socket.get("typed_config", {})
                findings.extend(self._scan_tls_context(config, file_path))

        return findings

    def _scan_tls_context(self, config: dict, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        common_tls = config.get("common_tls_context", {})
        if common_tls:
            tls_params = common_tls.get("tls_params", {})
            if tls_params:
                if "cipher_suites" in tls_params:
                    findings.extend(self._analyze_cipher_suites(tls_params["cipher_suites"], file_path))
                if "tls_minimum_protocol_version" in tls_params:
                    findings.append(self._create_protocol_finding(tls_params["tls_minimum_protocol_version"], file_path, "min"))
                if "tls_maximum_protocol_version" in tls_params:
                    findings.append(self._create_protocol_finding(tls_params["tls_maximum_protocol_version"], file_path, "max"))

            validation = common_tls.get("validation_context", {})
            if validation:
                if "trusted_ca" in validation:
                    ca = validation["trusted_ca"]
                    if "filename" in ca:
                        findings.append(self._create_finding("X.509", "trusted_ca", f"Trusted CA: {ca['filename']}", file_path, 0.7))
                    if "inline_bytes" in ca:
                        findings.append(self._create_finding("X.509", "trusted_ca_inline", "Trusted CA (inline)", file_path, 0.7))

                if "verify_certificate_spki" in validation:
                    findings.append(self._create_finding("X.509", "verify_certificate_spki", "Certificate SPKI verification", file_path, 0.6))

            if "tls_certificates" in common_tls:
                for cert in common_tls["tls_certificates"]:
                    if "certificate_chain" in cert:
                        if "filename" in cert["certificate_chain"]:
                            findings.append(self._create_finding("X.509", "certificate_chain", f"Certificate chain: {cert['certificate_chain']['filename']}", file_path, 0.8))
                        if "inline_bytes" in cert["certificate_chain"]:
                            findings.append(self._create_finding("X.509", "certificate_chain_inline", "Certificate chain (inline)", file_path, 0.8))
                    if "private_key" in cert:
                        if "filename" in cert["private_key"]:
                            findings.append(self._create_finding("Private Key", "private_key", f"Private key: {cert['private_key']['filename']}", file_path, 0.9))
                        if "inline_bytes" in cert["private_key"]:
                            findings.append(self._create_finding("Private Key", "private_key_inline", "Private key (inline)", file_path, 0.9))

        return findings

    def _analyze_cipher_suites(self, cipher_suites: list[str], file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        for cipher in cipher_suites:
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
                        tool="config-envoy",
                        detail=f"Envoy cipher suite: {cipher}",
                        confidence=confidence,
                        snippet=cipher,
                    )],
                    location=Location(file=str(file_path)),
                    implementation=Implementation(library="envoy", api="cipher_suites"),
                    context=Context(exposure=Exposure.INTERNET_FACING),
                ))

        return findings

    def _parse_cipher(self, cipher: str) -> tuple[str, str] | tuple[None, None]:
        cipher_upper = cipher.upper().replace("-", "_")

        # Extract symmetric cipher from full TLS cipher suite strings
        # e.g., ECDHE-RSA-AES256-GCM-SHA384 -> AES-256-GCM
        if "CHACHA20_POLY1305" in cipher_upper:
            return "ChaCha20-Poly1305", cipher
        if "AES_256_GCM" in cipher_upper or "AES256_GCM" in cipher_upper:
            return "AES-256-GCM", cipher
        if "AES_128_GCM" in cipher_upper or "AES128_GCM" in cipher_upper:
            return "AES-128-GCM", cipher
        if "AES_GCM" in cipher_upper or "AESGCM" in cipher_upper:
            if "256" in cipher_upper:
                return "AES-256-GCM", cipher
            if "128" in cipher_upper:
                return "AES-128-GCM", cipher
            return "AES-256-GCM", cipher
        if "AES_CCM" in cipher_upper or "AESCCM" in cipher_upper:
            return "AES-CCM", cipher
        if "AES_256_CBC" in cipher_upper or "AES256_CBC" in cipher_upper:
            return "AES-256-CBC", cipher
        if "AES_128_CBC" in cipher_upper or "AES128_CBC" in cipher_upper:
            return "AES-128-CBC", cipher
        if "AES_CBC" in cipher_upper or "AESCBC" in cipher_upper:
            if "256" in cipher_upper:
                return "AES-256-CBC", cipher
            if "128" in cipher_upper:
                return "AES-128-CBC", cipher
            return "AES-256-CBC", cipher
        if "AES" in cipher_upper:
            return "AES", cipher
        if "CHACHA20" in cipher_upper:
            return "ChaCha20", cipher
        if "3DES" in cipher_upper or "DES_CBC3" in cipher_upper:
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
        if "RSA" in cipher_upper:
            return "RSA", cipher
        if "ECDSA" in cipher_upper:
            return "ECDSA", cipher

        return None, None

    def _is_insecure_cipher(self, cipher: str) -> bool:
        insecure = ["DES", "3DES", "RC4", "RC2", "MD5", "SHA1", "NULL", "EXPORT", "ANON", "AECDH", "ADH"]
        cipher_upper = cipher.upper()
        return any(insec in cipher_upper for insec in insecure)

    def _create_protocol_finding(self, protocol: str, file_path: Path, limit: str) -> ScannerFinding:
        proto_lower = protocol.lower()

        if "tlsv1_3" in proto_lower or "tlsv13" in proto_lower:
            canonical = "TLS1.3"
            usage_state = UsageState.CONFIRMED
            confidence = 0.8
        elif "tlsv1_2" in proto_lower or "tlsv12" in proto_lower:
            canonical = "TLS1.2"
            usage_state = UsageState.CONFIRMED
            confidence = 0.8
        elif "tlsv1_1" in proto_lower or "tlsv11" in proto_lower:
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
                tool="config-envoy",
                detail=f"Envoy TLS {limit} protocol: {protocol}",
                confidence=confidence,
                snippet=protocol,
            )],
            location=Location(file=str(file_path)),
            implementation=Implementation(library="envoy", api=f"tls_{limit}_protocol"),
            context=Context(exposure=Exposure.INTERNET_FACING),
        )

    def _create_finding(self, canonical: str, original: str, detail: str, file_path: Path, confidence: float) -> ScannerFinding:
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
                tool="config-envoy",
                detail=detail,
                confidence=confidence,
            )],
            location=Location(file=str(file_path)),
            implementation=Implementation(library="envoy", api=original),
            context=Context(exposure=Exposure.INTERNET_FACING),
        )