from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class TerraformScanner(Scanner[ScannerFinding]):
    name = "config-terraform"
    version = "0.1.0"

    def __init__(self) -> None:
        self._resource_pattern = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*{')
        self._tls_version_pattern = re.compile(r'(?:min|max)_tls_version\s*=\s*"([^"]+)"')
        self._ssl_policy_pattern = re.compile(r'ssl_policy\s*=\s*"([^"]+)"')
        self._cipher_pattern = re.compile(r'cipher_suites?\s*=\s*\[([^\]]+)\]')
        self._cert_pattern = re.compile(r'(?:cert|certificate|public_key|certificate_arn)\s*=\s*([^\n]+)')
        self._key_pattern = re.compile(r'(?:private_key|key)\s*=\s*([^\n]+)')

    def can_scan_file(self, path: Path) -> bool:
        return path.suffix in (".tf", ".tfvars") or path.name == "terraform.tfstate"

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return "terraform-config-parser"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        findings: list[ScannerFinding] = []

        if target_path.is_file():
            if self.can_scan_file(target_path):
                findings.extend(self._scan_file(target_path))
        else:
            for tf_file in target_path.rglob("*.tf"):
                findings.extend(self._scan_file(tf_file))
            for tfvars_file in target_path.rglob("*.tfvars"):
                findings.extend(self._scan_file(tfvars_file))
            tfstate = target_path / "terraform.tfstate"
            if tfstate.exists():
                findings.extend(self._scan_tfstate(tfstate))

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

            tls_version_match = self._tls_version_pattern.search(line_stripped)
            if tls_version_match:
                findings.append(self._create_tls_version_finding(tls_version_match.group(1), file_path, i + 1))

            ssl_policy_match = self._ssl_policy_pattern.search(line_stripped)
            if ssl_policy_match:
                findings.append(self._create_ssl_policy_finding(ssl_policy_match.group(1), file_path, i + 1))

            cipher_match = self._cipher_pattern.search(line_stripped)
            if cipher_match:
                findings.extend(self._analyze_ciphers(cipher_match.group(1), file_path, i + 1))

            cert_match = self._cert_pattern.search(line_stripped)
            if cert_match:
                findings.append(self._create_finding("X.509", cert_match.group(1).strip(), file_path, i + 1, 0.7))

            key_match = self._key_pattern.search(line_stripped)
            if key_match:
                findings.append(self._create_finding("Private Key", key_match.group(1).strip(), file_path, i + 1, 0.8))

        return findings

    def _scan_tfstate(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            import json
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except Exception:
            return findings

        for resource in data.get("resources", []):
            if resource.get("type") in ("aws_acm_certificate", "aws_lb_listener", "aws_alb_listener", "google_ssl_certificate", "azurerm_application_gateway"):
                findings.append(ScannerFinding(
                    canonical="TLS1.2",
                    original=resource.get("type", ""),
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=0.6,
                    evidence=[create_evidence_signal(
                        tool="config-terraform",
                        detail=f"Terraform state resource: {resource.get('type')} {resource.get('name', '')}",
                        confidence=0.6,
                        snippet=f"{resource.get('type')} {resource.get('name', '')}",
                    )],
                    location=Location(file=str(file_path), uri=f"tfstate:{resource.get('type')}:{resource.get('name', '')}"),
                    implementation=Implementation(library="terraform", provider="aws"),
                    context=Context(exposure=Exposure.CLOUD),
                ))

        return findings

    def _create_tls_version_finding(self, version: str, file_path: Path, line: int) -> ScannerFinding:
        version_lower = version.lower()

        if "1.3" in version_lower:
            canonical = "TLS1.3"
            usage_state = UsageState.CONFIRMED
            confidence = 0.8
        elif "1.2" in version_lower:
            canonical = "TLS1.2"
            usage_state = UsageState.CONFIRMED
            confidence = 0.8
        elif "1.1" in version_lower or "1.0" in version_lower:
            canonical = "TLS1.2"
            usage_state = UsageState.CONFIRMED
            confidence = 0.7
        else:
            canonical = "TLS"
            usage_state = UsageState.CONFIRMED
            confidence = 0.5

        return ScannerFinding(
            canonical=canonical,
            original=version,
            usage_state=usage_state,
            confidence=confidence,
            evidence=[create_evidence_signal(
                tool="config-terraform",
                detail=f"Terraform TLS version: {version}",
                confidence=confidence,
                snippet=f"tls_version = \"{version}\"",
            )],
            location=Location(file=str(file_path), line=line),
            implementation=Implementation(library="terraform", provider="aws", api="tls_version"),
            context=Context(exposure=Exposure.CLOUD),
        )

    def _create_ssl_policy_finding(self, policy: str, file_path: Path, line: int) -> ScannerFinding:
        policy_lower = policy.lower()

        if "tls13" in policy_lower or "tls1.3" in policy_lower:
            canonical = "TLS1.3"
            usage_state = UsageState.CONFIRMED
            confidence = 0.8
        elif "tls12" in policy_lower or "tls1.2" in policy_lower:
            canonical = "TLS1.2"
            usage_state = UsageState.CONFIRMED
            confidence = 0.8
        elif "tls11" in policy_lower or "tls1.1" in policy_lower:
            canonical = "TLS1.1"
            usage_state = UsageState.CONFIRMED
            confidence = 0.7
        elif "tls10" in policy_lower or "tls1.0" in policy_lower:
            canonical = "TLS1.0"
            usage_state = UsageState.CONFIRMED
            confidence = 0.7
        else:
            canonical = "TLS"
            usage_state = UsageState.CONFIRMED
            confidence = 0.5

        return ScannerFinding(
            canonical=canonical,
            original=policy,
            usage_state=usage_state,
            confidence=confidence,
            evidence=[create_evidence_signal(
                tool="config-terraform",
                detail=f"Terraform SSL policy: {policy}",
                confidence=confidence,
                snippet=f"ssl_policy = \"{policy}\"",
            )],
            location=Location(file=str(file_path), line=line),
            implementation=Implementation(library="terraform", provider="aws", api="ssl_policy"),
            context=Context(exposure=Exposure.CLOUD),
        )

    def _analyze_ciphers(self, cipher_string: str, file_path: Path, line: int) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        ciphers = [c.strip().strip('"\'') for c in cipher_string.split(",") if c.strip()]

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
                        tool="config-terraform",
                        detail=f"Terraform cipher suite: {cipher}",
                        confidence=confidence,
                        snippet=f"cipher_suites = [...{cipher}...]",
                    )],
                    location=Location(file=str(file_path), line=line),
                    implementation=Implementation(library="terraform", provider="aws", api="cipher_suites"),
                    context=Context(exposure=Exposure.CLOUD),
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

    def _create_finding(self, canonical: str, original: str, file_path: Path, line: int, confidence: float) -> ScannerFinding:
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
                tool="config-terraform",
                detail=f"Terraform {canonical} reference: {original}",
                confidence=confidence,
            )],
            location=Location(file=str(file_path), line=line),
            implementation=Implementation(library="terraform", provider="aws"),
            context=Context(exposure=Exposure.CLOUD),
        )