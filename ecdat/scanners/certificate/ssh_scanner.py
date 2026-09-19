from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class SSHKeyScanner(Scanner[ScannerFinding]):
    name = "certificate-ssh"
    version = "0.1.0"

    def __init__(self) -> None:
        self._public_key_pattern = re.compile(
            r"^(ssh-(rsa|dss|ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)\s+(\S+)",
            re.MULTILINE
        )
        self._private_key_pattern = re.compile(
            r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----",
            re.MULTILINE
        )

    def can_scan_file(self, path: Path) -> bool:
        suffixes = (".pub", ".key", "")
        return path.suffix in suffixes or path.name in ("authorized_keys", "known_hosts", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk")

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return "ssh-key-parser"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        findings: list[ScannerFinding] = []

        if target_path.is_file():
            findings.extend(self._scan_file(target_path))
        else:
            for ssh_file in target_path.rglob("*"):
                if ssh_file.is_file() and (self.can_scan_file(ssh_file) or ssh_file.suffix == ""):
                    findings.extend(self._scan_file(ssh_file))

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _scan_file(self, file_path: Path) -> list[ScannerFinding]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        findings: list[ScannerFinding] = []

        for match in self._public_key_pattern.finditer(content):
            key_type = match.group(1)
            key_data = match.group(3)

            canonical, original = self._parse_ssh_key_type(key_type)
            fingerprint = ""
            try:
                import base64
                from ecdat.scanners.certificate.cert_metadata import (
                    openssh_fingerprint)
                fingerprint = openssh_fingerprint(
                    base64.b64decode(key_data))
            except Exception:
                fingerprint = ""
            notes = f"fingerprint={fingerprint}" if fingerprint else ""
            findings.append(ScannerFinding(
                canonical=canonical,
                original=original,
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.8,
                evidence=[create_evidence_signal(
                    tool="certificate-ssh",
                    detail=f"SSH public key: {key_type}",
                    confidence=0.8,
                    snippet=f"{key_type} {key_data[:50]}...",
                )],
                location=Location(file=str(file_path)),
                implementation=Implementation(library="SSH", provider="ssh-key"),
                context=Context(exposure=Exposure.INTERNAL,
                                notes=notes or None),
            ))

        for match in self._private_key_pattern.finditer(content):
            key_type = match.group(1)
            canonical, original = self._parse_ssh_private_key_type(key_type)
            findings.append(ScannerFinding(
                canonical=canonical,
                original=original,
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.9,
                evidence=[create_evidence_signal(
                    tool="certificate-ssh",
                    detail=f"SSH private key: {key_type}",
                    confidence=0.9,
                    snippet=f"-----BEGIN {key_type} PRIVATE KEY----- [REDACTED]",
                )],
                location=Location(file=str(file_path)),
                implementation=Implementation(library="SSH", provider="ssh-key"),
                context=Context(exposure=Exposure.INTERNAL),
            ))

        return findings

    def _parse_ssh_key_type(self, key_type: str) -> tuple[str, str]:
        mapping = {
            "ssh-rsa": ("RSA", "ssh-rsa"),
            "ssh-dss": ("DSA", "ssh-dss"),
            "ssh-ed25519": ("Ed25519", "ssh-ed25519"),
            "ecdsa-sha2-nistp256": ("ECDSA", "ecdsa-sha2-nistp256"),
            "ecdsa-sha2-nistp384": ("ECDSA", "ecdsa-sha2-nistp384"),
            "ecdsa-sha2-nistp521": ("ECDSA", "ecdsa-sha2-nistp521"),
        }
        return mapping.get(key_type, ("Public Key", key_type))

    def _parse_ssh_private_key_type(self, key_type: str) -> tuple[str, str]:
        mapping = {
            "RSA": ("RSA", "RSA PRIVATE KEY"),
            "DSA": ("DSA", "DSA PRIVATE KEY"),
            "EC": ("ECDSA", "EC PRIVATE KEY"),
            "OPENSSH": ("OpenSSH Private Key", "OPENSSH PRIVATE KEY"),
        }
        return mapping.get(key_type, ("Private Key", f"{key_type} PRIVATE KEY"))