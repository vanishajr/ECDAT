from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, ScannerRegistry
from ecdat.scanners.certificate.pem_scanner import PEMScanner
from ecdat.scanners.certificate.der_scanner import DERScanner
from ecdat.scanners.certificate.jks_scanner import JKSScanner
from ecdat.scanners.certificate.pkcs12_scanner import PKCS12Scanner
from ecdat.scanners.certificate.ssh_scanner import SSHKeyScanner
from ecdat.scanners.certificate.jwk_scanner import JWKScanner


class CertificateScanner(Scanner[ScannerFinding]):
    name = "certificate"
    version = "0.1.0"

    def __init__(self) -> None:
        self._scanners: list[Scanner] = [
            PEMScanner(),
            DERScanner(),
            JKSScanner(),
            PKCS12Scanner(),
            SSHKeyScanner(),
            JWKScanner(),
        ]

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return f"certificate-v{self.version}"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        all_findings: list[ScannerFinding] = []

        if target_path.is_file():
            for scanner in self._scanners:
                if scanner.can_scan_file(target_path):
                    try:
                        findings = scanner.scan(target_path, **kwargs)
                        all_findings.extend(findings)
                    except Exception:
                        continue
        else:
            for scanner in self._scanners:
                try:
                    findings = scanner.scan(target_path, **kwargs)
                    all_findings.extend(findings)
                except Exception:
                    continue

        return all_findings


ScannerRegistry.register(CertificateScanner())