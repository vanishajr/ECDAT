from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, ScannerRegistry
from ecdat.scanners.cloud.aws_scanner import AWSScanner
from ecdat.scanners.cloud.azure_scanner import AzureScanner
from ecdat.scanners.cloud.gcp_scanner import GCPScanner


class CloudScanner(Scanner[ScannerFinding]):
    name = "cloud"
    version = "0.1.0"

    def __init__(self) -> None:
        self._scanners: list[Scanner] = []
        self._init_scanners()

    def _init_scanners(self) -> None:
        aws = AWSScanner()
        if aws.is_available():
            self._scanners.append(aws)

        azure = AzureScanner()
        if azure.is_available():
            self._scanners.append(azure)

        gcp = GCPScanner()
        if gcp.is_available():
            self._scanners.append(gcp)

    def is_available(self) -> bool:
        return len(self._scanners) > 0

    def get_tool_version(self) -> str:
        versions = [s.get_tool_version() for s in self._scanners]
        return f"cloud-v{self.version}({','.join(versions)})"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        all_findings: list[ScannerFinding] = []

        for scanner in self._scanners:
            try:
                findings = scanner.scan(target, **kwargs)
                all_findings.extend(findings)
            except Exception:
                continue

        return all_findings


ScannerRegistry.register(CloudScanner())