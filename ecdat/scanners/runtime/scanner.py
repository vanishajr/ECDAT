from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, ScannerRegistry
from ecdat.scanners.runtime.tls_scanner import TLSScanner
from ecdat.scanners.runtime.ssh_scanner import SSHScanner


class RuntimeScanner(Scanner[ScannerFinding]):
    name = "runtime"
    version = "0.1.0"

    def __init__(self) -> None:
        self._scanners: list[Scanner] = [
            TLSScanner(),
            SSHScanner(),
        ]

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return f"runtime-v{self.version}"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_str = str(target)
        if not target_str:
            return []

        all_findings: list[ScannerFinding] = []

        for scanner in self._scanners:
            if scanner.can_scan_target(target_str):
                try:
                    findings = scanner.scan(target_str, **kwargs)
                    all_findings.extend(findings)
                except Exception:
                    continue

        return all_findings


ScannerRegistry.register(RuntimeScanner())