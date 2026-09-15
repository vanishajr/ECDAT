from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, ScannerRegistry
from ecdat.scanners.binary.lief_scanner import LIEFScanner
from ecdat.scanners.binary.strings_scanner import StringsScanner
from ecdat.scanners.binary.yara_scanner import YARAScanner


class BinaryScanner(Scanner[ScannerFinding]):
    name = "binary"
    version = "0.1.0"

    def __init__(self) -> None:
        self._scanners: list[Scanner] = []
        self._init_scanners()

    def _init_scanners(self) -> None:
        self._scanners.append(StringsScanner())
        lief = LIEFScanner()
        if lief.is_available():
            self._scanners.append(lief)
        yara = YARAScanner()
        if yara.is_available():
            self._scanners.append(yara)

    def is_available(self) -> bool:
        return len(self._scanners) > 0

    def get_tool_version(self) -> str:
        versions = [s.get_tool_version() for s in self._scanners]
        return f"binary-v{self.version}({','.join(versions)})"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        all_findings: list[ScannerFinding] = []

        if target_path.is_file():
            if self._is_binary_file(target_path):
                for scanner in self._scanners:
                    try:
                        findings = scanner.scan(target_path, **kwargs)
                        all_findings.extend(findings)
                    except Exception:
                        continue
        else:
            for binary_file in self._find_binary_files(target_path):
                for scanner in self._scanners:
                    try:
                        findings = scanner.scan(binary_file, **kwargs)
                        all_findings.extend(findings)
                    except Exception:
                        continue

        return all_findings

    def _is_binary_file(self, path: Path) -> bool:
        if path.suffix in {".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".o", ".a", ".lib"}:
            return True
        try:
            with open(path, "rb") as f:
                chunk = f.read(1024)
                if b"\x00" in chunk:
                    return True
        except Exception:
            pass
        return False

    def _find_binary_files(self, root: Path) -> list[Path]:
        binaries: list[Path] = []
        for path in root.rglob("*"):
            if path.is_file() and self._is_binary_file(path):
                binaries.append(path)
        return binaries


ScannerRegistry.register(BinaryScanner())