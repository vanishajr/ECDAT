from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding


class GCPScanner(Scanner[ScannerFinding]):
    name = "cloud-gcp"
    version = "0.1.0"

    def __init__(self) -> None:
        self._sdk_present = self._check_gcp()

    def _check_gcp(self) -> bool:
        try:
            from google.cloud import kms
            from google.cloud import securitycenter
            return True
        except ImportError:
            return False

    def is_available(self) -> bool:
        # Phase 7 honesty: inventory is not implemented, so this family
        # is never offered regardless of SDK presence. Emitting stub
        # findings would fabricate evidence; returning [] silently would
        # read as "nothing found". Unavailable is the honest state.
        return False

    def get_tool_version(self) -> str:
        state = "sdk-present" if self._sdk_present else "sdk-missing"
        return f"gcp-{state}-inventory-not-implemented"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        return []