from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding


class AzureScanner(Scanner[ScannerFinding]):
    name = "cloud-azure"
    version = "0.1.0"

    def __init__(self) -> None:
        self._sdk_present = self._check_azure()

    def _check_azure(self) -> bool:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.keyvault import KeyVaultManagementClient
            from azure.mgmt.resource import ResourceManagementClient
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
        return f"azure-{state}-inventory-not-implemented"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        return []