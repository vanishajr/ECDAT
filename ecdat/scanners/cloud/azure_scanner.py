from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class AzureScanner(Scanner[ScannerFinding]):
    name = "cloud-azure"
    version = "0.1.0"

    def __init__(self) -> None:
        self._available = self._check_azure()

    def _check_azure(self) -> bool:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.keyvault import KeyVaultManagementClient
            from azure.mgmt.resource import ResourceManagementClient
            return True
        except ImportError:
            return False

    def is_available(self) -> bool:
        return self._available

    def get_tool_version(self) -> str:
        return "azure-sdk-stub"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        if not self.is_available():
            return []

        findings: list[ScannerFinding] = []

        findings.append(ScannerFinding(
            canonical="Azure Key Vault",
            original="Azure Key Vault (stub)",
            usage_state=UsageState.PROVIDED_ONLY,
            confidence=0.1,
            evidence=[create_evidence_signal(
                tool="cloud-azure",
                detail="Azure scanner stub - not fully implemented",
                confidence=0.1,
                snippet="Azure Key Vault scanning not implemented",
            )],
            location=Location(uri="azure:keyvault:stub"),
            implementation=Implementation(library="Azure SDK", provider="azure"),
            context=Context(exposure=Exposure.CLOUD),
        ))

        normalized = [normalize_finding(f) for f in findings]
        return normalized