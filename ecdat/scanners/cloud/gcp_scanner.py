from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class GCPScanner(Scanner[ScannerFinding]):
    name = "cloud-gcp"
    version = "0.1.0"

    def __init__(self) -> None:
        self._available = self._check_gcp()

    def _check_gcp(self) -> bool:
        try:
            from google.cloud import kms
            from google.cloud import securitycenter
            return True
        except ImportError:
            return False

    def is_available(self) -> bool:
        return self._available

    def get_tool_version(self) -> str:
        return "gcp-sdk-stub"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        if not self.is_available():
            return []

        findings: list[ScannerFinding] = []

        findings.append(ScannerFinding(
            canonical="GCP Cloud KMS",
            original="GCP Cloud KMS (stub)",
            usage_state=UsageState.PROVIDED_ONLY,
            confidence=0.1,
            evidence=[create_evidence_signal(
                tool="cloud-gcp",
                detail="GCP scanner stub - not fully implemented",
                confidence=0.1,
                snippet="GCP Cloud KMS scanning not implemented",
            )],
            location=Location(uri="gcp:kms:stub"),
            implementation=Implementation(library="GCP SDK", provider="gcp"),
            context=Context(exposure=Exposure.CLOUD),
        ))

        normalized = [normalize_finding(f) for f in findings]
        return normalized