from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generic, Optional, TypeVar

from ecdat.core.cir_models import (
    CryptoAsset,
    CryptoOperation,
    EvidenceSignal,
    Location,
    Implementation,
    Context,
    RiskInputs,
    UsageState,
    OperationType,
    Exposure,
    new_asset_id,
    new_operation_id,
)
from ecdat.core.signature_registry import (
    normalize_algorithm,
    get_category,
    infer_usage_state,
    infer_operation_type,
)


@dataclass
class ScannerFinding:
    canonical: str
    original: str
    key_size: Optional[int] = None
    mode: Optional[str] = None
    curve: Optional[str] = None
    protocol: Optional[str] = None
    library: Optional[str] = None
    usage_state: UsageState = UsageState.POSSIBLE
    confidence: float = 0.5
    evidence: list[EvidenceSignal] = field(default_factory=list)
    location: Optional[Location] = None
    implementation: Optional[Implementation] = None
    context: Optional[Context] = None
    operation_type: Optional[OperationType] = None
    function: Optional[str] = None
    dependency_only: bool = False

    def to_asset(self) -> CryptoAsset:
        asset_id = new_asset_id(
            self.canonical, 
            self.key_size, 
            self.mode, 
            self.curve, 
            self.protocol,
            self.location.file if self.location else None,
            self.location.line if self.location else None,
        )
        risk_inputs = None
        if self.context:
            risk_inputs = RiskInputs(
                usage_state=self.usage_state,
                exposure=self.context.exposure,
                sensitive_data=self.context.data_classification in ("restricted", "confidential", "secret"),
                external_dependency=self.library is not None,
            )
        return CryptoAsset(
            asset_id=asset_id,
            canonical=self.canonical,
            original=self.original,
            key_size=self.key_size,
            mode=self.mode,
            curve=self.curve,
            protocol=self.protocol,
            library=self.library,
            usage_state=self.usage_state,
            confidence=self.confidence,
            evidence=self.evidence,
            location=self.location,
            implementation=self.implementation,
            context=self.context,
            risk_inputs=risk_inputs,
        )

    def to_operation(self, asset_id: str) -> CryptoOperation | None:
        if self.operation_type is None:
            return None
        op_id = new_operation_id(self.operation_type, asset_id, self.function, self.location)
        risk_inputs = None
        if self.context:
            risk_inputs = RiskInputs(
                usage_state=self.usage_state,
                exposure=self.context.exposure,
                sensitive_data=self.context.data_classification in ("restricted", "confidential", "secret"),
                external_dependency=self.library is not None,
            )
        return CryptoOperation(
            operation_id=op_id,
            operation_type=self.operation_type,
            asset_id=asset_id,
            confidence=self.confidence,
            evidence=self.evidence,
            function=self.function,
            location=self.location,
            implementation=self.implementation,
            context=self.context,
            risk_inputs=risk_inputs,
        )


T = TypeVar("T", bound=ScannerFinding)


class Scanner(ABC, Generic[T]):
    name: str = "base"
    version: str = "0.1.0"

    @abstractmethod
    def scan(self, target: Path | str, **kwargs) -> list[T]:
        pass

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return self.version


class ScannerRegistry:
    _scanners: dict[str, Scanner] = {}

    @classmethod
    def register(cls, scanner: Scanner) -> None:
        cls._scanners[scanner.name] = scanner

    @classmethod
    def get(cls, name: str) -> Scanner | None:
        return cls._scanners.get(name)

    @classmethod
    def all(cls) -> list[Scanner]:
        return list(cls._scanners.values())

    @classmethod
    def available(cls) -> list[Scanner]:
        return [s for s in cls._scanners.values() if s.is_available()]


def create_evidence_signal(tool: str, detail: str, confidence: Optional[float] = None,
                          snippet: Optional[str] = None) -> EvidenceSignal:
    return EvidenceSignal(tool=tool, detail=detail, confidence=confidence, snippet=snippet)


def normalize_finding(finding: ScannerFinding, registry_available: bool = True) -> ScannerFinding:
    if registry_available:
        canonical, original = normalize_algorithm(finding.original)
        finding.canonical = canonical
        finding.original = original
        category = get_category(canonical)
        finding.library = finding.library or (canonical if category == "library" else None)

        # Dependency-only findings must remain ProvidedOnly - never upgrade based on evidence confidence
        if not finding.dependency_only:
            has_direct = any(e.confidence and e.confidence > 0.8 for e in finding.evidence)
            has_indirect = any(e.confidence and 0.4 <= e.confidence <= 0.8 for e in finding.evidence)
            finding.usage_state = infer_usage_state(category, has_direct, has_indirect)

        if finding.operation_type is None and category:
            detail = " ".join(e.detail for e in finding.evidence)
            finding.operation_type = infer_operation_type(category, detail)

    return finding