from __future__ import annotations

import logging
import hashlib
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, ScannerRegistry, normalize_finding
from ecdat.core.cir_models import (
    CIRDocument,
    CryptoAsset,
    CryptoOperation,
    EvidenceSignal,
    Graph,
    GraphEdge,
    GraphNode,
    Location,
    Implementation,
    Context,
    RiskInputs,
    Stats,
    UsageState,
    OperationType,
    Exposure,
    GraphNodeKind,
    GraphRelationship,
    new_asset_id,
    new_operation_id,
    load_cir_json,
    validate_cir_json,
)
from ecdat.core.signature_registry import get_registry_version
from ecdat.scanners.source.scanner import SourceScanner
from ecdat.scanners.dependency.scanner import DependencyScanner
from ecdat.scanners.binary.scanner import BinaryScanner
from ecdat.scanners.container.scanner import ContainerScanner
from ecdat.scanners.config.scanner import ConfigScanner
from ecdat.scanners.certificate.scanner import CertificateScanner
from ecdat.scanners.runtime.scanner import RuntimeScanner
from ecdat.scanners.cloud.scanner import CloudScanner

logger = logging.getLogger(__name__)


def _deterministic_hash(value: str, prefix: str, length: int = 16) -> str:
    """Generate a deterministic hash for a string value.
    
    Uses SHA256 for cross-process determinism (unlike Python's built-in hash()).
    """
    hash_val = hashlib.sha256(value.encode()).hexdigest()[:length]
    return f"{prefix}:{hash_val}"


class DiscoveryEngine:
    def __init__(self, enabled_scanners: Optional[list[str]] = None) -> None:
        # P3 integration note: construct ONLY explicitly enabled scanners.
        # P2 constructed all eight families up front, which fires an AWS
        # STS identity call (the cloud availability probe) at
        # construction time — network I/O as a constructor side effect.
        # enabled_scanners=None now means the P3 safe local default
        # (source/dependency/binary/config/certificate), never the
        # network-capable families (container/cloud/runtime), which are
        # constructed solely on explicit request.
        if enabled_scanners is None:
            from ecdat.adapters.scanner_policy import DEFAULT_SCANNERS
            enabled_scanners = list(DEFAULT_SCANNERS)
        factories = {
            "source": SourceScanner,
            "dependency": DependencyScanner,
            "binary": BinaryScanner,
            "container": ContainerScanner,
            "config": ConfigScanner,
            "certificate": CertificateScanner,
            "runtime": RuntimeScanner,
            "cloud": CloudScanner,
        }
        self._all_scanners = {}
        for name in enabled_scanners:
            factory = factories.get(str(name).strip().lower())
            if factory is not None and name not in self._all_scanners:
                self._all_scanners[str(name).strip().lower()] = factory()
        self._scanners = dict(self._all_scanners)

    def get_available_scanners(self) -> list[str]:
        return [name for name, scanner in self._all_scanners.items() if scanner.is_available()]

    def get_enabled_scanners(self) -> list[str]:
        return list(self._scanners.keys())

    def availability(self) -> dict[str, bool]:
        """P3 integration addition: availability of ENABLED scanners.

        Public probe so orchestrators can warn loudly when an
        explicitly requested family cannot run (missing tool, daemon,
        or credentials) instead of silently yielding zero findings.
        Note: probing the cloud family may use ambient credentials.
        """
        report: dict[str, bool] = {}
        for name, scanner in self._scanners.items():
            try:
                report[name] = bool(scanner.is_available())
            except Exception:
                report[name] = False
        return report

    def scan(self, target: Path | str, scanner_names: Optional[list[str]] = None, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target) if not isinstance(target, str) or Path(target).exists() else target

        scanners_to_run = self._scanners
        if scanner_names:
            scanners_to_run = {name: self._scanners[name] for name in scanner_names if name in self._scanners}

        all_findings: list[ScannerFinding] = []

        for name, scanner in scanners_to_run.items():
            try:
                findings = scanner.scan(target_path, **kwargs)
                all_findings.extend(findings)
            except Exception as e:
                logger.warning("Scanner %s failed: %s", name, e)
                continue

        normalized = [normalize_finding(f) for f in all_findings]
        
        # Correlate findings from different scanners
        correlated = self._correlate_findings(normalized)
        return correlated

    def _correlate_findings(self, findings: list[ScannerFinding]) -> list[ScannerFinding]:
        """Correlate findings from different scanners that refer to the same logical asset.
        
        Groups by (file, canonical) and merges findings from different scanners
        that are within 5 lines of each other. Also merges findings from the same
        scanner that are within 5 lines and in the same function.
        """
        if not findings:
            return findings
            
        # Group by file + canonical
        groups: dict[tuple[str, str], list[ScannerFinding]] = defaultdict(list)
        for f in findings:
            file_key = f.location.file if f.location and f.location.file else "unknown"
            groups[(file_key, f.canonical)].append(f)
        
        correlated: list[ScannerFinding] = []
        
        for group_findings in groups.values():
            if len(group_findings) == 1:
                correlated.append(group_findings[0])
                continue
            
            # Sort by line number for proximity-based merging
            group_findings.sort(key=lambda f: (f.location.line or 0) if f.location else 0)
            
            merged: list[ScannerFinding] = []
            current = group_findings[0]
            
            for finding in group_findings[1:]:
                # Check if from different scanner and within 5 lines
                current_line = current.location.line if current.location else None
                finding_line = finding.location.line if finding.location else None
                
                different_scanner = self._get_scanner_name(current) != self._get_scanner_name(finding)
                same_function = (
                    current.location.function is not None and
                    finding.location.function is not None and
                    current.location.function == finding.location.function
                )
                nearby = (
                    current_line is not None and 
                    finding_line is not None and 
                    abs(current_line - finding_line) <= 5
                )
                
                # Merge if: different scanners nearby, OR same scanner in same function nearby
                if (different_scanner and nearby) or (not different_scanner and same_function and nearby):
                    # Merge findings
                    current = self._merge_findings(current, finding)
                else:
                    merged.append(current)
                    current = finding
            
            merged.append(current)
            correlated.extend(merged)
        
        return correlated

    def _get_scanner_name(self, finding: ScannerFinding) -> str:
        """Extract scanner name from evidence tool field."""
        if finding.evidence:
            tool = finding.evidence[0].tool
            if ":" in tool:
                return tool.split(":")[0]
            return tool
        return "unknown"

    def _merge_findings(self, a: ScannerFinding, b: ScannerFinding) -> ScannerFinding:
        """Merge two findings from different scanners into one."""
        # Combine evidence
        combined_evidence = a.evidence + b.evidence
        
        # Take max confidence
        combined_confidence = max(a.confidence, b.confidence)
        
        # Take highest usage state (Confirmed > Probable > Possible > ProvidedOnly > FalsePositiveSuppressed)
        state_order = {
            UsageState.CONFIRMED: 5,
            UsageState.PROBABLE: 4,
            UsageState.POSSIBLE: 3,
            UsageState.PROVIDED_ONLY: 2,
            UsageState.FALSE_POSITIVE_SUPPRESSED: 1,
        }
        combined_state = a.usage_state if state_order[a.usage_state] >= state_order[b.usage_state] else b.usage_state
        
        # If both are dependency-only, keep dependency_only=True
        # If one has actual usage evidence, dependency_only becomes False
        combined_dependency_only = getattr(a, 'dependency_only', False) and getattr(b, 'dependency_only', False)
        
        # Use the finding with higher confidence as base, but merge properties
        base = a if a.confidence >= b.confidence else b
        
        return ScannerFinding(
            canonical=base.canonical,
            original=base.original,
            key_size=base.key_size,
            mode=base.mode,
            curve=base.curve,
            protocol=base.protocol,
            library=base.library,
            usage_state=combined_state,
            confidence=combined_confidence,
            evidence=combined_evidence,
            location=base.location,
            implementation=base.implementation,
            context=base.context,
            operation_type=base.operation_type,
            function=base.function,
            dependency_only=combined_dependency_only,
        )

    def scan_and_emit_cir(
        self,
        target: Path | str,
        scanner_names: Optional[list[str]] = None,
        target_name: Optional[str] = None,
        **kwargs
    ) -> CIRDocument:
        findings = self.scan(target, scanner_names, **kwargs)

        cir = self._emit_cir(findings, target, target_name)

        return cir

    def _emit_cir(
        self,
        findings: list[ScannerFinding],
        target: Path | str,
        target_name: Optional[str] = None
    ) -> CIRDocument:
        scan_id = f"scan:{uuid.uuid4().hex[:16]}"
        started_at = datetime.now(timezone.utc)
        finished_at = datetime.now(timezone.utc)

        target_str = target_name or str(target)

        assets: dict[str, CryptoAsset] = {}
        operations: dict[str, CryptoOperation] = {}
        graph_nodes: dict[str, GraphNode] = {}
        graph_edges: list[GraphEdge] = []

        for finding in findings:
            asset = finding.to_asset()
            if asset.asset_id not in assets:
                assets[asset.asset_id] = asset
                self._add_asset_to_graph(asset, graph_nodes, graph_edges, target_str)

            operation = finding.to_operation(asset.asset_id)
            if operation and operation.operation_id not in operations:
                operations[operation.operation_id] = operation
                self._add_operation_to_graph(operation, graph_nodes, graph_edges, asset.asset_id)

        cir = CIRDocument(
            cir_version="0.1",
            scan_id=scan_id,
            target=target_str,
            started_at=started_at,
            finished_at=finished_at,
            tool_versions=self._get_tool_versions(),
            registry_version=get_registry_version(),
            assets=list(assets.values()),
            operations=list(operations.values()),
            graph=Graph(nodes=list(graph_nodes.values()), edges=graph_edges),
        )

        return cir

    def _add_asset_to_graph(
        self,
        asset: CryptoAsset,
        graph_nodes: dict[str, GraphNode],
        graph_edges: list[GraphEdge],
        target_str: str
    ) -> None:
        asset_node = GraphNode(id=asset.asset_id, kind=GraphNodeKind.ASSET, label=asset.canonical, ref=asset.asset_id)
        graph_nodes[asset.asset_id] = asset_node

        if asset.location and asset.location.file:
            file_id = _deterministic_hash(asset.location.file, "file")
            if file_id not in graph_nodes:
                graph_nodes[file_id] = GraphNode(id=file_id, kind=GraphNodeKind.FILE, label=asset.location.file, ref=asset.location.file)
            graph_edges.append(GraphEdge(**{"from": file_id, "to": asset.asset_id, "relationship": GraphRelationship.CONTAINS}))

        if asset.implementation and asset.implementation.library:
            lib_id = _deterministic_hash(asset.implementation.library, "library")
            if lib_id not in graph_nodes:
                graph_nodes[lib_id] = GraphNode(id=lib_id, kind=GraphNodeKind.LIBRARY, label=asset.implementation.library, ref=asset.implementation.library)
            graph_edges.append(GraphEdge(**{"from": asset.asset_id, "to": lib_id, "relationship": GraphRelationship.USES}))

    def _add_operation_to_graph(
        self,
        operation: CryptoOperation,
        graph_nodes: dict[str, GraphNode],
        graph_edges: list[GraphEdge],
        asset_id: str
    ) -> None:
        op_node = GraphNode(id=operation.operation_id, kind=GraphNodeKind.OPERATION, label=operation.operation_type.value, ref=operation.operation_id)
        graph_nodes[operation.operation_id] = op_node

        graph_edges.append(GraphEdge(**{"from": operation.operation_id, "to": asset_id, "relationship": GraphRelationship.USES}))

        if operation.location and operation.location.file:
            file_id = _deterministic_hash(operation.location.file, "file")
            if file_id not in graph_nodes:
                graph_nodes[file_id] = GraphNode(id=file_id, kind=GraphNodeKind.FILE, label=operation.location.file, ref=operation.location.file)
            graph_edges.append(GraphEdge(**{"from": file_id, "to": operation.operation_id, "relationship": GraphRelationship.CONTAINS}))

    def _get_tool_versions(self) -> dict[str, str]:
        versions = {}
        for name, scanner in self._scanners.items():
            versions[name] = scanner.get_tool_version()
        return versions

    def validate_cir(self, cir: CIRDocument) -> bool:
        try:
            cir.model_validate(cir.model_dump())
            return True
        except Exception:
            return False


def create_discovery_engine(scanners: Optional[list[str]] = None) -> DiscoveryEngine:
    return DiscoveryEngine(enabled_scanners=scanners)