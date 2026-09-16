from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from enum import Enum

from ecdat.scanners.base import ScannerFinding
from ecdat.core.cir_models import UsageState, OperationType, Location, Implementation, Context, Exposure, EvidenceSignal
from ecdat.core.signature_registry import normalize_algorithm, get_category


class MatchStrategy(Enum):
    EXACT = "exact"
    PROXIMITY = "proximity"
    SAME_FILE = "same_file"


@dataclass
class ExpectedFinding:
    canonical: str
    original: Optional[str] = None
    key_size: Optional[int] = None
    mode: Optional[str] = None
    curve: Optional[str] = None
    protocol: Optional[str] = None
    library: Optional[str] = None
    usage_state: UsageState = UsageState.CONFIRMED
    confidence: Optional[float] = None
    operation_type: Optional[OperationType] = None
    function: Optional[str] = None
    location: Optional[Location] = None
    match_strategy: MatchStrategy = MatchStrategy.EXACT
    proximity_lines: int = 5

    def matches(self, finding: ScannerFinding) -> bool:
        if self.canonical != finding.canonical:
            return False
        
        if self.original and self.original != finding.original:
            return False
        
        if self.key_size and self.key_size != finding.key_size:
            return False
        
        if self.mode and self.mode != finding.mode:
            return False
        
        if self.curve and self.curve != finding.curve:
            return False
        
        if self.protocol and self.protocol != finding.protocol:
            return False
        
        if self.library and self.library != finding.library:
            return False
        
        if self.usage_state != finding.usage_state:
            return False
        
        if self.confidence and finding.confidence < self.confidence - 0.15:
            return False
        
        if self.operation_type and self.operation_type != finding.operation_type:
            return False
        
        if self.function and self.function != finding.function:
            return False
        
        if self.location:
            if self.location.file and finding.location:
                def normalize_path(path: str) -> str:
                    path = path.replace('\\', '/')
                    idx = path.find('ecdat/')
                    if idx >= 0:
                        return path[idx + len('ecdat/'):]
                    return path
                
                expected_file = normalize_path(self.location.file)
                actual_file = normalize_path(finding.location.file)
                if expected_file != actual_file:
                    return False
            if self.location.line and finding.location and finding.location.line:
                if self.match_strategy == MatchStrategy.PROXIMITY:
                    if abs(self.location.line - finding.location.line) > self.proximity_lines:
                        return False
                elif self.match_strategy == MatchStrategy.EXACT:
                    if self.location.line != finding.location.line:
                        return False
            if self.location.function and finding.location:
                if self.location.function != finding.location.function:
                    return False
        
        return True


@dataclass
class FixtureGroundTruth:
    fixture_path: str
    scanner_type: str
    expected_findings: list[ExpectedFinding] = field(default_factory=list)
    negative_patterns: list[str] = field(default_factory=list)


class GroundTruthRegistry:
    def __init__(self):
        self.fixtures: dict[str, FixtureGroundTruth] = {}
    
    def register(self, fixture: FixtureGroundTruth):
        self.fixtures[fixture.fixture_path] = fixture
    
    def get(self, path: str) -> Optional[FixtureGroundTruth]:
        return self.fixtures.get(path)
    
    def get_by_scanner(self, scanner_type: str) -> list[FixtureGroundTruth]:
        return [f for f in self.fixtures.values() if f.scanner_type == scanner_type]


@dataclass
class EvaluationResult:
    scanner_name: str
    fixture_path: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    matched_findings: list[tuple[ExpectedFinding, ScannerFinding]] = field(default_factory=list)
    unmatched_expected: list[ExpectedFinding] = field(default_factory=list)
    unmatched_actual: list[ScannerFinding] = field(default_factory=list)
    true_positive_details: list[dict] = field(default_factory=list)
    false_positive_details: list[dict] = field(default_factory=list)
    false_negative_details: list[dict] = field(default_factory=list)
    
    @property
    def precision(self) -> float:
        if self.true_positives + self.false_positives == 0:
            return 1.0
        return self.true_positives / (self.true_positives + self.false_positives)
    
    @property
    def recall(self) -> float:
        if self.true_positives + self.false_negatives == 0:
            return 1.0
        return self.true_positives / (self.true_positives + self.false_negatives)
    
    @property
    def f1(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)
    
    @property
    def false_discovery_rate(self) -> float:
        """False Discovery Rate = FP / (TP + FP) = 1 - Precision"""
        total_positives = self.false_positives + self.true_positives
        if total_positives == 0:
            return 0.0
        return self.false_positives / total_positives


class EvaluationEngine:
    def __init__(self, registry: GroundTruthRegistry):
        self.registry = registry
    
    def evaluate(self, findings: list[ScannerFinding], fixture_path: str, scanner_name: str) -> EvaluationResult:
        # Normalize path separators to forward slashes for consistent lookup
        normalized_fixture_path = fixture_path.replace('\\', '/')
        ground_truth = self.registry.get(normalized_fixture_path)
        if not ground_truth:
            return EvaluationResult(
                scanner_name=scanner_name,
                fixture_path=fixture_path,
                true_positives=0,
                false_positives=len(findings),
                false_negatives=0,
                unmatched_actual=findings,
            )
        
        expected = ground_truth.expected_findings[:]
        actual = findings[:]
        matched_pairs = []
        
        for exp in expected[:]:
            for act in actual[:]:
                if exp.matches(act):
                    matched_pairs.append((exp, act))
                    expected.remove(exp)
                    actual.remove(act)
                    break
        
        # Check negative patterns: findings matching negative patterns are expected FPs
        # and should not count against precision
        negative_patterns = ground_truth.negative_patterns or []
        if negative_patterns:
            new_actual = []
            for act in actual:
                is_expected_fp = False
                for pattern in negative_patterns:
                    if pattern.lower() in act.canonical.lower() or \
                       (act.original and pattern.lower() in act.original.lower()) or \
                       (act.library and pattern.lower() in act.library.lower()):
                        is_expected_fp = True
                        result.false_positive_details.append({
                            "actual": self._finding_to_dict(act),
                            "reason": f"Matches negative pattern: {pattern}",
                        })
                        break
                if not is_expected_fp:
                    new_actual.append(act)
            actual = new_actual
        
        result = EvaluationResult(
            scanner_name=scanner_name,
            fixture_path=fixture_path,
            true_positives=len(matched_pairs),
            false_positives=len(actual),
            false_negatives=len(expected),
            matched_findings=matched_pairs,
            unmatched_expected=expected,
            unmatched_actual=actual,
        )
        
        for exp, act in matched_pairs:
            result.true_positive_details.append({
                "expected": self._finding_to_dict(exp),
                "actual": self._finding_to_dict(act),
            })
        
        for act in actual:
            result.false_positive_details.append({
                "actual": self._finding_to_dict(act),
                "reason": "No matching expected finding",
            })
        
        for exp in expected:
            result.false_negative_details.append({
                "expected": self._finding_to_dict(exp),
                "reason": "Expected finding not detected",
            })
        
        return result
    
    def _finding_to_dict(self, finding) -> dict:
        return {
            "canonical": finding.canonical,
            "original": finding.original,
            "key_size": finding.key_size,
            "mode": finding.mode,
            "curve": finding.curve,
            "protocol": finding.protocol,
            "library": finding.library,
            "usage_state": finding.usage_state.value if hasattr(finding.usage_state, 'value') else str(finding.usage_state),
            "confidence": finding.confidence,
            "operation_type": finding.operation_type.value if finding.operation_type and hasattr(finding.operation_type, 'value') else str(finding.operation_type) if finding.operation_type else None,
            "function": finding.function,
            "location": {
                "file": finding.location.file if finding.location else None,
                "line": finding.location.line if finding.location else None,
                "function": finding.location.function if finding.location else None,
            } if finding.location else None,
        }


def load_ground_truth_from_json(path: Path) -> GroundTruthRegistry:
    registry = GroundTruthRegistry()
    if not path.exists():
        return registry
    
    with open(path) as f:
        data = json.load(f)
    
    for fixture_data in data.get("fixtures", []):
        expected = []
        for exp_data in fixture_data.get("expected_findings", []):
            location = None
            if exp_data.get("location"):
                loc_data = exp_data["location"]
                location = Location(
                    file=loc_data.get("file"),
                    line=loc_data.get("line"),
                    function=loc_data.get("function"),
                )
            
            expected.append(ExpectedFinding(
                canonical=exp_data["canonical"],
                original=exp_data.get("original"),
                key_size=exp_data.get("key_size"),
                mode=exp_data.get("mode"),
                curve=exp_data.get("curve"),
                protocol=exp_data.get("protocol"),
                library=exp_data.get("library"),
                usage_state=UsageState(exp_data.get("usage_state", "Confirmed")),
                confidence=exp_data.get("confidence"),
                operation_type=OperationType(exp_data["operation_type"]) if exp_data.get("operation_type") else None,
                function=exp_data.get("function"),
                location=location,
                match_strategy=MatchStrategy(exp_data.get("match_strategy", "exact")),
                proximity_lines=exp_data.get("proximity_lines", 5),
            ))
        
        fixture = FixtureGroundTruth(
            fixture_path=fixture_data["fixture_path"],
            scanner_type=fixture_data["scanner_type"],
            expected_findings=expected,
            negative_patterns=fixture_data.get("negative_patterns", []),
        )
        registry.register(fixture)
    
    return registry


def export_evaluation_results(results: list[EvaluationResult], output_path: Path):
    data = {
        "summary": {
            "total_scanners": len(set(r.scanner_name for r in results)),
            "total_fixtures": len(results),
            "overall_tp": sum(r.true_positives for r in results),
            "overall_fp": sum(r.false_positives for r in results),
            "overall_fn": sum(r.false_negatives for r in results),
        },
        "results": []
    }
    
    for r in results:
        data["results"].append({
            "scanner": r.scanner_name,
            "fixture": r.fixture_path,
            "tp": r.true_positives,
            "fp": r.false_positives,
            "fn": r.false_negatives,
            "precision": round(r.precision, 4),
            "recall": round(r.recall, 4),
            "f1": round(r.f1, 4),
            "fpr": round(r.false_discovery_rate, 4),
            "true_positives": r.true_positive_details,
            "false_positives": r.false_positive_details,
            "false_negatives": r.false_negative_details,
        })
    
    output_path.write_text(json.dumps(data, indent=2))