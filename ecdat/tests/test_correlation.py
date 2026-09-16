"""
Regression tests for DiscoveryEngine._correlate_findings proximity-based behavior.

These tests document the CURRENT behavior of the 5-line proximity window correlation.
This is a known limitation (tracked as future work P5) - two unrelated same-algorithm
findings within 5 lines get merged. These tests ensure this behavior is explicitly
tested and documented, not silently changed.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from ecdat.scanners.discovery import DiscoveryEngine
from ecdat.scanners.base import ScannerFinding
from ecdat.core.cir_models import (
    Location,
    Implementation,
    Context,
    UsageState,
    OperationType,
    Exposure,
    EvidenceSignal,
)
from ecdat.scanners.base import normalize_finding


class MockScannerFinding:
    """Helper to create test findings with controlled properties."""
    
    @staticmethod
    def create(canonical: str, file: str, line: int, scanner_name: str, 
               function: str = None, confidence: float = 0.8):
        return ScannerFinding(
            canonical=canonical,
            original=canonical,
            usage_state=UsageState.CONFIRMED,
            confidence=confidence,
            evidence=[EvidenceSignal(
                tool=f"{scanner_name}:test",
                detail=f"{scanner_name} found {canonical}",
                confidence=confidence,
                snippet=f"test snippet for {canonical}"
            )],
            location=Location(file=file, line=line, function=function),
            implementation=Implementation(library="test", api=canonical),
            context=Context(exposure=Exposure.INTERNAL),
            operation_type=OperationType.ENCRYPT,
            function=function,
        )


class TestCorrelationBehavior:
    """Test the proximity-based correlation in DiscoveryEngine._correlate_findings."""
    
    def test_same_file_different_algorithms_not_merged(self):
        """Findings for different algorithms in same file should NOT be merged."""
        findings = [
            MockScannerFinding.create("AES-256-GCM", "test.py", 10, "scanner1"),
            MockScannerFinding.create("RSA", "test.py", 12, "scanner2"),
        ]
        
        engine = DiscoveryEngine(enabled_scanners=[])
        correlated = engine._correlate_findings(findings)
        
        assert len(correlated) == 2
        assert {f.canonical for f in correlated} == {"AES-256-GCM", "RSA"}
    
    def test_same_algorithm_different_files_not_merged(self):
        """Findings for same algorithm in different files should NOT be merged."""
        findings = [
            MockScannerFinding.create("AES-256-GCM", "file1.py", 10, "scanner1"),
            MockScannerFinding.create("AES-256-GCM", "file2.py", 10, "scanner2"),
        ]
        
        engine = DiscoveryEngine(enabled_scanners=[])
        correlated = engine._correlate_findings(findings)
        
        assert len(correlated) == 2
    
    def test_different_scanners_within_5_lines_merged(self):
        """Findings from different scanners for same algorithm within 5 lines SHOULD be merged."""
        findings = [
            MockScannerFinding.create("AES-256-GCM", "test.py", 10, "scanner1"),
            MockScannerFinding.create("AES-256-GCM", "test.py", 13, "scanner2"),  # 3 lines apart
        ]
        
        engine = DiscoveryEngine(enabled_scanners=[])
        correlated = engine._correlate_findings(findings)
        
        # Should be merged into 1 finding
        assert len(correlated) == 1
        assert correlated[0].canonical == "AES-256-GCM"
        # Evidence from both scanners should be combined
        assert len(correlated[0].evidence) == 2
        tools = {e.tool for e in correlated[0].evidence}
        assert "scanner1:test" in tools
        assert "scanner2:test" in tools
    
    def test_different_scanners_outside_5_lines_NOT_merged(self):
        """Findings from different scanners for same algorithm >5 lines apart should NOT be merged."""
        findings = [
            MockScannerFinding.create("AES-256-GCM", "test.py", 10, "scanner1"),
            MockScannerFinding.create("AES-256-GCM", "test.py", 16, "scanner2"),  # 6 lines apart
        ]
        
        engine = DiscoveryEngine(enabled_scanners=[])
        correlated = engine._correlate_findings(findings)
        
        # Should NOT be merged - 2 findings remain
        assert len(correlated) == 2
    
    def test_same_scanner_same_function_within_5_lines_merged(self):
        """Findings from SAME scanner in same function within 5 lines SHOULD be merged."""
        findings = [
            MockScannerFinding.create("AES-256-GCM", "test.py", 10, "scanner1", function="encrypt_data"),
            MockScannerFinding.create("AES-256-GCM", "test.py", 13, "scanner1", function="encrypt_data"),
        ]
        
        engine = DiscoveryEngine(enabled_scanners=[])
        correlated = engine._correlate_findings(findings)
        
        assert len(correlated) == 1
    
    def test_same_scanner_different_function_within_5_lines_NOT_merged(self):
        """Findings from SAME scanner in DIFFERENT functions within 5 lines should NOT be merged."""
        findings = [
            MockScannerFinding.create("AES-256-GCM", "test.py", 10, "scanner1", function="func1"),
            MockScannerFinding.create("AES-256-GCM", "test.py", 13, "scanner1", function="func2"),
        ]
        
        engine = DiscoveryEngine(enabled_scanners=[])
        correlated = engine._correlate_findings(findings)
        
        # Different functions, so NOT merged even though same scanner and within 5 lines
        assert len(correlated) == 2
    
    def test_same_scanner_no_function_within_5_lines_NOT_merged(self):
        """Findings from SAME scanner with NO function info within 5 lines should NOT be merged."""
        findings = [
            MockScannerFinding.create("AES-256-GCM", "test.py", 10, "scanner1", function=None),
            MockScannerFinding.create("AES-256-GCM", "test.py", 13, "scanner1", function=None),
        ]
        
        engine = DiscoveryEngine(enabled_scanners=[])
        correlated = engine._correlate_findings(findings)
        
        # No function info, so NOT merged (requires same function for same-scanner merge)
        assert len(correlated) == 2
    
    def test_known_limitation_unrelated_findings_4_lines_apart_get_merged(self):
        """
        KNOWN LIMITATION: Two unrelated same-algorithm findings from different scanners
        4 lines apart get merged even if they're logically distinct.
        
        This is the documented P5 roadmap item - context-aware cross-file identity
        correlation is not implemented. This test documents the current behavior
        so it doesn't change silently.
        """
        # Simulate: scanner1 finds AES-GCM on line 10 (actual encrypt call)
        # scanner2 finds AES-GCM on line 13 (actually a config constant, but detected)
        findings = [
            MockScannerFinding.create("AES-256-GCM", "test.py", 10, "source:ast"),
            MockScannerFinding.create("AES-256-GCM", "test.py", 13, "config:generic"),  # 3 lines apart
        ]
        
        engine = DiscoveryEngine(enabled_scanners=[])
        correlated = engine._correlate_findings(findings)
        
        # CURRENT BEHAVIOR: These get merged (known limitation)
        assert len(correlated) == 1
        assert correlated[0].canonical == "AES-256-GCM"
        # This is the known limitation - they're merged despite being potentially unrelated
        # TODO(P5): Replace proximity-based with context-aware identity correlation
    
    def test_adjacent_findings_not_transitive(self):
        """
        Test that merging is only pairwise-adjacent, not transitive.
        
        A(10) merges with B(13) -> AB
        C(16) is 6 lines from A(10), 3 from B(13)
        But since AB is at line 10 (first finding's line), C is 6 lines from AB -> NOT merged
        
        This documents the current non-transitive behavior.
        """
        findings = [
            MockScannerFinding.create("AES-256-GCM", "test.py", 10, "scanner1"),
            MockScannerFinding.create("AES-256-GCM", "test.py", 13, "scanner2"),  # 3 from A
            MockScannerFinding.create("AES-256-GCM", "test.py", 16, "scanner3"),  # 3 from B, 6 from A
        ]
        
        engine = DiscoveryEngine(enabled_scanners=[])
        correlated = engine._correlate_findings(findings)
        
        # A and B merge (3 lines apart, different scanners)
        # C is 6 lines from merged AB (which keeps line 10), so NOT merged
        assert len(correlated) == 2
        # First merged finding has evidence from scanner1 and scanner2
        merged = [f for f in correlated if len(f.evidence) == 2][0]
        tools = {e.tool for e in merged.evidence}
        assert "scanner1:test" in tools
        assert "scanner2:test" in tools
        # Second finding is scanner3 alone
        solo = [f for f in correlated if len(f.evidence) == 1][0]
        assert "scanner3:test" in {e.tool for e in solo.evidence}
    
    def test_confidence_max_used_in_merge(self):
        """When merging, max confidence should be used."""
        findings = [
            MockScannerFinding.create("AES-256-GCM", "test.py", 10, "scanner1", confidence=0.6),
            MockScannerFinding.create("AES-256-GCM", "test.py", 13, "scanner2", confidence=0.9),
        ]
        
        engine = DiscoveryEngine(enabled_scanners=[])
        correlated = engine._correlate_findings(findings)
        
        assert len(correlated) == 1
        assert correlated[0].confidence == 0.9  # max of 0.6 and 0.9
    
    def test_highest_usage_state_used_in_merge(self):
        """When merging, highest usage state should be used (Confirmed > Probable > Possible > ProvidedOnly)."""
        findings = [
            MockScannerFinding.create("AES-256-GCM", "test.py", 10, "scanner1"),
            MockScannerFinding.create("AES-256-GCM", "test.py", 13, "scanner2"),
        ]
        # Manually set different usage states
        findings[0].usage_state = UsageState.PROBABLE
        findings[1].usage_state = UsageState.CONFIRMED
        
        engine = DiscoveryEngine(enabled_scanners=[])
        correlated = engine._correlate_findings(findings)
        
        assert len(correlated) == 1
        assert correlated[0].usage_state == UsageState.CONFIRMED
    
    def test_provided_only_not_upgraded_by_confidence(self):
        """
        ProvidedOnly from same scanner with no function info does NOT merge.
        
        The current logic only merges same-scanner findings if they're in the
        SAME function. Since these have function=None, they remain separate.
        This is the correct current behavior.
        """
        findings = [
            MockScannerFinding.create("AES-256-GCM", "test.py", 10, "dependency:requirements"),
            MockScannerFinding.create("AES-256-GCM", "test.py", 13, "dependency:requirements"),
        ]
        findings[0].usage_state = UsageState.PROVIDED_ONLY
        findings[1].usage_state = UsageState.PROVIDED_ONLY
        
        engine = DiscoveryEngine(enabled_scanners=[])
        correlated = engine._correlate_findings(findings)
        
        # Same scanner, no function -> NOT merged
        assert len(correlated) == 2
        for f in correlated:
            assert f.usage_state == UsageState.PROVIDED_ONLY
    
    def test_provided_only_different_scanners_merged(self):
        """
        ProvidedOnly from DIFFERENT scanners within 5 lines DOES merge.
        
        The usage state of the merged result should be the highest (ProvidedOnly
        stays ProvidedOnly since both are ProvidedOnly).
        """
        findings = [
            MockScannerFinding.create("AES-256-GCM", "test.py", 10, "dependency:requirements"),
            MockScannerFinding.create("AES-256-GCM", "test.py", 13, "config:generic"),  # Different scanner
        ]
        findings[0].usage_state = UsageState.PROVIDED_ONLY
        findings[1].usage_state = UsageState.PROVIDED_ONLY
        
        engine = DiscoveryEngine(enabled_scanners=[])
        correlated = engine._correlate_findings(findings)
        
        # Different scanners within 5 lines -> merged
        assert len(correlated) == 1
        assert correlated[0].usage_state == UsageState.PROVIDED_ONLY


if __name__ == "__main__":
    pytest.main([__file__, "-v"])