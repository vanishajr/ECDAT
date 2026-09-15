"""Test for ContainerScanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from ecdat.scanners.container import ContainerScanner
from ecdat.core.cir_models import UsageState


class TestContainerScanner:
    @pytest.fixture
    def container_scanner(self):
        return ContainerScanner()

    def test_container_scanner_available(self, container_scanner):
        # May not be available if docker/syft not installed
        # Just verify it doesn't crash
        available = container_scanner.is_available()
        assert isinstance(available, bool)

    def test_scan_nonexistent_image(self, container_scanner):
        findings = container_scanner.scan("docker://nonexistent:image")
        assert findings == []

    def test_scan_invalid_target(self, container_scanner):
        findings = container_scanner.scan("not-a-valid-target")
        assert findings == []

    def test_scan_directory(self, container_scanner, tmp_path):
        # Create a directory with some test files
        (tmp_path / "test.txt").write_text("hello")
        findings = container_scanner.scan(tmp_path)
        # Should not crash
        assert isinstance(findings, list)