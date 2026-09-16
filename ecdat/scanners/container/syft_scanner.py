from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only
from ecdat.scanners.dependency.crypto_packages import CRYPTO_PACKAGES


class SyftScanner(Scanner[ScannerFinding]):
    name = "container-syft"
    version = "0.1.0"

    def __init__(self) -> None:
        self._syft_available = self._check_syft()

    def _check_syft(self) -> bool:
        try:
            result = subprocess.run(
                ["syft", "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def is_available(self) -> bool:
        return self._syft_available

    def get_tool_version(self) -> str:
        try:
            result = subprocess.run(
                ["syft", "version", "-o", "json"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return f"syft-{data.get('version', 'unknown')}"
        except Exception:
            pass
        return "syft-unknown"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        if not self._syft_available:
            return []

        target_str = str(target)
        findings: list[ScannerFinding] = []

        try:
            cmd = ["syft", "scan", "-o", "json", target_str]
            if "dir:" in target_str or Path(target_str).is_dir():
                cmd = ["syft", "scan", "-o", "json", f"dir:{target_str}"]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if result.returncode not in (0, 1):
                return findings

            data = json.loads(result.stdout)
            findings = self._parse_syft_output(data, target_str)
        except Exception:
            pass

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _parse_syft_output(self, data: dict, target_ref: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        for artifact in data.get("artifacts", []):
            name = artifact.get("name", "")
            version = artifact.get("version", "")
            pkg_type = artifact.get("type", "").lower()
            locations = artifact.get("locations", [])

            ecosystem = self._map_syft_type(pkg_type)
            if not ecosystem:
                continue

            crypto_info = CRYPTO_PACKAGES.get(ecosystem, {}).get(name.lower())
            if not crypto_info:
                for pattern, info in CRYPTO_PACKAGES.get(ecosystem, {}).items():
                    if pattern.lower() in name.lower():
                        crypto_info = info
                        break

            if not crypto_info:
                continue

            canonical = crypto_info.get("canonical", name)
            category = crypto_info.get("category", "library")

            if is_library_only(canonical) or category == "library":
                usage_state = UsageState.PROVIDED_ONLY
                confidence = 0.35
            else:
                usage_state = UsageState.PROVIDED_ONLY
                confidence = 0.4

            location_str = ""
            if locations:
                location_str = locations[0].get("path", "")

            findings.append(ScannerFinding(
                canonical=canonical,
                original=name,
                key_size=crypto_info.get("key_size"),
                mode=crypto_info.get("mode"),
                curve=crypto_info.get("curve"),
                library=name,
                usage_state=usage_state,
                confidence=confidence,
                evidence=[create_evidence_signal(
                    tool="container-syft",
                    detail=f"Package: {name}@{version} ({pkg_type}) at {location_str}",
                    confidence=confidence,
                    snippet=f"{name}@{version} in {target_ref}",
                )],
                location=Location(file=location_str or target_ref, uri=f"syft:{pkg_type}:{name}"),
                implementation=Implementation(library=name, version=version, provider=ecosystem),
                context=Context(exposure=Exposure.INTERNAL),
            ))

        return findings

    def _map_syft_type(self, syft_type: str) -> str | None:
        mapping = {
            "npm": "npm",
            "yarn": "npm",
            "pnpm": "npm",
            "pypi": "pypi",
            "poetry": "pypi",
            "pip": "pypi",
            "cargo": "cargo",
            "go": "go",
            "gomod": "go",
            "maven": "maven",
            "gradle": "gradle",
            "gem": "rubygems",
            "bundler": "rubygems",
            "composer": "composer",
            "apk": "apk",
            "dpkg": "dpkg",
            "rpm": "rpm",
            "java-archive": "maven",
            "jenkins-plugin": "maven",
        }
        return mapping.get(syft_type.lower())