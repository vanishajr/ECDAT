from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class GenericConfigScanner(Scanner[ScannerFinding]):
    name = "config-generic"
    version = "0.1.0"

    def __init__(self) -> None:
        self._tls_keywords = [
            "tls", "ssl", "https", "cert", "key", "ca", "crt", "pem", "der",
            "p12", "pfx", "jks", "keystore", "truststore", "cipher", "protocol"
        ]

    def can_scan_file(self, path: Path) -> bool:
        suffixes = (".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".config", ".properties")
        if path.suffix in suffixes:
            return True
        # Phase 5: dot-env files carry TLS/service bindings but have no
        # usable suffix (``Path(".env").suffix == ""``).
        name = path.name.lower()
        return name.startswith(".env") or name.endswith(".env")

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return "generic-config-parser"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        findings: list[ScannerFinding] = []

        if target_path.is_file():
            if self.can_scan_file(target_path):
                findings.extend(self._scan_file(target_path))
        else:
            for conf_file in target_path.rglob("*"):
                if self.can_scan_file(conf_file):
                    findings.extend(self._scan_file(conf_file))

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _scan_file(self, file_path: Path) -> list[ScannerFinding]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        findings: list[ScannerFinding] = []

        if file_path.suffix == ".json":
            findings.extend(self._scan_json(content, file_path))
        elif file_path.suffix in (".yaml", ".yml"):
            findings.extend(self._scan_yaml(content, file_path))
        elif file_path.suffix == ".toml":
            findings.extend(self._scan_toml(content, file_path))
        else:
            findings.extend(self._scan_text(content, file_path))

        return findings

    def _scan_json(self, content: str, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            data = json.loads(content)
        except Exception:
            return findings

        findings.extend(self._scan_dict(data, file_path, "json"))
        return findings

    def _scan_yaml(self, content: str, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            import yaml
            data = yaml.safe_load(content)
        except Exception:
            return findings

        if isinstance(data, dict):
            findings.extend(self._scan_dict(data, file_path, "yaml"))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    findings.extend(self._scan_dict(item, file_path, "yaml"))

        return findings

    def _scan_toml(self, content: str, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            import tomli
            data = tomli.loads(content)
        except Exception:
            return findings

        findings.extend(self._scan_dict(data, file_path, "toml"))
        return findings

    def _scan_text(self, content: str, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        lines = content.splitlines()

        for i, line in enumerate(lines):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith(("#", ";", "//")):
                continue

            line_lower = line_stripped.lower()
            for kw in self._tls_keywords:
                if kw in line_lower and "=" in line_stripped:
                    key, _, value = line_stripped.partition("=")
                    canonical = self._guess_canonical(key, value)
                    if canonical:
                        findings.append(ScannerFinding(
                            canonical=canonical,
                            original=key.strip(),
                            usage_state=UsageState.PROVIDED_ONLY,
                            confidence=0.3,
                            evidence=[create_evidence_signal(
                                tool="config-generic",
                                detail=f"Config line {i+1}: {key.strip()}={value.strip()[:100]}",
                                confidence=0.3,
                                snippet=line_stripped[:200],
                            )],
                            location=Location(file=str(file_path), line=i + 1),
                            implementation=Implementation(library="generic", provider=file_path.suffix[1:]),
                            context=Context(exposure=Exposure.INTERNAL),
                        ))
                    break

        return findings

    def _scan_dict(self, data: dict, file_path: Path, format_type: str, path_prefix: str = "") -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        for key, value in data.items():
            current_path = f"{path_prefix}.{key}" if path_prefix else key

            if isinstance(value, dict):
                findings.extend(self._scan_dict(value, file_path, format_type, current_path))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        findings.extend(self._scan_dict(item, file_path, format_type, f"{current_path}[{i}]"))
                    elif isinstance(item, str):
                        self._check_string_value(current_path, item, file_path, findings)
            elif isinstance(value, str):
                self._check_string_value(current_path, value, file_path, findings)

        return findings

    def _check_string_value(self, path: str, value: str, file_path: Path, findings: list[ScannerFinding]) -> None:
        value_lower = value.lower()
        path_lower = path.lower()

        crypto_indicators = ["tls", "ssl", "https", "cert", "key", "ca", "crt", "pem", "der", "p12", "pfx", "jks", "keystore", "truststore", "cipher", "protocol"]

        if any(kw in path_lower for kw in crypto_indicators) or any(kw in value_lower for kw in crypto_indicators):
            canonical = self._guess_canonical(path, value)
            if canonical:
                findings.append(ScannerFinding(
                    canonical=canonical,
                    original=path,
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=0.35,
                    evidence=[create_evidence_signal(
                        tool="config-generic",
                        detail=f"{path} = {value[:100]}",
                        confidence=0.35,
                        snippet=f"{path} = {value[:200]}",
                    )],
                    location=Location(file=str(file_path), uri=f"{file_path.suffix[1:]}:{path}"),
                    implementation=Implementation(library="generic", provider=file_path.suffix[1:]),
                    context=Context(exposure=Exposure.INTERNAL),
                ))

    def _guess_canonical(self, key: str, value: str) -> str | None:
        key_lower = key.lower()
        value_lower = value.lower()

        if "cipher" in key_lower:
            return "TLS"
        if "protocol" in key_lower or "version" in key_lower:
            if "1.3" in value_lower:
                return "TLS1.3"
            if "1.2" in value_lower:
                return "TLS1.2"
            if "1.1" in value_lower or "1.0" in value_lower:
                return "TLS1.2"
            return "TLS"
        if "cert" in key_lower or "crt" in key_lower or "pem" in key_lower:
            return "X.509"
        if "key" in key_lower and "private" in key_lower:
            return "Private Key"
        if "key" in key_lower:
            return "Private Key"
        if "ca" in key_lower:
            return "X.509"
        if "keystore" in key_lower or "truststore" in key_lower or "jks" in key_lower or "p12" in key_lower or "pfx" in key_lower:
            return "KeyStore"

        return None