from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, ScannerRegistry
from ecdat.scanners.config.nginx_scanner import NginxScanner
from ecdat.scanners.config.apache_scanner import ApacheScanner
from ecdat.scanners.config.envoy_scanner import EnvoyScanner
from ecdat.scanners.config.openssl_scanner import OpenSSLConfigScanner
from ecdat.scanners.config.kubernetes_scanner import KubernetesScanner
from ecdat.scanners.config.terraform_scanner import TerraformScanner
from ecdat.scanners.config.generic_scanner import GenericConfigScanner
from ecdat.scanners.config.dockerfile_scanner import DockerfileScanner
from ecdat.scanners.config.service_context import attach_service_context


class ConfigScanner(Scanner[ScannerFinding]):
    name = "config"
    version = "0.1.0"

    def __init__(self) -> None:
        self._scanners: list[Scanner] = [
            NginxScanner(),
            ApacheScanner(),
            EnvoyScanner(),
            OpenSSLConfigScanner(),
            KubernetesScanner(),
            TerraformScanner(),
            GenericConfigScanner(),
            DockerfileScanner(),
        ]

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return f"config-v{self.version}"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        all_findings: list[ScannerFinding] = []

        if target_path.is_file():
            for scanner in self._scanners:
                if scanner.can_scan_file(target_path):
                    try:
                        findings = scanner.scan(target_path, **kwargs)
                        all_findings.extend(findings)
                    except Exception:
                        continue
        else:
            for scanner in self._scanners:
                try:
                    findings = scanner.scan(target_path, **kwargs)
                    all_findings.extend(findings)
                except Exception:
                    continue

        # Phase 5: graph-linkable service context (service, listeners,
        # cert/key/KMS refs) derived per file; additive, never drops.
        try:
            attach_service_context(all_findings)
        except Exception:
            pass
        return all_findings


ScannerRegistry.register(ConfigScanner())