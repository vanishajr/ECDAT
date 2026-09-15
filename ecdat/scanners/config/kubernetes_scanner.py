from __future__ import annotations

import yaml
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class KubernetesScanner(Scanner[ScannerFinding]):
    name = "config-kubernetes"
    version = "0.1.0"

    def __init__(self) -> None:
        pass

    def can_scan_file(self, path: Path) -> bool:
        name = path.name.lower()
        return name.endswith((".yaml", ".yml")) and any(kw in name for kw in ["k8s", "kube", "deployment", "service", "ingress", "secret", "cert"])

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return "kubernetes-config-parser"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        findings: list[ScannerFinding] = []

        if target_path.is_file():
            if self.can_scan_file(target_path):
                findings.extend(self._scan_file(target_path))
        else:
            for yaml_file in target_path.rglob("*.yaml"):
                if self.can_scan_file(yaml_file):
                    findings.extend(self._scan_file(yaml_file))
            for yml_file in target_path.rglob("*.yml"):
                if self.can_scan_file(yml_file):
                    findings.extend(self._scan_file(yml_file))

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _scan_file(self, file_path: Path) -> list[ScannerFinding]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        findings: list[ScannerFinding] = []

        try:
            docs = list(yaml.safe_load_all(content))
        except Exception:
            return findings

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            kind = doc.get("kind", "")
            if kind == "Secret":
                findings.extend(self._scan_secret(doc, file_path))
            elif kind == "Certificate":
                findings.extend(self._scan_certificate(doc, file_path))
            elif kind == "Ingress":
                findings.extend(self._scan_ingress(doc, file_path))
            elif kind in ("Deployment", "StatefulSet", "DaemonSet", "Pod"):
                findings.extend(self._scan_workload(doc, file_path))

        return findings

    def _scan_secret(self, secret: dict, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        secret_type = secret.get("type", "")
        data = secret.get("data", {})
        string_data = secret.get("stringData", {})

        for key, value in data.items():
            key_lower = key.lower()
            if any(kw in key_lower for kw in ["tls", "ssl", "cert", "key", "ca", "pem", "crt", "der", "p12", "pfx", "jks", "keystore", "truststore"]):
                if "key" in key_lower and "private" not in key_lower:
                    canonical = "Private Key"
                    usage_state = UsageState.PROVIDED_ONLY
                    confidence = 0.8
                elif "cert" in key_lower or "crt" in key_lower or "pem" in key_lower:
                    canonical = "X.509"
                    usage_state = UsageState.PROVIDED_ONLY
                    confidence = 0.7
                else:
                    canonical = "Secret"
                    usage_state = UsageState.PROVIDED_ONLY
                    confidence = 0.5

                findings.append(ScannerFinding(
                    canonical=canonical,
                    original=key,
                    usage_state=usage_state,
                    confidence=confidence,
                    evidence=[create_evidence_signal(
                        tool="config-kubernetes",
                        detail=f"Secret {secret.get('metadata', {}).get('name', '')}: {key}",
                        confidence=confidence,
                        snippet=f"Secret key: {key}",
                    )],
                    location=Location(file=str(file_path), uri=f"k8s-secret:{secret.get('metadata', {}).get('name', '')}:{key}"),
                    implementation=Implementation(library="kubernetes", api="Secret"),
                    context=Context(exposure=Exposure.INTERNAL),
                ))

        for key, value in string_data.items():
            key_lower = key.lower()
            if any(kw in key_lower for kw in ["tls", "ssl", "cert", "key", "ca", "pem", "crt"]):
                findings.append(ScannerFinding(
                    canonical="X.509" if "cert" in key_lower else "Private Key",
                    original=key,
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=0.7,
                    evidence=[create_evidence_signal(
                        tool="config-kubernetes",
                        detail=f"Secret stringData {secret.get('metadata', {}).get('name', '')}: {key}",
                        confidence=0.7,
                        snippet=f"Secret stringData key: {key}",
                    )],
                    location=Location(file=str(file_path), uri=f"k8s-secret-string:{secret.get('metadata', {}).get('name', '')}:{key}"),
                    implementation=Implementation(library="kubernetes", api="Secret.stringData"),
                    context=Context(exposure=Exposure.INTERNAL),
                ))

        return findings

    def _scan_certificate(self, cert: dict, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        spec = cert.get("spec", {})
        if "secretName" in spec:
            findings.append(ScannerFinding(
                canonical="X.509",
                original="cert-manager Certificate",
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.7,
                evidence=[create_evidence_signal(
                    tool="config-kubernetes",
                    detail=f"cert-manager Certificate: {cert.get('metadata', {}).get('name', '')} -> secret {spec['secretName']}",
                    confidence=0.7,
                    snippet=f"Certificate {cert.get('metadata', {}).get('name', '')}",
                )],
                location=Location(file=str(file_path), uri=f"k8s-cert:{cert.get('metadata', {}).get('name', '')}"),
                implementation=Implementation(library="cert-manager", api="Certificate"),
                context=Context(exposure=Exposure.INTERNET_FACING),
            ))

        return findings

    def _scan_ingress(self, ingress: dict, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        spec = ingress.get("spec", {})
        tls = spec.get("tls", [])

        for tls_config in tls:
            hosts = tls_config.get("hosts", [])
            secret_name = tls_config.get("secretName", "")

            findings.append(ScannerFinding(
                canonical="TLS1.2",
                original="Ingress TLS",
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.7,
                evidence=[create_evidence_signal(
                    tool="config-kubernetes",
                    detail=f"Ingress TLS: hosts={hosts}, secret={secret_name}",
                    confidence=0.7,
                    snippet=f"Ingress TLS secret: {secret_name}",
                )],
                location=Location(file=str(file_path), uri=f"k8s-ingress:{ingress.get('metadata', {}).get('name', '')}:{secret_name}"),
                implementation=Implementation(library="kubernetes", api="Ingress.tls"),
                context=Context(exposure=Exposure.INTERNET_FACING),
            ))

        annotations = ingress.get("metadata", {}).get("annotations", {})
        for key, value in annotations.items():
            if any(kw in key.lower() for kw in ["ssl", "tls", "cert", "backend-protocol"]):
                findings.append(ScannerFinding(
                    canonical="TLS",
                    original=key,
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=0.5,
                    evidence=[create_evidence_signal(
                        tool="config-kubernetes",
                        detail=f"Ingress annotation: {key}={value}",
                        confidence=0.5,
                        snippet=f"{key}: {value}",
                    )],
                    location=Location(file=str(file_path), uri=f"k8s-ingress-ann:{key}"),
                    implementation=Implementation(library="kubernetes", api="Ingress.annotations"),
                    context=Context(exposure=Exposure.INTERNET_FACING),
                ))

        return findings

    def _scan_workload(self, workload: dict, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        spec = workload.get("spec", {})
        template = spec.get("template", {}) if "template" in spec else workload
        pod_spec = template.get("spec", {})

        volumes = pod_spec.get("volumes", [])
        for vol in volumes:
            if "secret" in vol:
                secret_name = vol["secret"].get("secretName", "")
                findings.append(ScannerFinding(
                    canonical="Secret volume",
                    original=secret_name,
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=0.5,
                    evidence=[create_evidence_signal(
                        tool="config-kubernetes",
                        detail=f"Volume mounts secret: {secret_name}",
                        confidence=0.5,
                        snippet=f"Volume secret: {secret_name}",
                    )],
                    location=Location(file=str(file_path), uri=f"k8s-volume:{secret_name}"),
                    implementation=Implementation(library="kubernetes", api="Volume.secret"),
                    context=Context(exposure=Exposure.INTERNAL),
                ))

        containers = pod_spec.get("containers", []) + pod_spec.get("initContainers", [])
        for container in containers:
            env = container.get("env", [])
            for env_var in env:
                name = env_var.get("name", "")
                if any(kw in name.lower() for kw in ["ssl", "tls", "cert", "key", "ca", "password", "secret", "token"]):
                    findings.append(ScannerFinding(
                        canonical="Environment variable",
                        original=name,
                        usage_state=UsageState.PROVIDED_ONLY,
                        confidence=0.4,
                        evidence=[create_evidence_signal(
                            tool="config-kubernetes",
                            detail=f"Container env: {name}=[REDACTED]",
                            confidence=0.4,
                            snippet=f"{name}=[REDACTED]",
                        )],
                        location=Location(file=str(file_path), uri=f"k8s-env:{container.get('name', '')}:{name}"),
                        implementation=Implementation(library="kubernetes", api="Container.env"),
                        context=Context(exposure=Exposure.INTERNAL),
                    ))

        return findings