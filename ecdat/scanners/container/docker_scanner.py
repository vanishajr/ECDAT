from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class DockerScanner(Scanner[ScannerFinding]):
    name = "container-docker"
    version = "0.1.0"

    def __init__(self) -> None:
        self._docker_available = self._check_docker()
        self._trivy_available = self._check_trivy()

    def _check_docker(self) -> bool:
        try:
            result = subprocess.run(
                ["docker", "version", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _check_trivy(self) -> bool:
        try:
            result = subprocess.run(
                ["trivy", "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def is_available(self) -> bool:
        return self._docker_available

    def get_tool_version(self) -> str:
        versions = []
        if self._docker_available:
            try:
                result = subprocess.run(
                    ["docker", "version", "--format", "{{.Server.Version}}"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    versions.append(f"docker-{result.stdout.strip()}")
            except Exception:
                versions.append("docker-unknown")
        if self._trivy_available:
            try:
                result = subprocess.run(
                    ["trivy", "version", "--format", "json"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    import json
                    data = json.loads(result.stdout)
                    versions.append(f"trivy-{data.get('Version', 'unknown')}")
            except Exception:
                versions.append("trivy-unknown")
        return ",".join(versions) if versions else "unavailable"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        if not self._docker_available:
            return []

        target_str = str(target)
        findings: list[ScannerFinding] = []

        if target_str.startswith("sha256:") or ":" in target_str and not target_str.startswith("/"):
            findings.extend(self._scan_image(target_str))
        elif Path(target).is_file() and target_str.endswith((".tar", ".tar.gz", ".tgz")):
            findings.extend(self._scan_tarball(target_str))
        elif Path(target).is_dir():
            findings.extend(self._scan_directory(target_str))

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _scan_image(self, image_ref: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        findings.extend(self._scan_with_docker_inspect(image_ref))
        findings.extend(self._scan_with_trivy(image_ref))
        findings.extend(self._scan_layers(image_ref))

        return findings

    def _scan_tarball(self, tarball_path: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            result = subprocess.run(
                ["docker", "load", "--input", tarball_path],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "Loaded image:" in line:
                        image_ref = line.split("Loaded image:")[1].strip()
                        findings.extend(self._scan_image(image_ref))
                        break
        except Exception:
            pass

        return findings

    def _scan_directory(self, dir_path: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        dockerfile = Path(dir_path) / "Dockerfile"
        if dockerfile.exists():
            findings.extend(self._scan_dockerfile(dockerfile))

        docker_compose = Path(dir_path) / "docker-compose.yml"
        if not docker_compose.exists():
            docker_compose = Path(dir_path) / "docker-compose.yaml"
        if docker_compose.exists():
            findings.extend(self._scan_docker_compose(docker_compose))

        return findings

    def _scan_with_docker_inspect(self, image_ref: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            result = subprocess.run(
                ["docker", "inspect", image_ref],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return findings

            data = json.loads(result.stdout)
            if not data:
                return findings

            image_data = data[0]
            config = image_data.get("Config", {})

            findings.extend(self._extract_env_crypto(config.get("Env", [])))
            findings.extend(self._extract_labels_crypto(image_data.get("Config", {}).get("Labels", {})))
            findings.extend(self._extract_ports_crypto(config.get("ExposedPorts", {})))
            findings.extend(self._extract_volumes_crypto(config.get("Volumes", {})))

            history = image_data.get("History", [])
            for layer in history:
                created_by = layer.get("CreatedBy", "")
                if any(kw in created_by.lower() for kw in ["ssl", "tls", "cert", "key", "crypto", "openssl", "gnutls", "mbedtls", "wolfssl", "nss", "boringssl", "libressl"]):
                    findings.append(ScannerFinding(
                        canonical="Container layer crypto",
                        original=created_by[:100],
                        usage_state=UsageState.PROVIDED_ONLY,
                        confidence=0.3,
                        evidence=[create_evidence_signal(
                            tool="container-docker",
                            detail=f"Layer with crypto reference: {created_by[:200]}",
                            confidence=0.3,
                            snippet=created_by[:500],
                        )],
                        location=Location(file=image_ref, uri=f"docker-layer:{hash(created_by) & 0xffffffff:x}"),
                        implementation=Implementation(library="docker", provider="docker-inspect"),
                        context=Context(exposure=Exposure.INTERNAL),
                    ))

        except Exception:
            pass

        return findings

    def _extract_env_crypto(self, env_vars: list[str]) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        crypto_keywords = ["ssl", "tls", "cert", "key", "crypto", "password", "secret", "token", "ca_", "crt_", "pem_", "jks_", "pkcs12", "keystore", "truststore"]

        for env in env_vars:
            if "=" in env:
                key, value = env.split("=", 1)
                if any(kw in key.lower() for kw in crypto_keywords):
                    findings.append(ScannerFinding(
                        canonical="Environment variable with crypto reference",
                        original=key,
                        usage_state=UsageState.PROVIDED_ONLY,
                        confidence=0.4,
                        evidence=[create_evidence_signal(
                            tool="container-docker",
                            detail=f"Env var: {key}=[REDACTED]",
                            confidence=0.4,
                            snippet=f"{key}=[REDACTED]",
                        )],
                        location=Location(uri=f"docker-env:{key}"),
                        implementation=Implementation(library="docker", provider="docker-inspect"),
                        context=Context(exposure=Exposure.INTERNAL),
                    ))
        return findings

    def _extract_labels_crypto(self, labels: dict) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        for key, value in labels.items():
            if any(kw in key.lower() for kw in ["ssl", "tls", "cert", "key", "crypto", "ca", "crt", "pem"]):
                findings.append(ScannerFinding(
                    canonical="Docker label with crypto reference",
                    original=key,
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=0.3,
                    evidence=[create_evidence_signal(
                        tool="container-docker",
                        detail=f"Label: {key}={value}",
                        confidence=0.3,
                        snippet=f"{key}={value}",
                    )],
                    location=Location(uri=f"docker-label:{key}"),
                    implementation=Implementation(library="docker", provider="docker-inspect"),
                    context=Context(exposure=Exposure.INTERNAL),
                ))
        return findings

    def _extract_ports_crypto(self, ports: dict) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        tls_ports = {"443", "8443", "9443", "6443", "22", "2222", "993", "995", "465", "587", "636", "989", "990"}

        for port_spec in ports.keys():
            port = port_spec.split("/")[0]
            if port in tls_ports:
                findings.append(ScannerFinding(
                    canonical="Container exposes TLS/SSL port",
                    original=f"port/{port}",
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=0.4,
                    evidence=[create_evidence_signal(
                        tool="container-docker",
                        detail=f"Exposed port: {port_spec}",
                        confidence=0.4,
                        snippet=port_spec,
                    )],
                    location=Location(uri=f"docker-port:{port_spec}"),
                    implementation=Implementation(library="docker", provider="docker-inspect"),
                    context=Context(exposure=Exposure.INTERNET_FACING),
                ))
        return findings

    def _extract_volumes_crypto(self, volumes: dict) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        crypto_paths = ["/etc/ssl", "/etc/pki", "/etc/certs", "/etc/keys", "/etc/letsencrypt", "/etc/tls", "/certs", "/keys", "/ssl"]

        for vol_path in volumes.keys():
            for cp in crypto_paths:
                if vol_path.startswith(cp):
                    findings.append(ScannerFinding(
                        canonical="Container volume with crypto path",
                        original=vol_path,
                        usage_state=UsageState.PROVIDED_ONLY,
                        confidence=0.5,
                        evidence=[create_evidence_signal(
                            tool="container-docker",
                            detail=f"Volume mount: {vol_path}",
                            confidence=0.5,
                            snippet=vol_path,
                        )],
                        location=Location(uri=f"docker-volume:{vol_path}"),
                        implementation=Implementation(library="docker", provider="docker-inspect"),
                        context=Context(exposure=Exposure.INTERNAL),
                    ))
                    break
        return findings

    def _scan_with_trivy(self, image_ref: str) -> list[ScannerFinding]:
        if not self._trivy_available:
            return []

        findings: list[ScannerFinding] = []

        try:
            result = subprocess.run(
                ["trivy", "image", "--format", "json", "--quiet", image_ref],
                capture_output=True,
                text=True,
                timeout=180,
            )
            if result.returncode not in (0, 1):
                return findings

            data = json.loads(result.stdout)
            for result_item in data.get("Results", []):
                for vuln in result_item.get("Vulnerabilities", []):
                    pkg_name = vuln.get("PkgName", "")
                    if any(kw in pkg_name.lower() for kw in ["ssl", "tls", "crypto", "openssl", "gnutls", "mbedtls", "wolfssl", "nss", "boringssl", "libressl", "libsodium", "nettle", "gcrypt"]):
                        findings.append(ScannerFinding(
                            canonical="Vulnerable crypto package",
                            original=pkg_name,
                            usage_state=UsageState.PROVIDED_ONLY,
                            confidence=0.6,
                            evidence=[create_evidence_signal(
                                tool="trivy",
                                detail=f"Vulnerable package: {pkg_name} ({vuln.get('VulnerabilityID', '')})",
                                confidence=0.6,
                                snippet=f"{pkg_name} {vuln.get('InstalledVersion', '')} - {vuln.get('Title', '')}",
                            )],
                            location=Location(file=image_ref, uri=f"trivy-vuln:{vuln.get('VulnerabilityID', '')}"),
                            implementation=Implementation(library=pkg_name, version=vuln.get("InstalledVersion", ""), provider="trivy"),
                            context=Context(exposure=Exposure.INTERNAL),
                        ))
        except Exception:
            pass

        return findings

    def _scan_layers(self, image_ref: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            result = subprocess.run(
                ["docker", "save", image_ref],
                capture_output=True,
                timeout=120,
            )
            if result.returncode != 0:
                return findings

            import tarfile
            import io

            tar_stream = io.BytesIO(result.stdout)
            with tarfile.open(fileobj=tar_stream, mode="r:*") as tar:
                for member in tar.getmembers():
                    if member.isfile() and member.name.endswith((".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".jks", ".keystore", ".truststore")):
                        try:
                            f = tar.extractfile(member)
                            if f:
                                content = f.read(4096)
                                findings.extend(self._analyze_cert_content(content, member.name, image_ref))
                        except Exception:
                            pass
        except Exception:
            pass

        return findings

    def _analyze_cert_content(self, content: bytes, filename: str, image_ref: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        if content.startswith(b"-----BEGIN ") and b"-----END " in content:
            if b"CERTIFICATE" in content:
                canonical, original = normalize_algorithm("X.509")
                findings.append(ScannerFinding(
                    canonical=canonical,
                    original=original,
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=0.7,
                    evidence=[create_evidence_signal(
                        tool="container-docker",
                        detail=f"Certificate found in layer: {filename}",
                        confidence=0.7,
                        snippet=f"Certificate in {filename}",
                    )],
                    location=Location(file=image_ref, uri=f"docker-cert:{filename}"),
                    implementation=Implementation(library="X.509", provider="docker-layer"),
                    context=Context(exposure=Exposure.INTERNAL),
                ))
            elif b"PRIVATE KEY" in content:
                findings.append(ScannerFinding(
                    canonical="Private key found in container",
                    original="Private Key",
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=0.9,
                    evidence=[create_evidence_signal(
                        tool="container-docker",
                        detail=f"Private key found in layer: {filename}",
                        confidence=0.9,
                        snippet=f"Private key in {filename} - [REDACTED]",
                    )],
                    location=Location(file=image_ref, uri=f"docker-key:{filename}"),
                    implementation=Implementation(library="Private Key", provider="docker-layer"),
                    context=Context(exposure=Exposure.INTERNAL),
                ))

        return findings

    def _scan_dockerfile(self, dockerfile: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            content = dockerfile.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings

        lines = content.splitlines()
        for i, line in enumerate(lines):
            line_lower = line.lower().strip()
            if line_lower.startswith(("run", "cmd", "entrypoint")):
                if any(kw in line_lower for kw in ["openssl", "gnutls", "mbedtls", "wolfssl", "libressl", "boringssl", "nss", "libsodium", "nettle", "gcrypt"]):
                    findings.append(ScannerFinding(
                        canonical="Dockerfile installs crypto library",
                        original=line.strip(),
                        usage_state=UsageState.PROVIDED_ONLY,
                        confidence=0.5,
                        evidence=[create_evidence_signal(
                            tool="container-docker",
                            detail=f"Dockerfile line {i+1}: {line.strip()}",
                            confidence=0.5,
                            snippet=line.strip(),
                        )],
                        location=Location(file=str(dockerfile), line=i+1),
                        implementation=Implementation(library="docker", provider="dockerfile"),
                        context=Context(exposure=Exposure.INTERNAL),
                    ))
        return findings

    def _scan_docker_compose(self, compose_file: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            import yaml
            content = yaml.safe_load(compose_file.read_text(encoding="utf-8"))
        except Exception:
            return findings

        if not content or "services" not in content:
            return findings

        for service_name, service_config in content.get("services", {}).items():
            ports = service_config.get("ports", [])
            for port in ports:
                port_str = str(port)
                if ":" in port_str:
                    host_port = port_str.split(":")[0]
                    if host_port in {"443", "8443", "9443", "6443", "22", "2222"}:
                        findings.append(ScannerFinding(
                            canonical="Docker Compose exposes TLS/SSL port",
                            original=f"{service_name}:{port_str}",
                            usage_state=UsageState.PROVIDED_ONLY,
                            confidence=0.4,
                            evidence=[create_evidence_signal(
                                tool="container-docker",
                                detail=f"Service {service_name} exposes port {port_str}",
                                confidence=0.4,
                                snippet=port_str,
                            )],
                            location=Location(file=str(compose_file), uri=f"docker-compose:{service_name}:{port_str}"),
                            implementation=Implementation(library="docker-compose", provider="docker-compose"),
                            context=Context(exposure=Exposure.INTERNET_FACING),
                        ))

            environment = service_config.get("environment", {})
            if isinstance(environment, list):
                for env in environment:
                    if "=" in env:
                        key, _ = env.split("=", 1)
                        if any(kw in key.lower() for kw in ["ssl", "tls", "cert", "key", "crypto", "password", "secret", "token"]):
                            findings.append(ScannerFinding(
                                canonical="Docker Compose env with crypto reference",
                                original=key,
                                usage_state=UsageState.PROVIDED_ONLY,
                                confidence=0.4,
                                evidence=[create_evidence_signal(
                                    tool="container-docker",
                                    detail=f"Service {service_name} env: {key}=[REDACTED]",
                                    confidence=0.4,
                                    snippet=f"{key}=[REDACTED]",
                                )],
                                location=Location(file=str(compose_file), uri=f"docker-compose:{service_name}:env:{key}"),
                                implementation=Implementation(library="docker-compose", provider="docker-compose"),
                                context=Context(exposure=Exposure.INTERNAL),
                            ))

        return findings