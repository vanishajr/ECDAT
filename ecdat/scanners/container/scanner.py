from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Optional

from ecdat.scanners.base import (
    Scanner,
    ScannerFinding,
    ScannerRegistry,
    create_evidence_signal,
    normalize_finding,
)
from ecdat.core.cir_models import (
    Location,
    Implementation,
    Context,
    UsageState,
    Exposure,
)
from ecdat.core.signature_registry import (
    get_category,
    normalize_algorithm,
)


class ContainerScanner(Scanner[ScannerFinding]):
    name = "container"
    version = "0.1.0"

    def __init__(self):
        self._has_docker = self._check_docker()
        self._has_syft = self._check_syft()
        self._layer_cache: dict[str, list[ScannerFinding]] = {}

    def _check_docker(self) -> bool:
        try:
            subprocess.run(["docker", "version"], capture_output=True, check=True)
            return True
        except Exception:
            return False

    def _check_syft(self) -> bool:
        try:
            subprocess.run(["syft", "version"], capture_output=True, check=True)
            return True
        except Exception:
            return False

    def is_available(self) -> bool:
        return self._has_docker or self._has_syft

    def get_tool_version(self) -> str:
        parts = []
        if self._has_docker:
            try:
                result = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True)
                parts.append(f"docker:{result.stdout.strip()}")
            except Exception:
                parts.append("docker:unknown")
        if self._has_syft:
            try:
                result = subprocess.run(["syft", "version"], capture_output=True, text=True)
                parts.append(f"syft:{result.stdout.strip()}")
            except Exception:
                parts.append("syft:unknown")
        return ", ".join(parts) or "none"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_str = str(target)
        findings: list[ScannerFinding] = []

        if target_str.startswith("docker://") or target_str.startswith("oci://"):
            image_ref = target_str.replace("docker://", "").replace("oci://", "")
            findings.extend(self._scan_image(image_ref))
        elif target_str.endswith(".tar"):
            findings.extend(self._scan_tarball(Path(target_str)))
        elif Path(target_str).is_dir():
            findings.extend(self._scan_directory(Path(target_str)))

        return [normalize_finding(f) for f in findings]

    def _scan_image(self, image_ref: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        if self._has_syft:
            findings.extend(self._scan_with_syft(image_ref))

        if self._has_docker:
            findings.extend(self._scan_with_docker(image_ref))

        return findings

    def _scan_with_syft(self, image_ref: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            result = subprocess.run(
                ["syft", "-o", "json", image_ref],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                return findings

            data = json.loads(result.stdout)
            artifacts = data.get("artifacts", [])

            for artifact in artifacts:
                name = artifact.get("name", "").lower()
                version = artifact.get("version", "")
                locations = artifact.get("locations", [])

                for location in locations:
                    layer_id = location.get("layer", "")

                    if name in ("openssl", "libssl", "libcrypto", "boringssl", "libressl",
                               "cryptography", "pycryptodome", "pyopenssl", "bcrypt", "argon2",
                               "scrypt", "hkdf", "passlib"):
                        canonical_map = {
                            "openssl": "OpenSSL", "libssl": "OpenSSL", "libcrypto": "OpenSSL",
                            "boringssl": "BoringSSL", "libressl": "LibreSSL",
                            "cryptography": "cryptography", "pycryptodome": "cryptography",
                            "pyopenssl": "OpenSSL", "bcrypt": "bcrypt", "argon2": "Argon2",
                            "scrypt": "scrypt", "hkdf": "HKDF", "passlib": "PBKDF2",
                        }
                        canonical = canonical_map.get(name, name)
                        canonical_norm, original = normalize_algorithm(canonical)

                        evidence = create_evidence_signal(
                            tool="container:syft",
                            detail=f"package {name}@{version} found in image {image_ref} layer {layer_id[:12]}",
                            confidence=0.55,
                            snippet=f"{name}=={version}",
                        )

                        finding = ScannerFinding(
                            canonical=canonical_norm,
                            original=original,
                            library=name,
                            usage_state=UsageState.PROVIDED_ONLY,
                            confidence=0.55,
                            evidence=[evidence],
                            location=Location(
                                file=location.get("path", ""),
                                uri=f"image:{image_ref}/layer:{layer_id}",
                            ),
                            implementation=Implementation(library=name, version=version),
                            context=Context(
                                exposure=Exposure.CLOUD,
                                notes="Package capability only; no matching application-use evidence",
                            ),
                        )
                        findings.append(finding)

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return findings

    def _scan_with_docker(self, image_ref: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            result = subprocess.run(
                ["docker", "save", image_ref],
                capture_output=True,
                timeout=120,
            )
            if result.returncode != 0:
                return findings

            with tempfile.TemporaryDirectory() as tmpdir:
                tar_path = Path(tmpdir) / "image.tar"
                tar_path.write_bytes(result.stdout)

                with tarfile.open(tar_path, "r") as tar:
                    manifest_names = [m for m in tar.getnames() if m.endswith("manifest.json")]
                    for manifest_name in manifest_names:
                        manifest_data = json.loads(tar.extractfile(manifest_name).read())
                        for layer_info in manifest_data:
                            layer_digest = layer_info.get("Layers", [])[0] if layer_info.get("Layers") else ""
                            if layer_digest:
                                layer_id = layer_digest.replace("sha256:", "")
                                if layer_id in self._layer_cache:
                                    findings.extend(self._layer_cache[layer_id])
                                else:
                                    layer_findings = self._scan_layer(tar, layer_info, image_ref, layer_id)
                                    self._layer_cache[layer_id] = layer_findings
                                    findings.extend(layer_findings)

        except Exception:
            pass

        return findings

    def _scan_layer(self, tar: tarfile.TarFile, layer_info: dict, image_ref: str, layer_id: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        layer_files = layer_info.get("Layers", [])
        for layer_file in layer_files:
            try:
                layer_member = tar.getmember(layer_file)
                if layer_member is None:
                    continue

                with tempfile.TemporaryDirectory() as tmpdir:
                    tar.extract(layer_member, tmpdir)
                    layer_tar_path = Path(tmpdir) / layer_file

                    with tarfile.open(layer_tar_path, "r") as layer_tar:
                        layer_tar.extractall(tmpdir)

                        for root, dirs, files in os.walk(tmpdir):
                            for file in files:
                                file_path = Path(root) / file
                                rel_path = file_path.relative_to(tmpdir)

                                if file.endswith((".crt", ".pem", ".key", ".p12", ".pfx", ".jks")):
                                    findings.extend(self._scan_certificate_file(file_path, image_ref, layer_id, str(rel_path)))
                                elif file.endswith((".conf", ".config", ".ini", ".yaml", ".yml", ".json")):
                                    findings.extend(self._scan_config_file(file_path, image_ref, layer_id, str(rel_path)))
                                elif self._is_binary(file_path):
                                    findings.extend(self._scan_binary_file(file_path, image_ref, layer_id, str(rel_path)))

            except Exception:
                continue

        return findings

    def _scan_certificate_file(self, file_path: Path, image_ref: str, layer_id: str, rel_path: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_bytes()
            if b"-----BEGIN CERTIFICATE-----" in content or b"-----BEGIN PUBLIC KEY-----" in content:
                from ecdat.scanners.certificate.scanner import CertificateScanner
                cert_scanner = CertificateScanner()
                cert_findings = cert_scanner.scan(file_path)
                for f in cert_findings:
                    f.location = Location(
                        file=str(file_path),
                        uri=f"image:{image_ref}/layer:{layer_id}/{rel_path}",
                    )
                    f.context = Context(exposure=Exposure.CLOUD, notes=f"Found in container image {image_ref}")
                findings.extend(cert_findings)
        except Exception:
            pass
        return findings

    def _scan_config_file(self, file_path: Path, image_ref: str, layer_id: str, rel_path: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            from ecdat.scanners.config.scanner import ConfigScanner
            config_scanner = ConfigScanner()
            config_findings = config_scanner.scan(file_path)
            for f in config_findings:
                f.location = Location(
                    file=str(file_path),
                    uri=f"image:{image_ref}/layer:{layer_id}/{rel_path}",
                )
                f.context = Context(exposure=Exposure.CLOUD, notes=f"Found in container image {image_ref}")
            findings.extend(config_findings)
        except Exception:
            pass
        return findings

    def _scan_binary_file(self, file_path: Path, image_ref: str, layer_id: str, rel_path: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            from ecdat.scanners.binary.scanner import BinaryScanner
            binary_scanner = BinaryScanner()
            if binary_scanner.is_available():
                binary_findings = binary_scanner.scan(file_path)
                for f in binary_findings:
                    f.location = Location(
                        file=str(file_path),
                        uri=f"image:{image_ref}/layer:{layer_id}/{rel_path}",
                    )
                    f.context = Context(exposure=Exposure.CLOUD, notes=f"Found in container image {image_ref}")
                findings.extend(binary_findings)
        except Exception:
            pass
        return findings

    def _scan_tarball(self, tar_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            with tarfile.open(tar_path, "r") as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        tar.extract(member, "/tmp/ecdat_container_scan")
                        extracted = Path("/tmp/ecdat_container_scan") / member.name
                        findings.extend(self._scan_file(extracted))
                        extracted.unlink(missing_ok=True)
        except Exception:
            pass
        return findings

    def _scan_directory(self, dir_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        for file_path in dir_path.rglob("*"):
            if file_path.is_file():
                findings.extend(self._scan_file(file_path))
        return findings

    def _scan_file(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        if file_path.suffix in (".crt", ".pem", ".key", ".p12", ".pfx", ".jks"):
            try:
                from ecdat.scanners.certificate.scanner import CertificateScanner
                cert_scanner = CertificateScanner()
                cert_findings = cert_scanner.scan(file_path)
                findings.extend(cert_findings)
            except Exception:
                pass

        if file_path.suffix in (".conf", ".config", ".ini", ".yaml", ".yml", ".json", ".nginx"):
            try:
                from ecdat.scanners.config.scanner import ConfigScanner
                config_scanner = ConfigScanner()
                config_findings = config_scanner.scan(file_path)
                findings.extend(config_findings)
            except Exception:
                pass

        if self._is_binary(file_path):
            try:
                from ecdat.scanners.binary.scanner import BinaryScanner
                binary_scanner = BinaryScanner()
                if binary_scanner.is_available():
                    binary_findings = binary_scanner.scan(file_path)
                    findings.extend(binary_findings)
            except Exception:
                pass

        return findings

    def _is_binary(self, path: Path) -> bool:
        try:
            with open(path, "rb") as f:
                chunk = f.read(1024)
                if b"\x00" in chunk:
                    return True
                text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x7f)))
                return not all(c in text_chars for c in chunk)
        except Exception:
            return False


ScannerRegistry.register(ContainerScanner())