from __future__ import annotations

import json
import re
import subprocess
try:
    import tomllib
except ImportError:  # Python 3.10: stdlib tomllib is 3.11+
    import tomli as tomllib
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
from ecdat.scanners.path_policy import iter_project_files, iter_project_files_matching


CRYPTO_PACKAGES = {
    "cryptography": {"canonical": "cryptography", "category": "library", "confidence": 0.6},
    "pycryptodome": {"canonical": "cryptography", "category": "library", "confidence": 0.6},
    "pycryptodomex": {"canonical": "cryptography", "category": "library", "confidence": 0.6},
    "pyopenssl": {"canonical": "OpenSSL", "category": "library", "confidence": 0.6},
    "openssl": {"canonical": "OpenSSL", "category": "library", "confidence": 0.6},
    "libcrypto": {"canonical": "OpenSSL", "category": "library", "confidence": 0.6},
    "libssl": {"canonical": "OpenSSL", "category": "library", "confidence": 0.6},
    "boringssl": {"canonical": "BoringSSL", "category": "library", "confidence": 0.6},
    "libressl": {"canonical": "LibreSSL", "category": "library", "confidence": 0.6},
    "bcrypt": {"canonical": "bcrypt", "category": "kdf", "confidence": 0.55},
    "argon2": {"canonical": "Argon2", "category": "kdf", "confidence": 0.55},
    "argon2-cffi": {"canonical": "Argon2", "category": "kdf", "confidence": 0.55},
    "passlib": {"canonical": "PBKDF2", "category": "kdf", "confidence": 0.55},
    "scrypt": {"canonical": "scrypt", "category": "kdf", "confidence": 0.55},
    "hkdf": {"canonical": "HKDF", "category": "kdf", "confidence": 0.55},
    "pqcrypto": {"canonical": "ML-KEM", "category": "pqc_kem", "confidence": 0.55},
    "liboqs": {"canonical": "ML-KEM", "category": "pqc_kem", "confidence": 0.55},
    "oqs": {"canonical": "ML-KEM", "category": "pqc_kem", "confidence": 0.55},
    "cryptography-hazmat": {"canonical": "cryptography", "category": "library", "confidence": 0.6},
    "paramiko": {"canonical": "SSH", "category": "protocol", "confidence": 0.55},
    "ssh": {"canonical": "SSH", "category": "protocol", "confidence": 0.55},
    "requests": {"canonical": "TLS1.2", "category": "protocol", "confidence": 0.4},
    "urllib3": {"canonical": "TLS1.2", "category": "protocol", "confidence": 0.4},
    "aiohttp": {"canonical": "TLS1.2", "category": "protocol", "confidence": 0.4},
    "httpx": {"canonical": "TLS1.2", "category": "protocol", "confidence": 0.4},
    "ssl": {"canonical": "TLS1.2", "category": "protocol", "confidence": 0.3},
    "certifi": {"canonical": "TLS1.2", "category": "protocol", "confidence": 0.3},
    "pyjwt": {"canonical": "pyjwt", "category": "library", "confidence": 0.5},
    "jose": {"canonical": "jose", "category": "library", "confidence": 0.5},
    "python-jose": {"canonical": "python-jose", "category": "library", "confidence": 0.5},
    "authlib": {"canonical": "authlib", "category": "library", "confidence": 0.5},
    "cryptography-vectors": {"canonical": "cryptography", "category": "library", "confidence": 0.3},
    "crypto": {"canonical": "crypto", "category": "library", "confidence": 0.5},
    "crypto-js": {"canonical": "crypto-js", "category": "library", "confidence": 0.5},
    "jsonwebtoken": {"canonical": "jsonwebtoken", "category": "library", "confidence": 0.5},
}


class DependencyScanner(Scanner[ScannerFinding]):
    name = "dependency"
    version = "0.1.0"

    def is_available(self) -> bool:
        return True

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        findings: list[ScannerFinding] = []

        if target_path.is_file():
            findings.extend(self._scan_file(target_path))
        elif target_path.is_dir():
            patterns = ["requirements*.txt", "pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock",
                        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                        "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
                        "pom.xml", "build.gradle", "build.gradle.kts",
                        "Gemfile", "Gemfile.lock", "composer.json", "composer.lock"]
            for file_path in iter_project_files(target_path):
                if any(file_path.match(pattern) for pattern in patterns):
                    findings.extend(self._scan_file(file_path))

            if not findings:
                findings.extend(self._scan_python_imports(target_path))

        return [normalize_finding(f) for f in findings]

    def _should_skip(self, path: Path) -> bool:
        skip_patterns = [
            "__pycache__",
            ".git",
            ".venv",
            "venv",
            "env",
            ".pytest_cache",
            ".mypy_cache",
            "node_modules",
            "dist",
            "build",
            ".tox",
            "target",
        ]
        return any(part in skip_patterns for part in path.parts)

    def _scan_file(self, file_path: Path) -> list[ScannerFinding]:
        suffix = file_path.suffix.lower()
        name = file_path.name.lower()

        if name in ("requirements.txt", "requirements-dev.txt", "requirements-prod.txt") or name.startswith("requirements"):
            return self._scan_requirements(file_path)
        elif name == "pyproject.toml":
            return self._scan_pyproject_toml(file_path)
        elif name == "poetry.lock":
            return self._scan_poetry_lock(file_path)
        elif name == "package.json":
            return self._scan_package_json(file_path)
        elif name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            return self._scan_js_lockfile(file_path)
        elif name == "cargo.toml":
            return self._scan_cargo_toml(file_path)
        elif name == "cargo.lock":
            return self._scan_cargo_lock(file_path)
        elif name in ("go.mod", "go.sum"):
            return self._scan_go_mod(file_path)
        elif name == "pom.xml":
            return self._scan_pom_xml(file_path)
        elif name in ("build.gradle", "build.gradle.kts"):
            return self._scan_gradle(file_path)
        elif name == "gemfile":
            return self._scan_gemfile(file_path)
        elif name == "composer.json":
            return self._scan_composer_json(file_path)

        return []

    def _scan_requirements(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return findings

        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            match = re.match(r"^([A-Za-z0-9_.-]+)(?:[=<>!~].*)?$", line)
            if not match:
                continue

            pkg_name = match.group(1).lower()
            if pkg_name in CRYPTO_PACKAGES:
                info = CRYPTO_PACKAGES[pkg_name]
                canonical, original = normalize_algorithm(info["canonical"])
                category = get_category(canonical)

                evidence = create_evidence_signal(
                    tool="dependency:requirements",
                    detail=f"dependency {pkg_name} found in {file_path.name}:{line_num}",
                    confidence=info["confidence"],
                    snippet=line[:200],
                )

                finding = ScannerFinding(
                    canonical=canonical,
                    original=original,
                    library=pkg_name,
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=info["confidence"],
                    evidence=[evidence],
                    location=Location(file=str(file_path), line=line_num),
                    implementation=Implementation(library=pkg_name),
                    context=Context(exposure=Exposure.INTERNAL, notes="Dependency-only; no confirmed crypto operation"),
                    dependency_only=True,
                )
                findings.append(finding)

        return findings

    def _scan_pyproject_toml(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8")
            data = tomllib.loads(content)
        except Exception:
            return findings

        deps = []
        if "project" in data and "dependencies" in data["project"]:
            deps.extend(data["project"]["dependencies"])
        if "tool" in data and "poetry" in data["tool"] and "dependencies" in data["tool"]["poetry"]:
            deps.extend(data["tool"]["poetry"]["dependencies"])
        if "tool" in data and "pdm" in data["tool"] and "dependencies" in data["tool"]["pdm"]:
            deps.extend(data["tool"]["pdm"]["dependencies"])

        for line_num, dep in enumerate(deps, 1):
            if isinstance(dep, str):
                match = re.match(r"^([A-Za-z0-9_.-]+)", dep)
                if match:
                    pkg_name = match.group(1).lower()
                    if pkg_name in CRYPTO_PACKAGES:
                        info = CRYPTO_PACKAGES[pkg_name]
                        canonical, original = normalize_algorithm(info["canonical"])

                        evidence = create_evidence_signal(
                            tool="dependency:pyproject",
                            detail=f"dependency {pkg_name} found in pyproject.toml",
                            confidence=info["confidence"],
                            snippet=dep[:200],
                        )

                        finding = ScannerFinding(
                            canonical=canonical,
                            original=original,
                            library=pkg_name,
                            usage_state=UsageState.PROVIDED_ONLY,
                            confidence=info["confidence"],
                            evidence=[evidence],
                            location=Location(file=str(file_path)),
                            implementation=Implementation(library=pkg_name),
                            context=Context(exposure=Exposure.INTERNAL, notes="Dependency-only; no confirmed crypto operation"),
                            dependency_only=True,
                        )
                        findings.append(finding)

        return findings

    def _scan_poetry_lock(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8")
            data = tomllib.loads(content)
        except Exception:
            return findings

        packages = data.get("package", [])
        for pkg in packages:
            name = pkg.get("name", "").lower()
            version = pkg.get("version", "")
            if name in CRYPTO_PACKAGES:
                info = CRYPTO_PACKAGES[name]
                canonical, original = normalize_algorithm(info["canonical"])

                evidence = create_evidence_signal(
                    tool="dependency:poetry-lock",
                    detail=f"dependency {name}@{version} found in poetry.lock",
                    confidence=info["confidence"],
                    snippet=f"{name}=={version}",
                )

                finding = ScannerFinding(
                    canonical=canonical,
                    original=original,
                    library=name,
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=info["confidence"],
                    evidence=[evidence],
                    location=Location(file=str(file_path)),
                    implementation=Implementation(library=name, version=version),
                    context=Context(exposure=Exposure.INTERNAL, notes="Dependency-only; no confirmed crypto operation"),
                    dependency_only=True,
                )
                findings.append(finding)

        return findings

    def _scan_package_json(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8")
            data = json.loads(content)
        except Exception:
            return findings

        all_deps = {}
        for key in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            if key in data:
                all_deps.update(data[key])

        for pkg_name, version in all_deps.items():
            normalized = pkg_name.lower()
            if normalized in CRYPTO_PACKAGES:
                info = CRYPTO_PACKAGES[normalized]
                canonical, original = normalize_algorithm(info["canonical"])

                evidence = create_evidence_signal(
                    tool="dependency:package-json",
                    detail=f"dependency {pkg_name}@{version} found in package.json",
                    confidence=info["confidence"],
                    snippet=f'"{pkg_name}": "{version}"',
                )

                finding = ScannerFinding(
                    canonical=canonical,
                    original=original,
                    library=pkg_name,
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=info["confidence"],
                    evidence=[evidence],
                    location=Location(file=str(file_path)),
                    implementation=Implementation(library=pkg_name, version=version.lstrip("^~")),
                    context=Context(exposure=Exposure.INTERNAL, notes="Dependency-only; no confirmed crypto operation"),
                    dependency_only=True,
                )
                findings.append(finding)

        return findings

    def _scan_js_lockfile(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8")
            if file_path.name == "package-lock.json":
                findings.extend(self._scan_package_lock_json(file_path, content))
            elif file_path.name == "yarn.lock":
                findings.extend(self._scan_yarn_lock(file_path, content))
            elif file_path.name == "pnpm-lock.yaml":
                findings.extend(self._scan_pnpm_lock(file_path, content))
        except Exception:
            pass
        return findings

    def _scan_package_lock_json(self, file_path: Path, content: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            data = json.loads(content)
            packages = data.get("packages", {})
            for pkg_path, pkg_info in packages.items():
                if pkg_path == "":
                    continue
                name = pkg_info.get("name", "").lower()
                version = pkg_info.get("version", "")
                if name in CRYPTO_PACKAGES:
                    info = CRYPTO_PACKAGES[name]
                    canonical, original = normalize_algorithm(info["canonical"])
                    
                    evidence = create_evidence_signal(
                        tool="dependency:package-lock",
                        detail=f"dependency {name}@{version} found in package-lock.json",
                        confidence=info["confidence"],
                        snippet=f"{name}=={version}",
                    )
                    
                    finding = ScannerFinding(
                        canonical=canonical,
                        original=original,
                        library=name,
                        usage_state=UsageState.PROVIDED_ONLY,
                        confidence=info["confidence"],
                        evidence=[evidence],
                        location=Location(file=str(file_path)),
                        implementation=Implementation(library=name, version=version),
                        context=Context(exposure=Exposure.INTERNAL, notes="Dependency-only; no confirmed crypto operation"),
                        dependency_only=True,
                    )
                    findings.append(finding)
        except Exception:
            pass
        return findings

    def _scan_yarn_lock(self, file_path: Path, content: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r'^([^@\s]+)@([^:]+):', line)
                if match:
                    name = match.group(1).lower()
                    version = match.group(2)
                    if name in CRYPTO_PACKAGES:
                        info = CRYPTO_PACKAGES[name]
                        canonical, original = normalize_algorithm(info["canonical"])
                        
                        evidence = create_evidence_signal(
                            tool="dependency:yarn-lock",
                            detail=f"dependency {name}@{version} found in yarn.lock",
                            confidence=info["confidence"],
                            snippet=f"{name}@{version}",
                        )
                        
                        finding = ScannerFinding(
                            canonical=canonical,
                            original=original,
                            library=name,
                            usage_state=UsageState.PROVIDED_ONLY,
                            confidence=info["confidence"],
                            evidence=[evidence],
                            location=Location(file=str(file_path)),
                            implementation=Implementation(library=name, version=version),
                            context=Context(exposure=Exposure.INTERNAL, notes="Dependency-only; no confirmed crypto operation"),
                            dependency_only=True,
                        )
                        findings.append(finding)
        except Exception:
            pass
        return findings

    def _scan_pnpm_lock(self, file_path: Path, content: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            import yaml
            data = yaml.safe_load(content)
            packages = data.get("packages", {})
            for pkg_path, pkg_info in packages.items():
                if not pkg_path or pkg_path == "/":
                    continue
                match = re.match(r"^/([^/]+)/(.+)$", pkg_path)
                if match:
                    name = match.group(1).lower()
                    version = match.group(2)
                    if name in CRYPTO_PACKAGES:
                        info = CRYPTO_PACKAGES[name]
                        canonical, original = normalize_algorithm(info["canonical"])
                        
                        evidence = create_evidence_signal(
                            tool="dependency:pnpm-lock",
                            detail=f"dependency {name}@{version} found in pnpm-lock.yaml",
                            confidence=info["confidence"],
                            snippet=f"{name}@{version}",
                        )
                        
                        finding = ScannerFinding(
                            canonical=canonical,
                            original=original,
                            library=name,
                            usage_state=UsageState.PROVIDED_ONLY,
                            confidence=info["confidence"],
                            evidence=[evidence],
                            location=Location(file=str(file_path)),
                            implementation=Implementation(library=name, version=version),
                            context=Context(exposure=Exposure.INTERNAL, notes="Dependency-only; no confirmed crypto operation"),
                            dependency_only=True,
                        )
                        findings.append(finding)
        except Exception:
            pass
        return findings
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8")
            data = tomllib.loads(content)
        except Exception:
            return findings

        for section in ["dependencies", "dev-dependencies", "build-dependencies"]:
            if section in data:
                for pkg_name, version in data[section].items():
                    normalized = pkg_name.lower()
                    if normalized in CRYPTO_PACKAGES:
                        info = CRYPTO_PACKAGES[normalized]
                        canonical, original = normalize_algorithm(info["canonical"])

                        version_str = version if isinstance(version, str) else version.get("version", "") if isinstance(version, dict) else ""

                        evidence = create_evidence_signal(
                            tool="dependency:cargo",
                            detail=f"dependency {pkg_name}@{version_str} found in Cargo.toml",
                            confidence=info["confidence"],
                            snippet=f'{pkg_name} = "{version_str}"',
                        )

                        finding = ScannerFinding(
                    canonical=canonical,
                    original=original,
                    library=pkg_name,
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=info["confidence"],
                    evidence=[evidence],
                    location=Location(file=str(file_path)),
                    implementation=Implementation(library=pkg_name, version=version_str),
                    context=Context(exposure=Exposure.INTERNAL, notes="Dependency-only; no confirmed crypto operation"),
                    dependency_only=True,
                )
                        findings.append(finding)

        return findings

    def _scan_cargo_lock(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8")
            # Cargo.lock is TOML format
            import tomllib
            data = tomllib.loads(content)
            packages = data.get("package", [])
            for pkg in packages:
                name = pkg.get("name", "").lower()
                version = pkg.get("version", "")
                if name in CRYPTO_PACKAGES:
                    info = CRYPTO_PACKAGES[name]
                    canonical, original = normalize_algorithm(info["canonical"])

                    evidence = create_evidence_signal(
                        tool="dependency:cargo-lock",
                        detail=f"dependency {name}@{version} found in Cargo.lock",
                        confidence=info["confidence"],
                        snippet=f"{name}=={version}",
                    )

                    finding = ScannerFinding(
                        canonical=canonical,
                        original=original,
                        library=name,
                        usage_state=UsageState.PROVIDED_ONLY,
                        confidence=info["confidence"],
                        evidence=[evidence],
                        location=Location(file=str(file_path)),
                        implementation=Implementation(library=name, version=version),
                        context=Context(exposure=Exposure.INTERNAL, notes="Dependency-only; no confirmed crypto operation"),
                        dependency_only=True,
                    )
                    findings.append(finding)
        except Exception:
            pass
        return findings

    def _scan_go_mod(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return findings

        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("//"):
                continue

            match = re.match(r"^\s*([a-zA-Z0-9./_-]+)\s+v?([0-9.]+)", line)
            if match:
                pkg_name = match.group(1).lower()
                version = match.group(2)
                if pkg_name in CRYPTO_PACKAGES:
                    info = CRYPTO_PACKAGES[pkg_name]
                    canonical, original = normalize_algorithm(info["canonical"])

                    evidence = create_evidence_signal(
                        tool="dependency:go-mod",
                        detail=f"dependency {pkg_name}@{version} found in go.mod:{line_num}",
                        confidence=info["confidence"],
                        snippet=line[:200],
                    )

                    finding = ScannerFinding(
                        canonical=canonical,
                        original=original,
                        library=pkg_name,
                        usage_state=UsageState.PROVIDED_ONLY,
                        confidence=info["confidence"],
                        evidence=[evidence],
                        location=Location(file=str(file_path), line=line_num),
                        implementation=Implementation(library=pkg_name, version=version),
                        context=Context(exposure=Exposure.INTERNAL, notes="Dependency-only; no confirmed crypto operation"),
                        dependency_only=True,
                    )
                    findings.append(finding)

        return findings

    def _scan_pom_xml(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            ns = {"mvn": "http://maven.apache.org/POM/4.0.0"}
            
            for dep in root.findall(".//mvn:dependency", ns):
                group_id = dep.findtext("mvn:groupId", default="", namespaces=ns)
                artifact_id = dep.findtext("mvn:artifactId", default="", namespaces=ns)
                version = dep.findtext("mvn:version", default="", namespaces=ns)
                
                if group_id and artifact_id:
                    simple_name = artifact_id.lower()
                    if simple_name in CRYPTO_PACKAGES:
                        info = CRYPTO_PACKAGES[simple_name]
                        canonical, original = normalize_algorithm(info["canonical"])
                        
                        evidence = create_evidence_signal(
                            tool="dependency:maven",
                            detail=f"dependency {group_id}:{artifact_id}:{version} found in pom.xml",
                            confidence=info["confidence"],
                            snippet=f"{group_id}:{artifact_id}:{version}",
                        )
                        
                        finding = ScannerFinding(
                            canonical=canonical,
                            original=original,
                            library=simple_name,
                            usage_state=UsageState.PROVIDED_ONLY,
                            confidence=info["confidence"],
                            evidence=[evidence],
                            location=Location(file=str(file_path)),
                            implementation=Implementation(library=simple_name, version=version),
                            context=Context(exposure=Exposure.INTERNAL, notes="Dependency-only; no confirmed crypto operation"),
                            dependency_only=True,
                        )
                        findings.append(finding)
        except Exception:
            pass
        return findings

    def _scan_gradle(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8")
            dep_pattern = re.compile(r'(?:implementation|api|compile|runtimeOnly|testImplementation)\s*[\("]\s*([^:"\s]+)\s*:\s*([^:"\s]+)\s*:\s*([^:"\s]+)')
            for match in dep_pattern.finditer(content):
                group_id = match.group(1)
                artifact_id = match.group(2)
                version = match.group(3)
                
                simple_name = artifact_id.lower()
                if simple_name in CRYPTO_PACKAGES:
                    info = CRYPTO_PACKAGES[simple_name]
                    canonical, original = normalize_algorithm(info["canonical"])
                    
                    evidence = create_evidence_signal(
                        tool="dependency:gradle",
                        detail=f"dependency {group_id}:{artifact_id}:{version} found in {file_path.name}",
                        confidence=info["confidence"],
                        snippet=f"{group_id}:{artifact_id}:{version}",
                    )
                    
                    finding = ScannerFinding(
                        canonical=canonical,
                        original=original,
                        library=simple_name,
                        usage_state=UsageState.PROVIDED_ONLY,
                        confidence=info["confidence"],
                        evidence=[evidence],
                        location=Location(file=str(file_path)),
                        implementation=Implementation(library=simple_name, version=version),
                        context=Context(exposure=Exposure.INTERNAL, notes="Dependency-only; no confirmed crypto operation"),
                        dependency_only=True,
                    )
                    findings.append(finding)
        except Exception:
            pass
        return findings

    def _scan_gemfile(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"gem\s+['\"]([^'\"]+)['\"]\s*(?:,\s*['\"]([^'\"]+)['\"])?", line)
                if match:
                    name = match.group(1).lower()
                    version = match.group(2) if match.group(2) else ""
                    if name in CRYPTO_PACKAGES:
                        info = CRYPTO_PACKAGES[name]
                        canonical, original = normalize_algorithm(info["canonical"])
                        
                        evidence = create_evidence_signal(
                            tool="dependency:gemfile",
                            detail=f"gem {name}@{version} found in Gemfile",
                            confidence=info["confidence"],
                            snippet=f"gem '{name}', '{version}'",
                        )
                        
                        finding = ScannerFinding(
                            canonical=canonical,
                            original=original,
                            library=name,
                            usage_state=UsageState.PROVIDED_ONLY,
                            confidence=info["confidence"],
                            evidence=[evidence],
                            location=Location(file=str(file_path)),
                            implementation=Implementation(library=name, version=version),
                            context=Context(exposure=Exposure.INTERNAL, notes="Dependency-only; no confirmed crypto operation"),
                            dependency_only=True,
                        )
                        findings.append(finding)
        except Exception:
            pass
        return findings

    def _scan_composer_json(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8")
            data = json.loads(content)
            
            all_deps = {}
            for key in ["require", "require-dev", "require-optional"]:
                if key in data:
                    all_deps.update(data[key])
            
            for pkg_name, version in all_deps.items():
                normalized = pkg_name.lower().split("/")[-1]
                if normalized in CRYPTO_PACKAGES:
                    info = CRYPTO_PACKAGES[normalized]
                    canonical, original = normalize_algorithm(info["canonical"])
                    
                    evidence = create_evidence_signal(
                        tool="dependency:composer",
                        detail=f"dependency {pkg_name}@{version} found in composer.json",
                        confidence=info["confidence"],
                        snippet=f'"{pkg_name}": "{version}"',
                    )
                    
                    finding = ScannerFinding(
                        canonical=canonical,
                        original=original,
                        library=pkg_name,
                        usage_state=UsageState.PROVIDED_ONLY,
                        confidence=info["confidence"],
                        evidence=[evidence],
                        location=Location(file=str(file_path)),
                        implementation=Implementation(library=pkg_name, version=version.lstrip("^~")),
                        context=Context(exposure=Exposure.INTERNAL, notes="Dependency-only; no confirmed crypto operation"),
                        dependency_only=True,
                    )
                    findings.append(finding)
        except Exception:
            pass
        return findings

    def _scan_python_imports(self, target_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        import ast
        for py_file in iter_project_files_matching(target_path, {".py"}):
            try:
                content = py_file.read_text(encoding="utf-8")
                tree = ast.parse(content, filename=str(py_file))
            except Exception:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self._check_import(alias.name, py_file, findings)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        for alias in node.names:
                            full_name = f"{node.module}.{alias.name}"
                            self._check_import(full_name, py_file, findings)

        return findings

    def _check_import(self, import_name: str, file_path: Path, findings: list[ScannerFinding]):
        normalized = import_name.lower().split(".")[0]
        if normalized in CRYPTO_PACKAGES:
            info = CRYPTO_PACKAGES[normalized]
            canonical, original = normalize_algorithm(info["canonical"])

            evidence = create_evidence_signal(
                tool="dependency:import",
                detail=f"import {import_name} found in {file_path}",
                confidence=info["confidence"] * 0.8,
                snippet=f"import {import_name}",
            )

            finding = ScannerFinding(
                canonical=canonical,
                original=original,
                library=normalized,
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=info["confidence"] * 0.8,
                evidence=[evidence],
                location=Location(file=str(file_path)),
                implementation=Implementation(library=normalized),
                context=Context(exposure=Exposure.INTERNAL, notes="Import-only; no confirmed crypto operation"),
                dependency_only=True,
            )
            findings.append(finding)


ScannerRegistry.register(DependencyScanner())
