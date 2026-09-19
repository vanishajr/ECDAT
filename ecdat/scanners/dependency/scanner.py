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


from ecdat.scanners.dependency.crypto_packages import (
    CRYPTO_PACKAGES,
    capabilities_for,
)


class DependencyScanner(Scanner[ScannerFinding]):
    name = "dependency"
    version = "0.2.0"

    def __init__(self) -> None:
        self._last_stats: dict[str, Any] = {"syft": "not-run",
                                            "cdxgen": "not-run"}

    def last_stats(self) -> dict[str, Any]:
        """Optional-tool status (Phase 5: recorded, never fatal)."""
        return dict(self._last_stats)

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
                        "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
                        "CMakeLists.txt", "*.cmake", "conanfile.txt", "conanfile.py",
                        "vcpkg.json", "meson.build", "configure.ac", "*.pc",
                        "*bom.json", "*.cdx.json", "*bom.xml", "*.cdx.xml",
                        "*.spdx.json", "*.spdx"]
            for file_path in iter_project_files(target_path):
                if any(file_path.match(pattern) for pattern in patterns):
                    findings.extend(self._scan_file(file_path))

            if not findings:
                findings.extend(self._scan_python_imports(target_path))
            findings.extend(self._scan_external_tools(target_path))

        self._attach_capabilities(findings)
        return [normalize_finding(f) for f in findings]

    @staticmethod
    def _attach_capabilities(findings: list[ScannerFinding]) -> None:
        """Record provided-algorithm capabilities in context notes.

        One finding per dependency stays one finding (no per-algorithm
        explosion): the capability list rides along for graph enrichment
        (Phase 9). Dependency-only evidence is never upgraded here.
        """
        for finding in findings:
            if not finding.dependency_only:
                continue
            caps = capabilities_for(finding.library) or \
                capabilities_for(finding.canonical)
            if not caps:
                continue
            note = f"provides={','.join(caps)}"
            try:
                if finding.context is None:
                    finding.context = Context(exposure=Exposure.INTERNAL,
                                              notes=note)
                elif finding.context.notes:
                    if "provides=" not in finding.context.notes:
                        finding.context.notes += f"; {note}"
                else:
                    finding.context.notes = note
            except Exception:
                continue

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
        elif name == "cmakelists.txt" or suffix == ".cmake":
            return self._scan_cmake(file_path)
        elif name == "conanfile.txt":
            return self._scan_conan_txt(file_path)
        elif name == "conanfile.py":
            return self._scan_conan_py(file_path)
        elif name == "vcpkg.json":
            return self._scan_vcpkg(file_path)
        elif name == "meson.build":
            return self._scan_meson(file_path)
        elif name == "configure.ac":
            return self._scan_autotools(file_path)
        elif suffix == ".pc":
            return self._scan_pkgconfig(file_path)
        elif name in ("bom.json", "cyclonedx.json") or name.endswith(".cdx.json"):
            return self._scan_cyclonedx_json(file_path)
        elif name in ("bom.xml", "cyclonedx.xml") or name.endswith(".cdx.xml"):
            return self._scan_cyclonedx_xml(file_path)
        elif name.endswith(".spdx.json"):
            return self._scan_spdx_json(file_path)
        elif name.endswith(".spdx"):
            return self._scan_spdx_tagvalue(file_path)

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

    #: Manifest spelling -> CRYPTO_PACKAGES key (native C/C++ ecosystems).
    NATIVE_LIB_ALIASES = {
        "openssl": "openssl", "libssl": "libssl", "libcrypto": "libcrypto",
        "ssl": "openssl", "crypto": "openssl",
        "wolfssl": "wolfssl",
        # Concatenated so the key can never drift to "mbedtls" (with a
        # space): ("mbed" + "tls") == "mbedtls".
        "mbed" + "tls": "mbed" + "tls", "mbedcrypto": "mbedcrypto",
        "mbedx509": "mbedx509", "mbed" + "tls-config": "mbed" + "tls",
        "sodium": "sodium", "libsodium": "libsodium",
        "cryptopp": "cryptopp", "crypto++": "crypto++",
        "botan": "botan", "gnutls": "gnutls", "nss": "nss",
        "boringssl": "boringssl", "libressl": "libressl",
        "libretls": "libressl", "libtls": "libressl",
        "liboqs": "liboqs", "oqs": "oqs",
    }

    def _native_finding(self, file_path: Path, line: int | None,
                        pkg_key: str, tool: str, version: str = "",
                        snippet: str = "") -> list[ScannerFinding]:
        """One ProvidedOnly finding for a native manifest reference."""
        info = CRYPTO_PACKAGES.get(pkg_key)
        if not info:
            return []
        canonical, original = normalize_algorithm(info["canonical"])
        evidence = create_evidence_signal(
            tool=tool,
            detail=f"native dependency {pkg_key}"
                   + (f"@{version}" if version else "")
                   + f" in {file_path.name}"
                   + (f":{line}" if line else ""),
            confidence=info["confidence"],
            snippet=(snippet or f"{pkg_key}@{version}".strip("@"))[:200],
        )
        location = Location(file=str(file_path))
        if line and line >= 1:
            location = Location(file=str(file_path), line=line)
        return [ScannerFinding(
            canonical=canonical,
            original=original,
            library=pkg_key,
            usage_state=UsageState.PROVIDED_ONLY,
            confidence=info["confidence"],
            evidence=[evidence],
            location=location,
            implementation=Implementation(library=pkg_key, version=version or None),
            context=Context(exposure=Exposure.INTERNAL,
                            notes="Dependency-only; no confirmed crypto operation"),
            dependency_only=True,
        )]

    @classmethod
    def _native_key(cls, raw: str) -> str:
        return cls.NATIVE_LIB_ALIASES.get(str(raw or "").strip().lower(), "")

    def _scan_cmake(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings
        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for match in re.finditer(
                    r"find_package\s*\(\s*([A-Za-z0-9_+\-.]+)(?:\s+([0-9][0-9A-Za-z._-]*))?",
                    stripped):
                key = self._native_key(match.group(1))
                if key:
                    version = match.group(2) or ""
                    findings.extend(self._native_finding(
                        file_path, line_num, key, "dependency:cmake",
                        version, stripped))
            for match in re.finditer(
                    r"pkg_check_modules\s*\([^)]*?\b([A-Za-z0-9_+\-.]+)\b",
                    stripped, re.IGNORECASE):
                key = self._native_key(match.group(1))
                if key:
                    findings.extend(self._native_finding(
                        file_path, line_num, key, "dependency:cmake",
                        "", stripped))
            link = re.search(
                r"target_link_libraries\s*\((.*)\)\s*$", stripped,
                re.IGNORECASE)
            if link:
                for token in re.split(r"\s+", link.group(1)):
                    key = self._native_key(token.strip("${}"))
                    if key:
                        findings.extend(self._native_finding(
                            file_path, line_num, key, "dependency:cmake",
                            "", stripped))
            for match in re.finditer(
                    r"(?:conan_cmake_configure|conan_cmake_install)\s*\(.*?REQUIRES\s+([A-Za-z0-9_+\-.]+)/([0-9][0-9A-Za-z._-]*)",
                    stripped, re.IGNORECASE):
                key = self._native_key(match.group(1))
                if key:
                    findings.extend(self._native_finding(
                        file_path, line_num, key, "dependency:cmake",
                        match.group(2), stripped))
        return findings

    def _scan_conan_txt(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return findings
        in_requires = False
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("["):
                in_requires = stripped.lower() == "[requires]"
                continue
            if not in_requires or not stripped or stripped.startswith("#"):
                continue
            match = re.match(r"([A-Za-z0-9_+\-.]+)/([0-9][0-9A-Za-z._-]*)", stripped)
            if match:
                key = self._native_key(match.group(1))
                if key:
                    findings.extend(self._native_finding(
                        file_path, line_num, key, "dependency:conan",
                        match.group(2), stripped))
        return findings

    def _scan_conan_py(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings
        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for match in re.finditer(
                    r"""self\.requires\(\s*["']([A-Za-z0-9_+\-.]+)/([0-9][0-9A-Za-z._-]*)""",
                    stripped):
                key = self._native_key(match.group(1))
                if key:
                    findings.extend(self._native_finding(
                        file_path, line_num, key, "dependency:conan",
                        match.group(2), stripped))
        return findings

    def _scan_vcpkg(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except Exception:
            return findings
        deps = data.get("dependencies", []) or []
        if isinstance(deps, dict):
            deps = list(deps.keys())
        for dep in deps:
            if isinstance(dep, dict):
                name, version = str(dep.get("name", "")), str(dep.get("version>=", ""))
            else:
                name, version = str(dep), ""
            key = self._native_key(name.split("[")[0])
            if key:
                findings.extend(self._native_finding(
                    file_path, None, key, "dependency:vcpkg", version,
                    f'"{name}"'))
        return findings

    def _scan_meson(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings
        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for match in re.finditer(
                    r"""dependency\(\s*['"]([A-Za-z0-9_+\-.]+)['"]""", stripped):
                key = self._native_key(match.group(1))
                if key:
                    findings.extend(self._native_finding(
                        file_path, line_num, key, "dependency:meson",
                        "", stripped))
        return findings

    def _scan_autotools(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings
        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") \
                    or stripped.startswith("dnl"):
                continue
            for match in re.finditer(
                    r"AC_CHECK_LIB\s*\(\s*\[?([A-Za-z0-9_+\-.]+)\]?", stripped):
                key = self._native_key(match.group(1))
                if key:
                    findings.extend(self._native_finding(
                        file_path, line_num, key, "dependency:autotools",
                        "", stripped))
            for match in re.finditer(
                    r"PKG_CHECK_MODULES\s*\([^,]+,\s*\[?([A-Za-z0-9_+\-.]+)",
                    stripped):
                key = self._native_key(match.group(1))
                if key:
                    findings.extend(self._native_finding(
                        file_path, line_num, key, "dependency:autotools",
                        "", stripped))
        return findings

    def _scan_pkgconfig(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings
        name, version = "", ""
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("name:"):
                name = stripped.split(":", 1)[1].strip()
            elif stripped.lower().startswith("version:"):
                version = stripped.split(":", 1)[1].strip()
        key = self._native_key(name)
        if key:
            findings.extend(self._native_finding(
                file_path, None, key, "dependency:pkgconfig", version,
                f"Name: {name}"))
        return findings

    # -- imported BOMs (CycloneDX / SPDX): inventory/capability evidence ---
    def _bom_finding(self, file_path: Path, name: str, version: str,
                     tool: str, canonical_hint: str = "") -> list[ScannerFinding]:
        key = str(name or "").strip().lower()
        info = CRYPTO_PACKAGES.get(key)
        canonical = canonical_hint
        if info:
            canonical = info["canonical"]
        elif not canonical_hint:
            return []
        canonical_norm, original = normalize_algorithm(canonical)
        confidence = float(info["confidence"]) if info else 0.4
        return [ScannerFinding(
            canonical=canonical_norm,
            original=original,
            library=key,
            usage_state=UsageState.PROVIDED_ONLY,
            confidence=confidence,
            evidence=[create_evidence_signal(
                tool=tool,
                detail=f"imported BOM component {name}"
                       + (f"@{version}" if version else "")
                       + f" in {file_path.name}",
                confidence=confidence,
                snippet=f"{name}@{version}".strip("@")[:200],
            )],
            location=Location(file=str(file_path)),
            implementation=Implementation(library=key, version=version or None,
                                          provider="bom-import"),
            context=Context(exposure=Exposure.INTERNAL,
                            notes="Imported BOM inventory; no confirmed crypto operation"),
            dependency_only=True,
        )]

    def _scan_cyclonedx_json(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except Exception:
            return findings
        if str(data.get("bomFormat", "")).lower() != "cyclonedx":
            return findings
        for component in data.get("components", []) or []:
            if not isinstance(component, dict):
                continue
            name = str(component.get("name", ""))
            version = str(component.get("version", ""))
            hint = self._cyclonedx_crypto_hint(component.get("cryptoProperties"))
            findings.extend(self._bom_finding(
                file_path, name, version, "dependency:bom-cyclonedx", hint))
        return findings

    @staticmethod
    def _cyclonedx_crypto_hint(props: object) -> str:
        if not isinstance(props, dict):
            return ""
        for key in ("cipher", "protocol", "algorithm", "primitive"):
            value = props.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        nested = props.get("algorithmProperties")
        if isinstance(nested, dict):
            for key in ("primitive", "oid", "algorithm"):
                value = nested.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return ""

    def _scan_cyclonedx_xml(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            import xml.etree.ElementTree as _et
            root = _et.fromstring(file_path.read_text(encoding="utf-8"))
        except Exception:
            return findings

        def _local(tag: str) -> str:
            return str(tag).rsplit("}", 1)[-1]

        if _local(root.tag) != "bom":
            return findings
        for comp in root.iter():
            if _local(comp.tag) != "component":
                continue
            name, version, hint = "", "", ""
            for child in comp:
                local = _local(child.tag)
                if local == "name" and child.text:
                    name = child.text.strip()
                elif local == "version" and child.text:
                    version = child.text.strip()
                elif local == "cryptoProperties":
                    texts = [str(e.text).strip() for e in comp.iter()
                             if e.text and e.text.strip()]
                    hint = next((t for t in texts if t and t != name), "")
            if name:
                findings.extend(self._bom_finding(
                    file_path, name, version, "dependency:bom-cyclonedx", hint))
        return findings

    def _scan_spdx_json(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except Exception:
            return findings
        if "packages" not in data and "spdxVersion" not in data:
            return findings
        for package in data.get("packages", []) or []:
            if not isinstance(package, dict):
                continue
            findings.extend(self._bom_finding(
                file_path, str(package.get("name", "")),
                str(package.get("versionInfo", "")),
                "dependency:bom-spdx"))
        return findings

    def _scan_spdx_tagvalue(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings
        name, version = "", ""
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("PackageName:"):
                if name:
                    findings.extend(self._bom_finding(
                        file_path, name, version, "dependency:bom-spdx"))
                name = stripped.split(":", 1)[1].strip()
                version = ""
            elif stripped.startswith("PackageVersion:") and name:
                version = stripped.split(":", 1)[1].strip()
        if name:
            findings.extend(self._bom_finding(
                file_path, name, version, "dependency:bom-spdx"))
        return findings

    # -- optional external inventory (Syft/cdxgen): best effort only ------
    _SYFT_ECO = {
        "npm": "npm", "yarn": "npm", "pnpm": "npm", "pypi": "pypi",
        "poetry": "pypi", "pip": "pypi", "cargo": "cargo", "go": "go",
        "gomod": "go", "maven": "maven", "gradle": "gradle", "gem": "gem",
        "bundler": "gem", "composer": "composer", "apk": "apk",
        "dpkg": "dpkg", "rpm": "rpm",
    }

    def _scan_external_tools(self, target_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        findings.extend(self._run_syft(target_path))
        findings.extend(self._run_cdxgen(target_path))
        return findings

    def _run_syft(self, target_path: Path) -> list[ScannerFinding]:
        import shutil
        import subprocess as _sp
        from ecdat.scanners.dependency.crypto_packages import (
            SYFT_CRYPTO_PACKAGES)
        if not shutil.which("syft"):
            self._last_stats["syft"] = "unavailable"
            return []
        try:
            proc = _sp.run(["syft", "scan", "-o", "json", f"dir:{target_path}"],
                           capture_output=True, text=True, timeout=120)
            if proc.returncode not in (0, 1):
                self._last_stats["syft"] = f"failed: rc={proc.returncode}"
                return []
            data = json.loads(proc.stdout or "{}")
        except Exception as exc:
            self._last_stats["syft"] = f"error: {exc}"
            return []
        findings: list[ScannerFinding] = []
        for artifact in data.get("artifacts", []) or []:
            if not isinstance(artifact, dict):
                continue
            eco = self._SYFT_ECO.get(str(artifact.get("type", "")).lower(), "")
            table = SYFT_CRYPTO_PACKAGES.get(eco, {}) if eco else {}
            info = table.get(str(artifact.get("name", "")).lower())
            if not info:
                continue
            canonical, original = normalize_algorithm(info["canonical"])
            version = str(artifact.get("version", ""))
            confidence = 0.4
            findings.append(ScannerFinding(
                canonical=canonical, original=original,
                library=str(artifact.get("name", "")).lower(),
                usage_state=UsageState.PROVIDED_ONLY, confidence=confidence,
                evidence=[create_evidence_signal(
                    tool="dependency:syft",
                    detail=f"syft package {artifact.get('name')}@{version}",
                    confidence=confidence,
                    snippet=f"{artifact.get('name')}@{version}"[:200])],
                location=Location(file=str(target_path)),
                implementation=Implementation(
                    library=str(artifact.get("name", "")).lower(),
                    version=version or None, provider="syft"),
                context=Context(exposure=Exposure.INTERNAL,
                                notes="Syft inventory; no confirmed crypto operation"),
                dependency_only=True,
            ))
        self._last_stats["syft"] = f"available:{len(findings)}"
        return findings

    def _run_cdxgen(self, target_path: Path) -> list[ScannerFinding]:
        import shutil
        import subprocess as _sp
        import tempfile
        if not shutil.which("cdxgen"):
            self._last_stats["cdxgen"] = "unavailable"
            return []
        try:
            with tempfile.TemporaryDirectory(prefix="ecdat-cdxgen-") as tmp:
                out = str(Path(tmp) / "bom.json")
                proc = _sp.run(["cdxgen", "-o", out, str(target_path)],
                               capture_output=True, text=True, timeout=180)
                if proc.returncode != 0 or not Path(out).is_file():
                    self._last_stats["cdxgen"] = \
                        f"failed: rc={proc.returncode}"
                    return []
                findings = self._scan_cyclonedx_json(Path(out))
                for finding in findings:
                    for ev in finding.evidence:
                        try:
                            ev.tool = "dependency:cdxgen"
                        except Exception:
                            pass
                    if finding.implementation is not None:
                        try:
                            finding.implementation.provider = "cdxgen"
                        except Exception:
                            pass
                self._last_stats["cdxgen"] = f"available:{len(findings)}"
                return findings
        except Exception as exc:
            self._last_stats["cdxgen"] = f"error: {exc}"
            return []

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
