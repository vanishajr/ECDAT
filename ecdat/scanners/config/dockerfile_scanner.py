"""Dockerfile / Containerfile definition scanner (Phase 5).

Local container-*definition* discovery belongs to the default
config-family scan (a repo-only scan must surface Dockerfile evidence
without opting into image pulls or the Docker daemon). Findings are
build-plan evidence, never proof of a deployed image: every finding is
``ProvidedOnly`` + ``dependency_only`` with a "container definition"
detail prefix, so fusion can never promote a Dockerfile into confirmed
deployment use. Full image analysis stays in the opt-in container
family (unified properly in Phase 7).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import (
    Scanner, ScannerFinding, ScannerRegistry, create_evidence_signal,
    normalize_finding,
)
from ecdat.core.cir_models import (
    Location, Implementation, Context, UsageState, Exposure,
)
from ecdat.core.signature_registry import normalize_algorithm, get_category

__all__ = ["DockerfileScanner"]

#: Base images that are themselves crypto-relevant capabilities.
_CRYPTO_BASE_IMAGES = {
    "openssl": "OpenSSL",
    "nginx": "TLS",
    "haproxy": "TLS",
    "traefik": "TLS",
    "caddy": "TLS",
    "certbot": "X.509",
    "vault": "Storage",
    "step-ca": "X.509",
    "smallstep": "X.509",
}

#: Package-install tokens -> capability canonical.
_CRYPTO_PACKAGES = {
    "openssl": "OpenSSL", "libssl": "OpenSSL", "libcrypto": "OpenSSL",
    "ca-certificates": "X.509", "certbot": "X.509",
    "gnutls": "GnuTLS", "libsodium": "libsodium", "sodium": "libsodium",
    "libgcrypt": "GnuTLS", "nettle": "GnuTLS",     "nss": "NSS",
    "mbed" + "tls": "mbedTLS", "wolfssl": "wolfSSL",
    "openssh": "SSH", "openssh-server": "SSH", "openssh-client": "SSH",
    "krb5": "Kerberos", "openvpn": "TLS", "strongswan": "IPsec",
}

_CERT_COPY_RE = re.compile(
    r"\.(pem|crt|cer|der|key|p12|pfx)\b", re.IGNORECASE)
_CONFIG_COPY_RE = re.compile(
    r"(nginx\.conf|httpd\.conf|ssl\.conf|openssl\.cnf|sshd_config)",
    re.IGNORECASE)
_EXPOSE_RE = re.compile(r"^EXPOSE\s+(.+)$", re.IGNORECASE)
_FROM_RE = re.compile(r"^FROM\s+(?:--[^\s]+\s+)*([^\s]+)", re.IGNORECASE)
_COPY_RE = re.compile(r"^COPY\s+(?:--[^\s]+\s+)*(.*?)\s+(\S+)\s*$", re.IGNORECASE)


class DockerfileScanner(Scanner[ScannerFinding]):
    name = "config-dockerfile"
    version = "0.1.0"

    def can_scan_file(self, path: Path) -> bool:
        name = path.name
        if name in ("Dockerfile", "Containerfile"):
            return True
        lowered = name.lower()
        return lowered.startswith("dockerfile.") or lowered.endswith(".dockerfile")

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return "dockerfile-parser"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []
        findings: list[ScannerFinding] = []
        if target_path.is_file():
            if self.can_scan_file(target_path):
                findings.extend(self._scan_file(target_path))
        else:
            for candidate in sorted(target_path.rglob("*")):
                if candidate.is_file() and self.can_scan_file(candidate):
                    findings.extend(self._scan_file(candidate))
        return [normalize_finding(f) for f in findings]

    def _scan_file(self, file_path: Path) -> list[ScannerFinding]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []
        findings: list[ScannerFinding] = []
        service_hint = file_path.parent.name
        logical = self._logical_lines(content.splitlines())
        for line_num, line in logical:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            upper = stripped.split(None, 1)[0].upper() if stripped.split() else ""
            if upper == "FROM":
                findings.extend(self._from_finding(
                    file_path, line_num, stripped, service_hint))
            elif upper in ("RUN", "ADD"):
                findings.extend(self._install_findings(
                    file_path, line_num, stripped, service_hint))
            elif upper == "COPY":
                findings.extend(self._copy_findings(
                    file_path, line_num, stripped, service_hint))
            elif upper in ("EXPOSE", "ENTRYPOINT", "CMD"):
                self._annotate_service(findings, stripped, upper)
        return findings

    @staticmethod
    def _logical_lines(lines: list[str]) -> list[tuple[int, str]]:
        """Join backslash continuations (first line number wins)."""
        logical: list[tuple[int, str]] = []
        buf, start = "", 0
        for idx, line in enumerate(lines, 1):
            chunk = line.rstrip()
            if not buf:
                start = idx
            if chunk.endswith("\\"):
                buf += chunk[:-1] + " "
            else:
                buf += line
                logical.append((start, buf))
                buf = ""
        if buf:
            logical.append((start, buf))
        return logical

    def _definition(self, file_path: Path, line: int, canonical: str,
                    original: str, detail: str, confidence: float,
                    service: str, extra_notes: str = "") -> ScannerFinding:
        canonical_norm, _original = normalize_algorithm(canonical)
        notes = f"container-definition; service={service}"
        if extra_notes:
            notes += f"; {extra_notes}"
        return ScannerFinding(
            canonical=canonical_norm,
            original=_original,
            library="docker",
            usage_state=UsageState.PROVIDED_ONLY,
            confidence=confidence,
            evidence=[create_evidence_signal(
                tool="config:dockerfile",
                detail=f"container definition (not deployed image): {detail}",
                confidence=confidence,
                snippet=original[:200],
            )],
            location=Location(file=str(file_path), line=line),
            implementation=Implementation(library="docker",
                                          provider="dockerfile"),
            context=Context(exposure=Exposure.INTERNAL, notes=notes),
            dependency_only=True,
        )

    def _from_finding(self, file_path: Path, line: int, stripped: str,
                      service: str) -> list[ScannerFinding]:
        match = _FROM_RE.match(stripped)
        if not match:
            return []
        image = match.group(1).strip("\"'")
        base = image.split("/")[-1].split(":")[0].lower()
        canonical = _CRYPTO_BASE_IMAGES.get(base, "")
        if not canonical:
            return []
        return [self._definition(
            file_path, line, canonical, stripped,
            f"base image {image} provides {canonical}", 0.55, service,
            extra_notes=f"base-image={image}")]

    def _install_findings(self, file_path: Path, line: int, stripped: str,
                          service: str) -> list[ScannerFinding]:
        lowered = stripped.lower()
        findings: list[ScannerFinding] = []
        for token, canonical in _CRYPTO_PACKAGES.items():
            if re.search(r"(?<![A-Za-z0-9_.\-])" + re.escape(token) + r"(?![A-Za-z0-9_.\-])",
                         lowered):
                findings.append(self._definition(
                    file_path, line, canonical, stripped,
                    f"package install provides {canonical} ({token})",
                    0.5, service))
        return findings

    def _copy_findings(self, file_path: Path, line: int, stripped: str,
                       service: str) -> list[ScannerFinding]:
        match = _COPY_RE.match(stripped)
        if not match:
            return []
        sources, dest = match.group(1), match.group(2)
        findings: list[ScannerFinding] = []
        cert_hit = _CERT_COPY_RE.search(sources)
        if cert_hit:
            kind = "key_ref" if cert_hit.group(1).lower() in (
                "key", "p12", "pfx") else "cert_ref"
            findings.append(self._definition(
                file_path, line, "X.509", stripped,
                f"baked-in certificate reference {sources.strip()} -> {dest}",
                0.55, service, extra_notes=f"{kind}={sources.strip()}"))
        config_hit = _CONFIG_COPY_RE.search(sources)
        if config_hit:
            findings.append(self._definition(
                file_path, line, "TLS", stripped,
                f"baked-in TLS config {sources.strip()} -> {dest}",
                0.5, service,
                extra_notes=f"config_ref={sources.strip()}"))
        return findings

    @staticmethod
    def _annotate_service(findings: list[ScannerFinding], stripped: str,
                          directive: str) -> None:
        """Fold EXPOSE/ENTRYPOINT hints into finding notes (no new rows)."""
        if directive == "EXPOSE":
            match = _EXPOSE_RE.match(stripped)
            extra = f"exposed-ports={match.group(1)}" if match else ""
        else:
            extra = f"{directive.lower()}={stripped.split(None, 1)[1] if len(stripped.split(None, 1)) > 1 else ''}"
        if not extra or "=" not in extra:
            return
        for finding in findings:
            try:
                notes = finding.context.notes or "" if finding.context else ""
                if "exposed-ports=" in notes or "entrypoint=" in notes:
                    continue
                if finding.context is None:
                    continue
                finding.context.notes = f"{notes}; {extra}" if notes else extra
            except Exception:
                continue


ScannerRegistry.register(DockerfileScanner())
