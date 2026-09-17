from __future__ import annotations

import socket
import subprocess
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class SSHScanner(Scanner[ScannerFinding]):
    name = "runtime-ssh"
    version = "0.1.0"

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def can_scan_target(self, target: str) -> bool:
        return target.startswith("ssh://") or (":" in target and not target.startswith(("http://", "https://")))

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        try:
            result = subprocess.run(["ssh", "-V"], capture_output=True, text=True, timeout=5)
            return f"ssh-{result.stderr.strip()}" if result.stderr else "ssh-unknown"
        except Exception:
            return "ssh-unknown"

    def scan(self, target: str, **kwargs) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        if target.startswith("ssh://"):
            target = target[6:]

        host, port = self._parse_target(target)
        if not host:
            return findings

        try:
            result = self._probe_ssh(host, port)
            if result:
                findings.extend(self._create_findings(result))
        except Exception:
            pass

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _parse_target(self, target: str) -> tuple[str, int] | tuple[None, None]:
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 22
            return host, port
        return target, 22

    def _probe_ssh(self, host: str, port: int) -> dict | None:
        try:
            result = subprocess.run(
                ["ssh-keyscan", "-T", str(int(self.timeout)), "-p", str(port), host],
                capture_output=True,
                text=True,
                timeout=self.timeout + 5,
            )
            if result.returncode == 0 and result.stdout:
                return self._parse_ssh_keyscan(result.stdout, host, port)
        except Exception:
            pass

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                return {"banner": banner, "host": host, "port": port}
        except Exception:
            pass

        return None

    def _parse_ssh_keyscan(self, output: str, host: str, port: int) -> dict:
        keys = []
        for line in output.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                keys.append({
                    "host": parts[0],
                    "key_type": parts[1],
                    "key_data": parts[2],
                })
        return {"keys": keys, "host": host, "port": port}

    def _create_findings(self, result: dict) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        from datetime import datetime, timezone
        probed_at = datetime.now(timezone.utc).isoformat()
        endpoint = f"{result.get('host')}:{result.get('port')}"

        if "banner" in result:
            banner = result["banner"]
            findings.append(ScannerFinding(
                canonical="SSH",
                original="SSH Banner",
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.7,
                evidence=[create_evidence_signal(
                    tool="runtime-ssh",
                    detail=f"SSH Banner: {banner.strip()}",
                    confidence=0.7,
                    snippet=banner.strip()[:200],
                )],
                location=Location(uri=f"ssh://{result['host']}:{result['port']}"),
                implementation=Implementation(library="OpenSSH", provider="runtime-ssh", api="SSH banner"),
                context=Context(exposure=Exposure.INTERNET_FACING,
                                notes=f"endpoint={endpoint}; "
                                      f"tool={self.get_tool_version()}; "
                                      f"probed_at={probed_at}"),
            ))

        if "keys" in result:
            for key in result["keys"]:
                key_type = key["key_type"]
                canonical, original = self._parse_ssh_key_type(key_type)
                fingerprint = ""
                try:
                    import base64
                    from ecdat.scanners.certificate.cert_metadata import (
                        openssh_fingerprint)
                    fingerprint = openssh_fingerprint(
                        base64.b64decode(key["key_data"]))
                except Exception:
                    fingerprint = ""
                notes = (f"endpoint={endpoint}; "
                         f"tool={self.get_tool_version()}; "
                         f"probed_at={probed_at}")
                if fingerprint:
                    notes += f"; fingerprint={fingerprint}"
                findings.append(ScannerFinding(
                    canonical=canonical,
                    original=original,
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=0.8,
                    evidence=[create_evidence_signal(
                        tool="runtime-ssh",
                        detail=f"SSH host key: {key_type}",
                        confidence=0.8,
                        snippet=f"{key_type} {key['key_data'][:50]}...",
                    )],
                    location=Location(uri=f"ssh://{result['host']}:{result['port']}"),
                    implementation=Implementation(library="OpenSSH", provider="runtime-ssh", api="SSH host key"),
                    context=Context(exposure=Exposure.INTERNET_FACING,
                                    notes=notes),
                ))

        return findings

    def _parse_ssh_key_type(self, key_type: str) -> tuple[str, str]:
        mapping = {
            "ssh-rsa": ("RSA", "ssh-rsa"),
            "ssh-dss": ("DSA", "ssh-dss"),
            "ssh-ed25519": ("Ed25519", "ssh-ed25519"),
            "ecdsa-sha2-nistp256": ("ECDSA", "ecdsa-sha2-nistp256"),
            "ecdsa-sha2-nistp384": ("ECDSA", "ecdsa-sha2-nistp384"),
            "ecdsa-sha2-nistp521": ("ECDSA", "ecdsa-sha2-nistp521"),
            "rsa-sha2-256": ("RSA", "rsa-sha2-256"),
            "rsa-sha2-512": ("RSA", "rsa-sha2-512"),
        }
        return mapping.get(key_type, ("Public Key", key_type))