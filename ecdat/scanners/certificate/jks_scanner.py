from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class JKSScanner(Scanner[ScannerFinding]):
    name = "certificate-jks"
    version = "0.1.0"

    def can_scan_file(self, path: Path) -> bool:
        return path.suffix.lower() in (".jks", ".keystore", ".truststore") or "keystore" in path.name.lower() or "truststore" in path.name.lower()

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return "jks-parser"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        findings: list[ScannerFinding] = []

        if target_path.is_file():
            findings.extend(self._scan_file(target_path))
        else:
            for jks_file in target_path.rglob("*"):
                if jks_file.is_file() and self.can_scan_file(jks_file):
                    findings.extend(self._scan_file(jks_file))

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _scan_file(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        password = kwargs.get("password", "") if "kwargs" in dir() else ""

        try:
            import subprocess
            result = subprocess.run(
                ["keytool", "-list", "-v", "-keystore", str(file_path), "-storepass", password],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                findings.extend(self._parse_keytool_output(result.stdout, file_path))
            else:
                for pw in ["", "changeit", "changeme", "password", "secret", "keystore"]:
                    if pw == password:
                        continue
                    result = subprocess.run(
                        ["keytool", "-list", "-v", "-keystore", str(file_path), "-storepass", pw],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    if result.returncode == 0:
                        findings.extend(self._parse_keytool_output(result.stdout, file_path))
                        break
        except Exception:
            pass

        return findings

    def _parse_keytool_output(self, output: str, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        lines = output.splitlines()
        current_entry = {}
        entries = []

        for line in lines:
            line = line.strip()
            if line.startswith("Alias name:"):
                if current_entry:
                    entries.append(current_entry)
                current_entry = {"alias": line.split(":", 1)[1].strip()}
            elif line.startswith("Entry type:"):
                current_entry["type"] = line.split(":", 1)[1].strip()
            elif line.startswith("Owner:"):
                current_entry["owner"] = line.split(":", 1)[1].strip()
            elif line.startswith("Issuer:"):
                current_entry["issuer"] = line.split(":", 1)[1].strip()
            elif line.startswith("Serial number:"):
                current_entry["serial"] = line.split(":", 1)[1].strip()
            elif line.startswith("Valid from:"):
                current_entry["valid_from"] = line.split(":", 1)[1].strip()
            elif line.startswith("Until:"):
                current_entry["valid_until"] = line.split(":", 1)[1].strip()
            elif line.startswith("Certificate fingerprints:"):
                current_entry["fingerprints"] = True
            elif line.startswith("Key algorithm:"):
                current_entry["key_algo"] = line.split(":", 1)[1].strip()
            elif line.startswith("Key size:"):
                current_entry["key_size"] = line.split(":", 1)[1].strip()
            elif line.startswith("Signature algorithm:"):
                current_entry["sig_algo"] = line.split(":", 1)[1].strip()

        if current_entry:
            entries.append(current_entry)

        for entry in entries:
            entry_type = entry.get("type", "")
            alias = entry.get("alias", "unknown")

            if entry_type in ("PrivateKeyEntry", "KeyEntry"):
                key_algo = entry.get("key_algo", "Unknown")
                key_size = entry.get("key_size", "Unknown")
                canonical, original = normalize_algorithm(key_algo)

                findings.append(ScannerFinding(
                    canonical=canonical,
                    original=original,
                    key_size=int(key_size) if key_size.isdigit() else None,
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=0.8,
                    evidence=[create_evidence_signal(
                        tool="certificate-jks",
                        detail=f"JKS PrivateKeyEntry: alias={alias}, algo={key_algo}, size={key_size}",
                        confidence=0.8,
                        snippet=f"Alias: {alias}, Type: {entry_type}",
                    )],
                    location=Location(file=str(file_path), uri=f"jks:{alias}"),
                    implementation=Implementation(library="JKS", provider="keytool"),
                    context=Context(exposure=Exposure.INTERNAL),
                ))

            elif entry_type in ("TrustedCertEntry", "TrustedCert"):
                sig_algo = entry.get("sig_algo", "Unknown")
                canonical, original = normalize_algorithm(self._map_sig_algorithm(sig_algo))

                findings.append(ScannerFinding(
                    canonical=canonical,
                    original=original,
                    usage_state=UsageState.PROVIDED_ONLY,
                    confidence=0.7,
                    evidence=[create_evidence_signal(
                        tool="certificate-jks",
                        detail=f"JKS TrustedCertEntry: alias={alias}, sig_algo={sig_algo}",
                        confidence=0.7,
                        snippet=f"Alias: {alias}, Type: {entry_type}",
                    )],
                    location=Location(file=str(file_path), uri=f"jks:{alias}"),
                    implementation=Implementation(library="JKS", provider="keytool"),
                    context=Context(exposure=Exposure.INTERNAL),
                ))

        return findings

    def _map_sig_algorithm(self, sig_algo: str) -> str:
        mapping = {
            "SHA256withRSA": "RSA",
            "SHA384withRSA": "RSA",
            "SHA512withRSA": "RSA",
            "SHA1withRSA": "RSA",
            "SHA256withECDSA": "ECDSA",
            "SHA384withECDSA": "ECDSA",
            "SHA512withECDSA": "ECDSA",
            "SHA1withECDSA": "ECDSA",
            "Ed25519": "Ed25519",
            "Ed448": "Ed448",
        }
        return mapping.get(sig_algo, sig_algo)