from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


class JWKScanner(Scanner[ScannerFinding]):
    name = "certificate-jwk"
    version = "0.1.0"

    def can_scan_file(self, path: Path) -> bool:
        return path.suffix.lower() in (".jwk", ".jwks", ".json") and ("jwk" in path.name.lower() or "jwks" in path.name.lower())

    def is_available(self) -> bool:
        return True

    def get_tool_version(self) -> str:
        return "jwk-parser"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        findings: list[ScannerFinding] = []

        if target_path.is_file():
            findings.extend(self._scan_file(target_path))
        else:
            for jwk_file in target_path.rglob("*"):
                if jwk_file.is_file() and self.can_scan_file(jwk_file):
                    findings.extend(self._scan_file(jwk_file))

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _scan_file(self, file_path: Path) -> list[ScannerFinding]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(content)
        except Exception:
            return []

        findings: list[ScannerFinding] = []

        if "keys" in data:
            for i, key in enumerate(data["keys"]):
                findings.extend(self._parse_jwk(key, file_path, i))
        elif "kty" in data:
            findings.extend(self._parse_jwk(data, file_path, 0))

        return findings

    def _parse_jwk(self, key: dict, file_path: Path, index: int) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        kty = key.get("kty", "")
        use = key.get("use", "")
        alg = key.get("alg", "")
        kid = key.get("kid", f"key-{index}")

        canonical, original, key_size, curve = self._identify_jwk(key)

        if canonical:
            # Secret-safe: the snippet carries the PUBLIC view only (kty,
            # crv, x/y, n/e, alg, use, kid). Private members (d, k, p, q,
            # dp, dq, qi, oth) are never stored; the fingerprint covers
            # the public view so the same key links across surfaces.
            from ecdat.scanners.certificate.cert_metadata import (
                jwk_fingerprint, public_jwk_view)
            view = public_jwk_view(key)
            fingerprint = jwk_fingerprint(key)
            notes = f"fingerprint={fingerprint}" if fingerprint else ""
            findings.append(ScannerFinding(
                canonical=canonical,
                original=original,
                key_size=key_size,
                curve=curve,
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=0.7,
                evidence=[create_evidence_signal(
                    tool="certificate-jwk",
                    detail=f"JWK: kty={kty}, use={use}, alg={alg}, kid={kid}",
                    confidence=0.7,
                    snippet=f"JWK kid={kid}: {json.dumps(view)[:200]}",
                )],
                location=Location(file=str(file_path), uri=f"jwk:{kid}"),
                implementation=Implementation(library="JWK", provider="jwk"),
                context=Context(exposure=Exposure.INTERNAL,
                                notes=notes or None),
            ))

        return findings

    def _identify_jwk(self, key: dict) -> tuple[str, str, int | None, str | None]:
        kty = key.get("kty", "")
        alg = key.get("alg", "")
        crv = key.get("crv", "")

        if kty == "RSA":
            n = key.get("n", "")
            if n:
                key_size = len(n) * 6  # approximate
                return "RSA", "RSA", key_size, None
            return "RSA", "RSA", None, None

        elif kty == "EC":
            if crv == "P-256":
                return "ECDSA", "ECDSA", 256, "P-256"
            elif crv == "P-384":
                return "ECDSA", "ECDSA", 384, "P-384"
            elif crv == "P-521":
                return "ECDSA", "ECDSA", 521, "P-521"
            elif crv == "secp256k1":
                return "ECDSA", "ECDSA", 256, "secp256k1"
            return "ECDSA", "ECDSA", None, crv

        elif kty == "OKP":
            if crv == "Ed25519":
                return "Ed25519", "Ed25519", 256, None
            elif crv == "Ed448":
                return "Ed448", "Ed448", 448, None
            elif crv == "X25519":
                return "X25519", "X25519", 256, None
            elif crv == "X448":
                return "X448", "X448", 448, None
            return "OKP", crv, None, crv

        elif kty == "oct":
            return "Symmetric Key", "oct", None, None

        return None, None, None, None