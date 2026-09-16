from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, OperationType, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import get_category, normalize_algorithm, is_library_only


"""
Semgrep-based source code scanner for cryptographic patterns.

NOTE: This scanner is NOT currently part of the active DiscoveryEngine pipeline.
It is a fully implemented but unused scanner that was developed as an alternative
pattern-matching approach using the semgrep tool. The active source scanner
uses AST-based analysis (see scanner.py and python_ast.py).

This module is retained for potential future integration if semgrep-based
detection proves superior for multi-language support. It is not imported,
instantiated, or called by SourceScanner or DiscoveryEngine.

To enable: add SemgrepScanner to DiscoveryEngine._all_scanners in
ecdat/scanners/discovery.py and ensure 'semgrep' CLI tool is installed.
"""

SEMGREP_RULES = r"""
rules:
  - id: crypto-aes-gcm
    pattern-either:
      - pattern: $X.AESGCM(...)
      - pattern: $X.AES.GCM(...)
      - pattern: AES_256_GCM
      - pattern: AES-256-GCM
    message: "AES-GCM detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: symmetric
      algorithm: AES-256-GCM
      confidence: 0.8

  - id: crypto-aes-cbc
    pattern-either:
      - pattern: $X.AES_CBC(...)
      - pattern: AES_256_CBC
      - pattern: AES-256-CBC
      - pattern: AES-CBC
    message: "AES-CBC detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: symmetric
      algorithm: AES-256-CBC
      confidence: 0.8

  - id: crypto-chacha20-poly1305
    pattern-either:
      - pattern: $X.ChaCha20Poly1305(...)
      - pattern: ChaCha20-Poly1305
      - pattern: CHACHA20_POLY1305
    message: "ChaCha20-Poly1305 detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: symmetric
      algorithm: ChaCha20-Poly1305
      confidence: 0.8

  - id: crypto-rsa
    pattern-either:
      - pattern: $X.RSA(...)
      - pattern: $X.RSA_public_encrypt(...)
      - pattern: $X.RSA_private_decrypt(...)
      - pattern: RSA_sign
      - pattern: RSA_verify
    message: "RSA detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: asymmetric
      algorithm: RSA
      confidence: 0.8

  - id: crypto-ecdsa
    pattern-either:
      - pattern: $X.ECDSA(...)
      - pattern: ECDSA_sign
      - pattern: ECDSA_verify
    message: "ECDSA detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: asymmetric
      algorithm: ECDSA
      confidence: 0.8

  - id: crypto-ecdh
    pattern-either:
      - pattern: $X.ECDH(...)
      - pattern: ECDH_key_agreement
    message: "ECDH detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: key_exchange
      algorithm: ECDH
      confidence: 0.8

  - id: crypto-x25519
    pattern-either:
      - pattern: $X.X25519(...)
      - pattern: X25519
      - pattern: Curve25519
    message: "X25519 detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: key_exchange
      algorithm: X25519
      confidence: 0.8

  - id: crypto-ed25519
    pattern-either:
      - pattern: $X.Ed25519(...)
      - pattern: Ed25519
      - pattern: EdDSA
    message: "Ed25519 detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: asymmetric
      algorithm: Ed25519
      confidence: 0.8

  - id: crypto-sha256
    pattern-either:
      - pattern: $X.SHA256(...)
      - pattern: SHA-256
      - pattern: SHA256
    message: "SHA-256 detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: hash
      algorithm: SHA-256
      confidence: 0.7

  - id: crypto-sha384
    pattern-either:
      - pattern: $X.SHA384(...)
      - pattern: SHA-384
      - pattern: SHA384
    message: "SHA-384 detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: hash
      algorithm: SHA-384
      confidence: 0.7

  - id: crypto-sha512
    pattern-either:
      - pattern: $X.SHA512(...)
      - pattern: SHA-512
      - pattern: SHA512
    message: "SHA-512 detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: hash
      algorithm: SHA-512
      confidence: 0.7

  - id: crypto-sha3
    pattern-either:
      - pattern: $X.SHA3_256(...)
      - pattern: $X.SHA3_512(...)
      - pattern: SHA3-256
      - pattern: SHA3-512
      - pattern: Keccak-256
      - pattern: Keccak-512
    message: "SHA-3 detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: hash
      algorithm: SHA-3-256
      confidence: 0.7

  - id: crypto-blake2
    pattern-either:
      - pattern: $X.BLAKE2b(...)
      - pattern: $X.BLAKE2s(...)
      - pattern: BLAKE2b
      - pattern: BLAKE2s
    message: "BLAKE2 detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: hash
      algorithm: BLAKE2b
      confidence: 0.7

  - id: crypto-pbkdf2
    pattern-either:
      - pattern: $X.PBKDF2(...)
      - pattern: PBKDF2
      - pattern: PBKDF2-HMAC-SHA256
      - pattern: PBKDF2-HMAC-SHA512
    message: "PBKDF2 detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: kdf
      algorithm: PBKDF2
      confidence: 0.8

  - id: crypto-hkdf
    pattern-either:
      - pattern: $X.HKDF(...)
      - pattern: HKDF
      - pattern: HKDF-SHA256
      - pattern: HKDF-SHA512
    message: "HKDF detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: kdf
      algorithm: HKDF
      confidence: 0.8

  - id: crypto-scrypt
    pattern-either:
      - pattern: $X.scrypt(...)
      - pattern: scrypt
    message: "scrypt detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: kdf
      algorithm: scrypt
      confidence: 0.8

  - id: crypto-argon2
    pattern-either:
      - pattern: $X.Argon2(...)
      - pattern: Argon2
      - pattern: Argon2id
      - pattern: Argon2i
    message: "Argon2 detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: kdf
      algorithm: Argon2
      confidence: 0.8

  - id: crypto-tls12
    pattern-either:
      - pattern: TLS1.2
      - pattern: TLSv1.2
      - pattern: tls12
    message: "TLS 1.2 detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust, yaml, json]
    metadata:
      category: protocol
      algorithm: TLS1.2
      confidence: 0.7

  - id: crypto-tls13
    pattern-either:
      - pattern: TLS1.3
      - pattern: TLSv1.3
      - pattern: tls13
    message: "TLS 1.3 detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust, yaml, json]
    metadata:
      category: protocol
      algorithm: TLS1.3
      confidence: 0.7

  - id: crypto-ssl
    pattern-either:
      - pattern: SSLv2
      - pattern: SSLv3
      - pattern: SSL
    message: "SSL detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust, yaml, json]
    metadata:
      category: protocol
      algorithm: SSL
      confidence: 0.7

  - id: crypto-ssh
    pattern-either:
      - pattern: SSH-2
      - pattern: SSH
    message: "SSH detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust, yaml, json]
    metadata:
      category: protocol
      algorithm: SSH
      confidence: 0.7

  - id: crypto-ml-kem
    pattern-either:
      - pattern: ML-KEM
      - pattern: Kyber
      - pattern: Kyber512
      - pattern: Kyber768
      - pattern: Kyber1024
    message: "ML-KEM/Kyber detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: pqc_kem
      algorithm: ML-KEM
      confidence: 0.8

  - id: crypto-ml-dsa
    pattern-either:
      - pattern: ML-DSA
      - pattern: Dilithium
      - pattern: Dilithium2
      - pattern: Dilithium3
      - pattern: Dilithium5
    message: "ML-DSA/Dilithium detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: pqc_sig
      algorithm: ML-DSA
      confidence: 0.8

  - id: crypto-slh-dsa
    pattern-either:
      - pattern: SLH-DSA
      - pattern: SPHINCS+
      - pattern: SPHINCSplus
    message: "SLH-DSA/SPHINCS+ detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: pqc_sig
      algorithm: SLH-DSA
      confidence: 0.8

  - id: crypto-falcon
    pattern-either:
      - pattern: Falcon
      - pattern: Falcon-512
      - pattern: Falcon-1024
    message: "Falcon detected"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: pqc_sig
      algorithm: Falcon
      confidence: 0.8

  - id: crypto-insecure-md5
    pattern-either:
      - pattern: $X.MD5(...)
      - pattern: MD5
    message: "MD5 detected (insecure)"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: hash
      algorithm: MD5
      confidence: 0.7

  - id: crypto-insecure-sha1
    pattern-either:
      - pattern: $X.SHA1(...)
      - pattern: SHA1
      - pattern: SHA-1
    message: "SHA-1 detected (insecure)"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: hash
      algorithm: SHA-1
      confidence: 0.7

  - id: crypto-insecure-des
    pattern-either:
      - pattern: $X.DES(...)
      - pattern: DES
    message: "DES detected (insecure)"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: symmetric
      algorithm: DES
      confidence: 0.8

  - id: crypto-insecure-3des
    pattern-either:
      - pattern: $X.DES3(...)
      - pattern: 3DES
      - pattern: DES-EDE3
    message: "3DES detected (insecure)"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: symmetric
      algorithm: 3DES
      confidence: 0.8

  - id: crypto-insecure-rc4
    pattern-either:
      - pattern: $X.RC4(...)
      - pattern: RC4
      - pattern: ARC4
    message: "RC4 detected (insecure)"
    languages: [python, javascript, typescript, go, java, c, cpp, rust]
    metadata:
      category: symmetric
      algorithm: RC4
      confidence: 0.8
"""


class SemgrepScanner(Scanner[ScannerFinding]):
    name = "source-semgrep"
    version = "0.1.0"

    def __init__(self) -> None:
        self._rules_path: Optional[Path] = None
        self._semgrep_available = self._check_semgrep()

    def _check_semgrep(self) -> bool:
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def is_available(self) -> bool:
        return self._semgrep_available

    def can_scan_file(self, path: Path) -> bool:
        return path.is_file() and path.suffix in {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java",
            ".c", ".cpp", ".cc", ".h", ".hpp", ".rs", ".cs",
            ".rb", ".php", ".swift", ".kt", ".scala", ".clj",
            ".yaml", ".yml", ".json", ".toml", ".xml"
        }

    def get_tool_version(self) -> str:
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return f"semgrep-{result.stdout.strip()}"
        except Exception:
            pass
        return "semgrep-unknown"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        if not self._semgrep_available:
            return []

        target_path = Path(target)
        if not target_path.exists():
            return []

        self._ensure_rules()

        findings: list[ScannerFinding] = []

        try:
            cmd = [
                "semgrep",
                "scan",
                "--config", str(self._rules_path),
                "--json",
                "--quiet",
                str(target_path),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode in (0, 1):
                findings = self._parse_results(result.stdout, target_path)
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _ensure_rules(self) -> None:
        if self._rules_path and self._rules_path.exists():
            return

        import tempfile
        self._rules_path = Path(tempfile.gettempdir()) / "ecdat_semgrep_rules.yaml"
        self._rules_path.write_text(SEMGREP_RULES)

    def _parse_results(self, json_output: str, target_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return findings

        for result in data.get("results", []):
            finding = self._convert_result(result, target_path)
            if finding:
                findings.append(finding)

        return findings

    def _convert_result(self, result: dict, target_path: Path) -> ScannerFinding | None:
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        algorithm = metadata.get("algorithm", "Unknown")
        category = metadata.get("category", "unknown")
        confidence = metadata.get("confidence", 0.5)

        canonical, original = normalize_algorithm(algorithm)

        if category == "library":
            usage_state = UsageState.PROVIDED_ONLY
            confidence = min(confidence, 0.4)
        elif confidence >= 0.8:
            usage_state = UsageState.CONFIRMED
        elif confidence >= 0.5:
            usage_state = UsageState.PROBABLE
        else:
            usage_state = UsageState.POSSIBLE

        path = result.get("path", "")
        start_line = result.get("start", {}).get("line", 0)
        end_line = result.get("end", {}).get("line", 0)

        snippet = extra.get("lines", "")

        return ScannerFinding(
            canonical=canonical,
            original=original,
            usage_state=usage_state,
            confidence=confidence,
            evidence=[create_evidence_signal(
                tool="source-semgrep",
                detail=extra.get("message", f"Semgrep match: {algorithm}"),
                confidence=confidence,
                snippet=snippet[:500] if snippet else None,
            )],
            location=Location(
                file=path,
                line=start_line if start_line > 0 else None,
            ),
            implementation=Implementation(library="unknown", api=algorithm),
            context=Context(exposure=Exposure.INTERNAL),
        )