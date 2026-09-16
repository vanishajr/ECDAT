from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.scanners.path_policy import iter_project_files_matching
from ecdat.core.signature_registry import get_category, normalize_algorithm
from ecdat.core.cir_models import UsageState, OperationType, Location, Implementation, Context, Exposure


CRYPTO_IMPORT_PATTERNS = {
    "cryptography.hazmat.primitives.asymmetric": ["rsa", "dsa", "dh", "ec", "ed25519", "ed448", "x25519", "x448"],
    "cryptography.hazmat.primitives.ciphers": ["aes", "des", "3des", "chacha20", "chachapoly"],
    "cryptography.hazmat.primitives.hashes": ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s"],
    "cryptography.hazmat.primitives.kdf": ["pbkdf2", "hkdf", "scrypt", "argon2"],
    "cryptography.hazmat.primitives.serialization": ["pkcs12", "pem", "der"],
    "Crypto.Cipher": ["AES", "DES", "DES3", "ARC4", "ChaCha20"],
    "Crypto.PublicKey": ["RSA", "DSA", "ECC", "ElGamal"],
    "Crypto.Hash": ["MD5", "SHA1", "SHA256", "SHA384", "SHA512", "SHA3_256", "SHA3_512", "BLAKE2b", "BLAKE2s"],
    "Crypto.Protocol.KDF": ["PBKDF2", "HKDF", "scrypt"],
    "Crypto.Signature": ["pkcs1_15", "pss", "dss", "ecdsa"],
    "hashlib": ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s"],
    "secrets": ["token_bytes", "token_hex", "token_urlsafe"],
    "ssl": ["SSLContext", "PROTOCOL_TLS", "PROTOCOL_TLSv1_2", "PROTOCOL_TLSv1_3"],
    "OpenSSL": ["crypto", "SSL"],
    "pqc": ["kyber", "dilithium", "falcon", "sphincs"],
    "liboqs": ["KEM", "SIG"],
}

CRYPTO_CLASS_PATTERNS = {
    "AES": "AES",
    "AESGCM": "AES-GCM",
    "AESCCM": "AES-CCM",
    "ChaCha20Poly1305": "ChaCha20-Poly1305",
    "ChaCha20": "ChaCha20",
    "DES": "DES",
    "DES3": "3DES",
    "ARC4": "RC4",
    "RSA": "RSA",
    "DSA": "DSA",
    "DH": "DH",
    "ECDH": "ECDH",
    "ECDSA": "ECDSA",
    "Ed25519": "Ed25519",
    "Ed448": "Ed448",
    "X25519": "X25519",
    "X448": "X448",
    "MD5": "MD5",
    "SHA1": "SHA-1",
    "SHA224": "SHA-256",
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
    "SHA3_224": "SHA-3-256",
    "SHA3_256": "SHA-3-256",
    "SHA3_384": "SHA-3-512",
    "SHA3_512": "SHA-3-512",
    "BLAKE2b": "BLAKE2b",
    "BLAKE2s": "BLAKE2s",
    "PBKDF2": "PBKDF2",
    "PBKDF2HMAC": "PBKDF2",
    "HKDF": "HKDF",
    "HKDFExpand": "HKDF",
    "HKDFExtract": "HKDF",
    "Scrypt": "scrypt",
    "Argon2": "Argon2",
    "Argon2id": "Argon2",
}

CRYPTO_METHOD_PATTERNS = {
    "encrypt": OperationType.ENCRYPT,
    "decrypt": OperationType.DECRYPT,
    "sign": OperationType.SIGN,
    "verify": OperationType.VERIFY,
    "derive": OperationType.KEY_EXCHANGE,
    "key_exchange": OperationType.KEY_EXCHANGE,
    "digest": OperationType.HASH,
    "update": OperationType.HASH,
    "finalize": OperationType.HASH,
    "hexdigest": OperationType.HASH,
}


class PythonASTScanner(Scanner[ScannerFinding]):
    name = "source-python-ast"
    version = "0.1.0"

    def __init__(self) -> None:
        self._imports: dict[str, list[str]] = {}
        self._current_file: Optional[Path] = None
        self._source_lines: list[str] = []

    def can_scan_file(self, path: Path) -> bool:
        return path.suffix == ".py"

    def is_available(self) -> bool:
        return True

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        if not target_path.exists():
            return []

        all_findings: list[ScannerFinding] = []

        if target_path.is_file():
            if self.can_scan_file(target_path):
                all_findings.extend(self._scan_file(target_path))
        else:
            for py_file in iter_project_files_matching(target_path, {".py"}):
                try:
                    all_findings.extend(self._scan_file(py_file))
                except Exception:
                    continue

        normalized = [normalize_finding(f) for f in all_findings]
        return normalized

    def _scan_file(self, file_path: Path) -> list[ScannerFinding]:
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        self._current_file = file_path
        self._source_lines = source.splitlines()
        self._imports = {}

        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            return []

        visitor = CryptoASTVisitor(self)
        visitor.visit(tree)

        return visitor.findings


class CryptoASTVisitor(ast.NodeVisitor):
    def __init__(self, scanner: PythonASTScanner) -> None:
        self.scanner = scanner
        self.findings: list[ScannerFinding] = []
        self._call_stack: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._record_import(alias.name, alias.asname or alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for alias in node.names:
                full_name = f"{node.module}.{alias.name}"
                self._record_import(node.module, alias.name, node.lineno, full_name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._analyze_call(node)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.generic_visit(node)

    def _record_import(self, module: str, name: str, lineno: int, full_name: Optional[str] = None) -> None:
        if module not in self.scanner._imports:
            self.scanner._imports[module] = []
        self.scanner._imports[module].append(name)

        for crypto_module, crypto_names in CRYPTO_IMPORT_PATTERNS.items():
            if module.startswith(crypto_module) or crypto_module in module:
                for cn in crypto_names:
                    if cn.lower() in name.lower() or cn.lower() in module.lower():
                        finding = self._create_finding_from_import(module, name, full_name or f"{module}.{name}", lineno)
                        if finding:
                            self.findings.append(finding)

    def _create_finding_from_import(self, module: str, name: str, full_name: str, lineno: int) -> ScannerFinding | None:
        canonical, original = normalize_algorithm(name)
        category = get_category(canonical)

        if category == "library":
            usage_state = UsageState.PROVIDED_ONLY
            confidence = 0.3
        else:
            usage_state = UsageState.POSSIBLE
            confidence = 0.4

        snippet = self._get_snippet(lineno)

        return ScannerFinding(
            canonical=canonical,
            original=name,
            library=module,
            usage_state=usage_state,
            confidence=confidence,
            evidence=[create_evidence_signal(
                tool="source-python-ast",
                detail=f"Import: {full_name}",
                confidence=confidence,
                snippet=snippet,
            )],
            location=Location(file=str(self.scanner._current_file), line=lineno),
            implementation=Implementation(library=module, api=full_name),
            context=Context(exposure=Exposure.INTERNAL),
        )

    def _analyze_call(self, node: ast.Call) -> None:
        func_name = self._get_call_name(node)
        if not func_name:
            return

        for pattern, op_type in CRYPTO_METHOD_PATTERNS.items():
            if pattern in func_name.lower():
                canonical_algo = self._infer_algorithm_from_context(node, func_name)
                if canonical_algo:
                    finding = self._create_finding_from_call(canonical_algo, func_name, op_type, node.lineno)
                    if finding:
                        self.findings.append(finding)
                break

        for class_name, canonical in CRYPTO_CLASS_PATTERNS.items():
            if class_name.lower() in func_name.lower():
                finding = self._create_finding_from_call(canonical, func_name, op_type or OperationType.KEY_MANAGEMENT, node.lineno)
                if finding:
                    self.findings.append(finding)
                break

    def _get_call_name(self, node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None

    def _infer_algorithm_from_context(self, node: ast.Call, func_name: str) -> str | None:
        for kw in node.keywords:
            if kw.arg in ("algorithm", "hash_algorithm", "cipher", "curve"):
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    return kw.value.value
                if isinstance(kw.value, ast.Name):
                    return kw.value.id
                if isinstance(kw.value, ast.Attribute):
                    return kw.value.attr

        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                val = arg.value.upper()
                if any(algo in val for algo in ["AES", "RSA", "SHA", "ECDSA", "ED25519", "X25519", "CHACHA", "PBKDF2", "HKDF", "SCRYPT", "ARGON2"]):
                    return arg.value

        return None

    def _create_finding_from_call(self, canonical: str, func_name: str, op_type: OperationType, lineno: int) -> ScannerFinding | None:
        canonical, original = normalize_algorithm(canonical)
        category = get_category(canonical)

        has_direct = True
        confidence = 0.85
        usage_state = UsageState.CONFIRMED

        snippet = self._get_snippet(lineno)

        lib = self._infer_library(func_name)

        return ScannerFinding(
            canonical=canonical,
            original=original,
            library=lib,
            usage_state=usage_state,
            confidence=confidence,
            evidence=[create_evidence_signal(
                tool="source-python-ast",
                detail=f"Direct API call: {func_name}",
                confidence=confidence,
                snippet=snippet,
            )],
            location=Location(file=str(self.scanner._current_file), line=lineno, function=func_name),
            implementation=Implementation(library=lib or "unknown", api=func_name),
            operation_type=op_type,
            function=func_name,
            context=Context(exposure=Exposure.INTERNAL),
        )

    def _infer_library(self, func_name: str) -> str | None:
        if func_name.startswith("cryptography."):
            return "cryptography"
        if func_name.startswith("Crypto."):
            return "pycryptodome"
        if func_name.startswith("hashlib."):
            return "hashlib"
        if func_name.startswith("ssl."):
            return "ssl"
        if func_name.startswith("OpenSSL."):
            return "OpenSSL"
        return None

    def _get_snippet(self, lineno: int, context: int = 2) -> str | None:
        if not self.scanner._source_lines:
            return None
        start = max(0, lineno - context - 1)
        end = min(len(self.scanner._source_lines), lineno + context)
        lines = self.scanner._source_lines[start:end]
        return "\n".join(lines)


from ecdat.core.cir_models import OperationType
