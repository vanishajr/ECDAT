from __future__ import annotations

import ast
import hashlib
import re
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
    RiskInputs,
    UsageState,
    OperationType,
    Exposure,
    EvidenceSignal,
)
from ecdat.core.signature_registry import (
    get_category,
    get_key_sizes,
    get_mode,
    get_curves,
    infer_operation_type,
    normalize_algorithm,
)


PYTHON_CRYPTO_PATTERNS = {
    "cryptography.hazmat.primitives.ciphers.aead.AESGCM": ("AES-256-GCM", OperationType.ENCRYPT),
    "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305": ("ChaCha20-Poly1305", OperationType.ENCRYPT),
    "cryptography.hazmat.primitives.ciphers.Cipher": ("AES", OperationType.ENCRYPT),
    "cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey": ("RSA", OperationType.SIGN),
    "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey": ("RSA", OperationType.ENCRYPT),
    "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key": ("RSA", OperationType.KEY_MANAGEMENT),
    "cryptography.hazmat.primitives.asymmetric.rsa.generate_public_key": ("RSA", OperationType.KEY_MANAGEMENT),
    "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey": ("ECDSA", OperationType.SIGN),
    "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey": ("ECDH", OperationType.KEY_EXCHANGE),
    "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key": ("ECDSA", OperationType.KEY_MANAGEMENT),
    "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey": ("X25519", OperationType.KEY_EXCHANGE),
    "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate": ("X25519", OperationType.KEY_MANAGEMENT),
    "cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey": ("X448", OperationType.KEY_EXCHANGE),
    "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey": ("Ed25519", OperationType.SIGN),
    "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate": ("Ed25519", OperationType.KEY_MANAGEMENT),
    "cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey": ("Ed448", OperationType.SIGN),
    "cryptography.hazmat.primitives.hashes.Hash": ("SHA-256", OperationType.HASH),
    "cryptography.hazmat.primitives.hashes.MD5": ("MD5", OperationType.HASH),
    "cryptography.hazmat.primitives.hashes.SHA1": ("SHA-1", OperationType.HASH),
    "cryptography.hazmat.primitives.hashes.SHA256": ("SHA-256", OperationType.HASH),
    "cryptography.hazmat.primitives.hashes.SHA384": ("SHA-384", OperationType.HASH),
    "cryptography.hazmat.primitives.hashes.SHA512": ("SHA-512", OperationType.HASH),
    "cryptography.hazmat.primitives.hashes.SHA3_256": ("SHA-3-256", OperationType.HASH),
    "cryptography.hazmat.primitives.hashes.SHA3_512": ("SHA-3-512", OperationType.HASH),
    "cryptography.hazmat.primitives.hashes.BLAKE2b": ("BLAKE2b", OperationType.HASH),
    "cryptography.hazmat.primitives.hashes.BLAKE2s": ("BLAKE2s", OperationType.HASH),
    "cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC": ("PBKDF2", OperationType.KDF),
    "cryptography.hazmat.primitives.kdf.hkdf.HKDF": ("HKDF", OperationType.KDF),
    "cryptography.hazmat.primitives.kdf.scrypt.Scrypt": ("scrypt", OperationType.KDF),
    "cryptography.hazmat.primitives.kdf.bcrypt.BCrypt": ("bcrypt", OperationType.KDF),
    "cryptography.hazmat.primitives.kdf.argon2.Argon2id": ("Argon2", OperationType.KDF),
    "cryptography.hazmat.primitives.kdf.argon2.Argon2i": ("Argon2", OperationType.KDF),
    "cryptography.hazmat.primitives.kdf.argon2.Argon2d": ("Argon2", OperationType.KDF),
    "Crypto.Cipher.AES": ("AES", OperationType.ENCRYPT),
    "Crypto.Cipher.DES": ("DES", OperationType.ENCRYPT),
    "Crypto.Cipher.DES3": ("3DES", OperationType.ENCRYPT),
    "Crypto.Cipher.ARC4": ("RC4", OperationType.ENCRYPT),
    "Crypto.Cipher.ChaCha20": ("ChaCha20", OperationType.ENCRYPT),
    "Crypto.Cipher.ChaCha20_Poly1305": ("ChaCha20-Poly1305", OperationType.ENCRYPT),
    "Crypto.PublicKey.RSA": ("RSA", OperationType.KEY_MANAGEMENT),
    "Crypto.PublicKey.DSA": ("DSA", OperationType.KEY_MANAGEMENT),
    "Crypto.PublicKey.ECC": ("ECDSA", OperationType.KEY_MANAGEMENT),
    "Crypto.Signature.pkcs1_15": ("RSA", OperationType.SIGN),
    "Crypto.Signature.pss": ("RSA", OperationType.SIGN),
    "Crypto.Signature.DSS": ("DSA", OperationType.SIGN),
    "Crypto.Hash.MD5": ("MD5", OperationType.HASH),
    "Crypto.Hash.SHA": ("SHA-1", OperationType.HASH),
    "Crypto.Hash.SHA256": ("SHA-256", OperationType.HASH),
    "Crypto.Hash.SHA384": ("SHA-384", OperationType.HASH),
    "Crypto.Hash.SHA512": ("SHA-512", OperationType.HASH),
    "Crypto.Hash.SHA3_256": ("SHA-3-256", OperationType.HASH),
    "Crypto.Hash.SHA3_512": ("SHA-3-512", OperationType.HASH),
    "Crypto.Hash.BLAKE2b": ("BLAKE2b", OperationType.HASH),
    "Crypto.Hash.BLAKE2s": ("BLAKE2s", OperationType.HASH),
    "Crypto.Protocol.KDF.PBKDF2": ("PBKDF2", OperationType.KDF),
    "Crypto.Protocol.KDF.HKDF": ("HKDF", OperationType.KDF),
    "Crypto.Protocol.KDF.scrypt": ("scrypt", OperationType.KDF),
    "hashlib.md5": ("MD5", OperationType.HASH),
    "hashlib.sha1": ("SHA-1", OperationType.HASH),
    "hashlib.sha256": ("SHA-256", OperationType.HASH),
    "hashlib.sha384": ("SHA-384", OperationType.HASH),
    "hashlib.sha512": ("SHA-512", OperationType.HASH),
    "hashlib.sha3_256": ("SHA-3-256", OperationType.HASH),
    "hashlib.sha3_512": ("SHA-3-512", OperationType.HASH),
    "hashlib.blake2b": ("BLAKE2b", OperationType.HASH),
    "hashlib.blake2s": ("BLAKE2s", OperationType.HASH),
    "hashlib.pbkdf2_hmac": ("PBKDF2", OperationType.KDF),
    "secrets.token_bytes": ("Random", OperationType.KEY_MANAGEMENT),
    "os.urandom": ("Random", OperationType.KEY_MANAGEMENT),
    "ssl.create_default_context": ("TLS1.2", OperationType.TLS),
    "ssl.SSLContext": ("TLS1.2", OperationType.TLS),
    "OpenSSL.crypto": ("OpenSSL", OperationType.KEY_MANAGEMENT),
    "OpenSSL.SSL": ("TLS1.2", OperationType.TLS),
    "cryptography.hazmat.primitives.serialization.load_pem_private_key": ("RSA", OperationType.KEY_MANAGEMENT),
    "cryptography.hazmat.primitives.serialization.load_pem_public_key": ("RSA", OperationType.KEY_MANAGEMENT),
    "cryptography.hazmat.primitives.serialization.load_der_private_key": ("RSA", OperationType.KEY_MANAGEMENT),
    "cryptography.hazmat.primitives.serialization.load_der_public_key": ("RSA", OperationType.KEY_MANAGEMENT),
}

IMPORT_ALIASES = {
    "AESGCM": "cryptography.hazmat.primitives.ciphers.aead.AESGCM",
    "ChaCha20Poly1305": "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305",
    "Cipher": "cryptography.hazmat.primitives.ciphers.Cipher",
    "RSA": "cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey",
    "ECDSA": "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey",
    "ECDH": "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey",
    "X25519": "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey",
    "X448": "cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey",
    "Ed25519": "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey",
    "Ed448": "cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey",
    "Hash": "cryptography.hazmat.primitives.hashes.Hash",
    "MD5": "cryptography.hazmat.primitives.hashes.MD5",
    "SHA1": "cryptography.hazmat.primitives.hashes.SHA1",
    "SHA256": "cryptography.hazmat.primitives.hashes.SHA256",
    "SHA384": "cryptography.hazmat.primitives.hashes.SHA384",
    "SHA512": "cryptography.hazmat.primitives.hashes.SHA512",
    "SHA3_256": "cryptography.hazmat.primitives.hashes.SHA3_256",
    "SHA3_512": "cryptography.hazmat.primitives.hashes.SHA3_512",
    "BLAKE2b": "cryptography.hazmat.primitives.hashes.BLAKE2b",
    "BLAKE2s": "cryptography.hazmat.primitives.hashes.BLAKE2s",
    "PBKDF2HMAC": "cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC",
    "HKDF": "cryptography.hazmat.primitives.kdf.hkdf.HKDF",
    "Scrypt": "cryptography.hazmat.primitives.kdf.scrypt.Scrypt",
    "BCrypt": "cryptography.hazmat.primitives.kdf.bcrypt.BCrypt",
    "Argon2id": "cryptography.hazmat.primitives.kdf.argon2.Argon2id",
}


class SourceScanner(Scanner[ScannerFinding]):
    name = "source"
    version = "0.1.0"

    def __init__(self):
        self._file_cache: dict[str, str] = {}

    def is_available(self) -> bool:
        return True

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        findings: list[ScannerFinding] = []

        if target_path.is_file():
            findings.extend(self._scan_file(target_path))
        elif target_path.is_dir():
            for file_path in target_path.rglob("*.py"):
                if self._should_skip(file_path):
                    continue
                findings.extend(self._scan_file(file_path))

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
        ]
        return any(part in skip_patterns for part in path.parts)

    def _scan_file(self, file_path: Path) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8")
            self._file_cache[str(file_path)] = content
        except Exception:
            return findings

        try:
            tree = ast.parse(content, filename=str(file_path))
        except SyntaxError:
            return self._scan_file_fallback(file_path, content)

        visitor = CryptoASTVisitor(file_path, content)
        visitor.visit(tree)
        findings.extend(visitor.findings)

        # Filter out false positives from padding/hash algorithm arguments
        findings = self._filter_false_positives(findings)

        return findings

    def _scan_file_fallback(self, file_path: Path, content: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()

            if line_stripped.startswith("#") or '"""' in line_stripped or "'''" in line_stripped:
                continue

            for pattern, (canonical, op_type) in PYTHON_CRYPTO_PATTERNS.items():
                if pattern in line:
                    canonical_norm, original = normalize_algorithm(canonical)
                    category = get_category(canonical_norm)

                    # Extract key_size and mode from canonical algorithm name
                    key_sizes = get_key_sizes(canonical_norm)
                    key_size = key_sizes[0] if key_sizes else None
                    mode = get_mode(canonical_norm)

                    evidence = create_evidence_signal(
                        tool="source:ast",
                        detail=f"direct source API call: {pattern} at {file_path}:{i}",
                        confidence=0.85,
                        snippet=line.strip()[:200],
                    )

                    finding = ScannerFinding(
                        canonical=canonical_norm,
                        original=original,
                        key_size=key_size,
                        mode=mode,
                        library="cryptography" if "cryptography" in pattern else ("pycryptodome" if "Crypto" in pattern else "stdlib"),
                        usage_state=UsageState.CONFIRMED,
                        confidence=0.85,
                        evidence=[evidence],
                        location=Location(file=str(file_path), line=i, function=self._find_function(lines, i)),
                        operation_type=op_type,
                        function=self._find_function(lines, i),
                        implementation=Implementation(
                            library="cryptography" if "cryptography" in pattern else ("pycryptodome" if "Crypto" in pattern else "stdlib"),
                            api=pattern,
                        ),
                        context=Context(exposure=Exposure.INTERNAL),
                    )
                    findings.append(finding)

        return findings

    def _find_function(self, lines: list[str], line_num: int) -> Optional[str]:
        for i in range(line_num - 1, -1, -1):
            stripped = lines[i].strip()
            if stripped.startswith("def ") or stripped.startswith("async def "):
                return stripped.split("(")[0].replace("def ", "").replace("async ", "").strip()
            if stripped.startswith("class "):
                return None
        return None

    def _filter_false_positives(self, findings: list[ScannerFinding]) -> list[ScannerFinding]:
        """Filter out false positives from padding/hash algorithm arguments."""
        filtered = []
        for f in findings:
            # Skip SHA-256/384/512 detections that come from padding.MGF1 or OAEP hash_algorithm
            if f.canonical in ("SHA-256", "SHA-384", "SHA-512") and f.implementation:
                api = f.implementation.api.lower()
                if ("padding" in api or "mgf1" in api or "oaep" in api or "pss" in api or
                    "hashes.sha256" in api or "hashes.sha384" in api or "hashes.sha512" in api):
                    continue
            filtered.append(f)
        return filtered


class CryptoASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, content: str):
        self.file_path = file_path
        self.content = content
        self.lines = content.splitlines()
        self.findings: list[ScannerFinding] = []
        self.imports: dict[str, str] = {}
        self.current_function: Optional[str] = None
        self._collect_imports()

    def _collect_imports(self):
        try:
            tree = ast.parse(self.content, filename=str(self.file_path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.imports[alias.asname or alias.name] = alias.name
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias in node.names:
                        full_name = f"{module}.{alias.name}"
                        self.imports[alias.asname or alias.name] = full_name
        except Exception:
            pass

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Attribute):
            self._check_attribute_call(node)
        elif isinstance(node.func, ast.Name):
            self._check_name_call(node)
        self.generic_visit(node)

    def _check_attribute_call(self, node: ast.Call):
        if not isinstance(node.func.value, ast.Name):
            return

        obj_name = node.func.value.id
        method_name = node.func.attr
        full_call = f"{obj_name}.{method_name}"

        # First, try exact import alias matching
        for import_alias, full_import in self.imports.items():
            if obj_name == import_alias:
                # Build the expected full pattern prefix
                expected_prefix = full_import + "."
                for pattern, (canonical, op_type) in PYTHON_CRYPTO_PATTERNS.items():
                    # Exact match on the full import path + method
                    if pattern == expected_prefix + method_name or pattern == full_import + "." + method_name:
                        self._create_finding(pattern, canonical, op_type, node.lineno, full_call, node)
                        return
                    # Fallback: pattern ends with method but also starts with the import
                    if pattern.endswith(f".{method_name}") and pattern.startswith(full_import):
                        self._create_finding(pattern, canonical, op_type, node.lineno, full_call, node)
                        return

        # Fallback: Heuristic matching for common EC/RSA method names on variables
        # when relevant crypto modules are imported
        self._check_heuristic_methods(node, obj_name, method_name, full_call)

    def _check_heuristic_methods(self, node: ast.Call, obj_name: str, method_name: str, full_call: str):
        """Heuristic matching for common crypto method names on local variables."""
        # Check if relevant crypto modules are imported
        has_ec = any("ec" in imp or "elliptic" in imp.lower() for imp in self.imports.values())
        has_rsa = any("rsa" in imp.lower() for imp in self.imports.values())
        has_ed25519 = any("ed25519" in imp.lower() for imp in self.imports.values())
        has_x25519 = any("x25519" in imp.lower() for imp in self.imports.values())

        # ECDSA/ECDH methods
        if has_ec:
            if method_name == "sign":
                self._create_finding(
                    "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey",
                    "ECDSA", OperationType.SIGN, node.lineno, full_call, node
                )
                return
            elif method_name == "verify":
                self._create_finding(
                    "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey",
                    "ECDSA", OperationType.VERIFY, node.lineno, full_call, node
                )
                return
            elif method_name == "exchange":
                self._create_finding(
                    "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey",
                    "ECDH", OperationType.KEY_EXCHANGE, node.lineno, full_call, node
                )
                return
            elif method_name == "public_key":
                self._create_finding(
                    "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey",
                    "ECDSA", OperationType.KEY_MANAGEMENT, node.lineno, full_call, node
                )
                return

        # RSA methods
        if has_rsa:
            if method_name == "sign":
                self._create_finding(
                    "cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey",
                    "RSA", OperationType.SIGN, node.lineno, full_call, node
                )
                return
            elif method_name == "verify":
                self._create_finding(
                    "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey",
                    "RSA", OperationType.VERIFY, node.lineno, full_call, node
                )
                return
            elif method_name == "encrypt":
                self._create_finding(
                    "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey",
                    "RSA", OperationType.ENCRYPT, node.lineno, full_call, node
                )
                return
            elif method_name == "decrypt":
                self._create_finding(
                    "cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey",
                    "RSA", OperationType.DECRYPT, node.lineno, full_call, node
                )
                return
            elif method_name == "public_key":
                self._create_finding(
                    "cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey",
                    "RSA", OperationType.KEY_MANAGEMENT, node.lineno, full_call, node
                )
                return

        # Ed25519 methods
        if has_ed25519:
            if method_name in ("sign", "verify"):
                self._create_finding(
                    "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey",
                    "Ed25519", OperationType.SIGN if method_name == "sign" else OperationType.VERIFY,
                    node.lineno, full_call, node
                )
                return

        # X25519 methods
        if has_x25519:
            if method_name == "exchange":
                self._create_finding(
                    "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey",
                    "X25519", OperationType.KEY_EXCHANGE, node.lineno, full_call, node
                )
                return

    def _check_name_call(self, node: ast.Call):
        func_name = node.func.id
        for import_alias, full_import in self.imports.items():
            if func_name == import_alias:
                for pattern, (canonical, op_type) in PYTHON_CRYPTO_PATTERNS.items():
                    if pattern == full_import or pattern.endswith(f".{func_name}"):
                        self._create_finding(pattern, canonical, op_type, node.lineno, func_name, node)
                        return

    def _create_finding(self, pattern: str, canonical: str, op_type: OperationType,
                       line_no: int, call_str: str, node: ast.Call = None):
        canonical_norm, original = normalize_algorithm(canonical)
        category = get_category(canonical_norm)
        
        # Extract key_size and mode from canonical algorithm name
        key_sizes = get_key_sizes(canonical_norm)
        key_size = key_sizes[0] if key_sizes else None
        mode = get_mode(canonical_norm)
        curves = get_curves(canonical_norm)
        curve = curves[0] if curves else None
        
        # Try to extract key_size from call arguments for RSA key generation
        if node is not None and canonical_norm == "RSA":
            for kw in node.keywords:
                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                    key_size = kw.value.value
                    break
        
        # Try to extract curve from call arguments for ECDSA/ECDH
        if node is not None and canonical_norm in ("ECDSA", "ECDH"):
            for kw in node.keywords:
                if kw.arg == "curve" and isinstance(kw.value, ast.Attribute):
                    curve = kw.value.attr
                    break
                elif kw.arg == "curve" and isinstance(kw.value, ast.Call):
                    if isinstance(kw.value.func, ast.Attribute):
                        curve = kw.value.func.attr
                        break
        
        snippet = self.lines[line_no - 1].strip() if line_no <= len(self.lines) else ""
        evidence = create_evidence_signal(
            tool="source:ast",
            detail=f"direct source API call: {call_str} at {self.file_path}:{line_no}",
            confidence=0.92,
            snippet=snippet[:200],
        )
        
        finding = ScannerFinding(
            canonical=canonical_norm,
            original=original,
            key_size=key_size,
            mode=mode,
            curve=curve,
            library="cryptography" if "cryptography" in pattern else ("pycryptodome" if "Crypto" in pattern else "stdlib"),
            usage_state=UsageState.CONFIRMED,
            confidence=0.92,
            evidence=[evidence],
            location=Location(file=str(self.file_path), line=line_no, function=self.current_function),
            operation_type=op_type,
            function=self.current_function,
            implementation=Implementation(
                library="cryptography" if "cryptography" in pattern else ("pycryptodome" if "Crypto" in pattern else "stdlib"),
                api=call_str,
            ),
            context=Context(exposure=Exposure.INTERNAL),
        )
        self.findings.append(finding)


ScannerRegistry.register(SourceScanner())