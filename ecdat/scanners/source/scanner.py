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
from ecdat.scanners.path_policy import iter_project_files_matching
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
    "cryptography.hazmat.primitives.ciphers.aead.AESGCM.encrypt": ("AES-256-GCM", OperationType.ENCRYPT),
    "cryptography.hazmat.primitives.ciphers.aead.AESGCM.decrypt": ("AES-256-GCM", OperationType.DECRYPT),
    "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.encrypt": ("ChaCha20-Poly1305", OperationType.ENCRYPT),
    "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.decrypt": ("ChaCha20-Poly1305", OperationType.DECRYPT),
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
    "hashlib.sha224": ("SHA-256", OperationType.HASH),
    "hashlib.sha256": ("SHA-256", OperationType.HASH),
    "hashlib.sha384": ("SHA-384", OperationType.HASH),
    "hashlib.sha512": ("SHA-512", OperationType.HASH),
    "hashlib.sha3_224": ("SHA-3-256", OperationType.HASH),
    "hashlib.sha3_256": ("SHA-3-256", OperationType.HASH),
    "hashlib.sha3_384": ("SHA-3-512", OperationType.HASH),
    "hashlib.sha3_512": ("SHA-3-512", OperationType.HASH),
    "hashlib.blake2b": ("BLAKE2b", OperationType.HASH),
    "hashlib.blake2s": ("BLAKE2s", OperationType.HASH),
    "hashlib.pbkdf2_hmac": ("PBKDF2", OperationType.KDF),
    "hmac.new": ("HMAC", OperationType.HASH),
    "hmac.HMAC": ("HMAC", OperationType.HASH),
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
    "X25519PrivateKey.generate": "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate",
    "X448": "cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey",
    "Ed25519": "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey",
    "Ed25519PrivateKey.generate": "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate",
    "Ed448": "cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey",
    "Hash": "cryptography.hazmat.primitives.hashes.Hash",
    "MD5": "hashlib.md5",
    "SHA1": "hashlib.sha1",
    "SHA224": "hashlib.sha224",
    "SHA256": "hashlib.sha256",
    "SHA384": "hashlib.sha384",
    "SHA512": "hashlib.sha512",
    "SHA3_224": "hashlib.sha3_224",
    "SHA3_256": "hashlib.sha3_256",
    "SHA3_384": "hashlib.sha3_384",
    "SHA3_512": "hashlib.sha3_512",
    "BLAKE2b": "hashlib.blake2b",
    "BLAKE2s": "hashlib.blake2s",
    "PBKDF2_HMAC": "hashlib.pbkdf2_hmac",
    "HMAC": "hmac.HMAC",
    "new": "hmac.new",
    "HKDF": "cryptography.hazmat.primitives.kdf.hkdf.HKDF",
    "Scrypt": "cryptography.hazmat.primitives.kdf.scrypt.Scrypt",
    "BCrypt": "cryptography.hazmat.primitives.kdf.bcrypt.BCrypt",
    "Argon2id": "cryptography.hazmat.primitives.kdf.argon2.Argon2id",
}


#: Suffix -> language code for the Phase 4 semantic routers.
#: Python keeps its dedicated AST path; every other entry routes to the
#: fast-syntax engine (c_parser) with registry-driven API knowledge.
SOURCE_LANGUAGE_SUFFIXES = {
    ".py": "py",
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hxx": "cpp",
    ".java": "java",
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "js", ".tsx": "js",
    ".go": "go",
    ".cs": "csharp",
    ".rs": "rust",
}


class SourceScanner(Scanner[ScannerFinding]):
    name = "source"
    version = "0.2.0"

    def __init__(self):
        self._file_cache: dict[str, str] = {}
        self._last_stats: dict[str, Any] = {}

    def is_available(self) -> bool:
        return True

    def last_stats(self) -> dict[str, Any]:
        """Per-run routing stats (traceability, Phase 4)."""
        return dict(self._last_stats)

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        target_path = Path(target)
        findings: list[ScannerFinding] = []
        self._last_stats = {"by_language": {}, "suppressed_noise": 0,
                            "semgrep": "not-run", "test_files": 0,
                            "impl_files": 0, "files": 0}

        # Phase 2/4 inventory routing: when the orchestrator passes
        # ``artifacts`` (ArtifactRecord dicts), only inventory-confirmed
        # source files are opened. Otherwise fall back to own traversal.
        allowed: set[str] | None = None
        artifacts = kwargs.get("artifacts")
        if artifacts:
            allowed = set()
            for item in artifacts:
                if isinstance(item, dict):
                    if item.get("category") == "source":
                        allowed.add(str(item.get("abs_path", "")))
                else:
                    if getattr(item, "category", "") == "source":
                        allowed.add(str(getattr(item, "abs_path", "")))

        if target_path.is_file():
            if allowed is None or str(target_path) in allowed:
                findings.extend(self._scan_file(target_path))
        elif target_path.is_dir():
            for file_path in iter_project_files_matching(
                    target_path, set(SOURCE_LANGUAGE_SUFFIXES)):
                if self._should_skip(file_path):
                    continue
                if allowed is not None and str(file_path) not in allowed:
                    continue
                findings.extend(self._scan_file(file_path))

        findings = self._merge_semgrep(target_path, findings)
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
        lang = SOURCE_LANGUAGE_SUFFIXES.get(file_path.suffix.lower(), "")
        if lang and lang != "py":
            return self._scan_brace_file(file_path, lang)
        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8")
            self._file_cache[str(file_path)] = content
        except Exception:
            return findings
        self._last_stats["files"] = self._last_stats.get("files", 0) + 1
        self._last_stats["by_language"]["py"] = \
            self._last_stats.get("by_language", {}).get("py", 0) + 1

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

        # Build regex patterns for fallback: short_name followed by optional (...) then .method
        import re
        alias_patterns = []
        for short_name, full_import in IMPORT_ALIASES.items():
            for pattern, (canonical, op_type) in PYTHON_CRYPTO_PATTERNS.items():
                if pattern.startswith(full_import + "."):
                    method = pattern[len(full_import) + 1:]
                    # Create regex: short_name followed by optional parentheses content then .method
                    regex = rf"{re.escape(short_name)}\s*\([^)]*\)\s*\.\s*{re.escape(method)}"
                    alias_patterns.append((regex, pattern, canonical, op_type))

        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()

            if line_stripped.startswith("#") or '"""' in line_stripped or "'''" in line_stripped:
                continue

            # First try exact pattern matching
            matched = False
            for pattern, (canonical, op_type) in PYTHON_CRYPTO_PATTERNS.items():
                if pattern in line:
                    self._add_fallback_finding(findings, file_path, i, line, pattern, canonical, op_type, lines)
                    matched = True
                    break  # Only first match per line

            # Also check alias patterns with regex
            if not matched:
                for regex, pattern, canonical, op_type in alias_patterns:
                    if re.search(regex, line):
                        self._add_fallback_finding(findings, file_path, i, line, pattern, canonical, op_type, lines)
                        matched = True
                        break  # Only first match per line

        return findings

    def _add_fallback_finding(self, findings: list, file_path: Path, line_num: int, line: str, 
                              pattern: str, canonical: str, op_type, lines: list):
        """Add a finding from fallback regex matching."""
        canonical_norm, original = normalize_algorithm(canonical)
        category = get_category(canonical_norm)

        key_sizes = get_key_sizes(canonical_norm)
        key_size = key_sizes[0] if key_sizes else None
        mode = get_mode(canonical_norm)

        evidence = create_evidence_signal(
            tool="source:ast",
            detail=f"direct source API call (fallback): {pattern} at {file_path}:{line_num}",
            confidence=0.8,
            snippet=line.strip()[:200],
        )

        # Determine library from pattern
        if "cryptography" in pattern:
            lib = "cryptography"
        elif "Crypto" in pattern:
            lib = "pycryptodome"
        elif pattern.startswith("hashlib."):
            lib = "hashlib"
        elif pattern.startswith("hmac."):
            lib = "hmac"
        else:
            lib = "stdlib"
            
        finding = ScannerFinding(
            canonical=canonical_norm,
            original=original,
            key_size=key_size,
            mode=mode,
            library=lib,
            usage_state=UsageState.CONFIRMED,
            confidence=0.8,
            evidence=[evidence],
            location=Location(file=str(file_path), line=line_num, function=self._find_function(lines, line_num)),
            operation_type=op_type,
            function=self._find_function(lines, line_num),
            implementation=Implementation(
                library=lib,
                api=pattern,
            ),
            context=Context(exposure=Exposure.INTERNAL),
        )
        findings.append(finding)

    def _find_function(self, lines: list[str], line_num: int) -> Optional[str]:
        for i in range(line_num - 1, -1, -1):
            stripped = lines[i].strip()
            if stripped.startswith("def ") or stripped.startswith("async def "):
                return stripped.split("(")[0].replace("def ", "").replace("async ", "").strip()
            if stripped.startswith("class "):
                return None
        return None

    def _scan_brace_file(self, file_path: Path, lang: str) -> list[ScannerFinding]:
        """Phase 4 semantic pass for C/C++/Java/JS/Go/C#/Rust.

        Masked fast-syntax analysis (comments/strings never match) over
        registry-driven API knowledge, with candidate-only constant
        propagation, one-hop wrapper resolution, and
        implementation/test-vector/use separation.
        """
        from ecdat.scanners.source import c_parser as _cp
        from ecdat.scanners.source.api_knowledge import patterns_for

        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings
        if len(content) > 2 * 1024 * 1024:
            return findings
        self._file_cache[str(file_path)] = content
        self._last_stats["files"] = self._last_stats.get("files", 0) + 1
        langs = self._last_stats.setdefault("by_language", {})
        langs[lang] = langs.get(lang, 0) + 1

        classification = _cp.classify_source_file(file_path)
        if classification == "test-vector":
            self._last_stats["test_files"] = self._last_stats.get("test_files", 0) + 1
        elif classification == "implementation":
            self._last_stats["impl_files"] = self._last_stats.get("impl_files", 0) + 1

        masked, suppressed = _cp.mask_source(content)
        self._last_stats["suppressed_noise"] = \
            self._last_stats.get("suppressed_noise", 0) + suppressed
        lines = content.splitlines()
        rows = patterns_for(lang)
        if not rows:
            return findings
        compiled = [(row, re.compile(row["re"])) for row in rows]
        api_names = {row["call"] for row in rows}

        sites = _cp.extract_calls(masked)
        consts = _cp.collect_constants(masked)
        matched_sites: set[int] = set()
        # (finding, site, row_id) for the subsumption post-pass.
        produced: list[tuple[Any, Any, str]] = []

        for index, site in enumerate(sites):
            raw_line = lines[site.line - 1] if 0 < site.line <= len(lines) else ""
            if raw_line.strip().startswith("#"):
                continue
            statement = _cp.statement_text(lines, site.line)
            if self._looks_like_declaration(statement, site.name):
                continue
            literals = _cp.string_literals_of_line(raw_line)
            for row, rx in compiled:
                # Rows are written as call patterns (name + opening
                # paren); match against the site name with a synthetic
                # paren so both ``\bName\b`` and ``Name\s*\(`` rows work.
                if not rx.search(site.name + "("):
                    continue
                resolved = _cp.resolve_entry(row, site.args, consts,
                                             site.name, literals)
                args = _cp.split_args(site.args)
                finding = self._build_finding(
                    file_path=file_path, line=site.line,
                    function=site.function, lang=lang,
                    classification=classification,
                    call_text=site.call_text, api_name=site.name,
                    resolved=resolved, row=row, args=args,
                    tool="source:api-call",
                    detail_prefix="direct source API call",
                    wrapper_from=None,
                )
                if finding is not None:
                    findings.append(finding)
                    produced.append((finding, site, str(row.get("id", ""))))
                    matched_sites.add(index)
                break

        # Subsumption: a cipher/digest constructor passed as an argument
        # to a resolved Init call on the same line is evidence for the
        # Init finding, not an independent second finding.
        if produced:
            subsumed: set[int] = set()
            for idx, (finding, site, row_id) in enumerate(produced):
                if not row_id.startswith("ossl-evp-ctor-"):
                    continue
                ctor_name = site.name
                for other, other_site, other_row in produced:
                    if other is finding or other_site.line != site.line:
                        continue
                    if other_row.startswith("ossl-evp-ctor-"):
                        continue
                    if ctor_name in other_site.args:
                        subsumed.add(idx)
                        break
            if subsumed:
                produced = [p for i, p in enumerate(produced)
                            if i not in subsumed]
                findings = [p[0] for p in produced]

        # One-hop wrapper resolution: local functions wrapping a crypto
        # API inherit the wrapped call's resolved semantics at reduced
        # confidence (Probable); chains are not followed.
        wrappers = _cp.find_wrappers(
            [s for i, s in enumerate(sites) if i in matched_sites], api_names)
        if wrappers:
            func_semantics: dict[str, dict] = {}
            for finding, site, row_id in produced:
                if row_id.startswith("ossl-evp-ctor-"):
                    continue
                if site.function and site.function not in func_semantics:
                    func_semantics[site.function] = {
                        "canonical": finding.canonical,
                        "key_size": finding.key_size,
                        "mode": finding.mode,
                        "curve": finding.curve,
                        "protocol": finding.protocol,
                        "op": finding.operation_type.name
                        if finding.operation_type else "ENCRYPT",
                        "confidence": 0.70,
                    }
            by_name: dict[str, list] = {}
            for row, rx in compiled:
                by_name.setdefault(row["call"], []).append((row, rx))
            for site in sites:
                base = site.name.split(".")[-1].split(":")[-1]
                if base not in wrappers or site.function in wrappers:
                    continue
                target_api = wrappers[base]
                for row, rx in by_name.get(target_api, []):
                    inherited = dict(func_semantics.get(base, {}))
                    resolved = _cp.resolve_entry(row, "", consts, target_api)
                    resolved.update({k: v for k, v in inherited.items() if v})
                    resolved["confidence"] = 0.70
                    finding = self._build_finding(
                        file_path=file_path, line=site.line,
                        function=site.function, lang=lang,
                        classification=classification,
                        call_text=site.call_text, api_name=site.name,
                        resolved=resolved,
                        row=row, args=[],
                        tool="source:wrapper-call",
                        detail_prefix=f"wrapper call resolving to {target_api}",
                        wrapper_from=base,
                    )
                    if finding is not None:
                        # Wrappers are never stronger than Probable: they
                        # prove reachability, not direct parameter use.
                        if finding.usage_state == UsageState.CONFIRMED:
                            finding.usage_state = UsageState.PROBABLE
                        findings.append(finding)
                    break
        return findings

    @staticmethod
    def _looks_like_declaration(line: str, name: str) -> bool:
        """Filter C-style prototypes (``int EVP_x(...);``), not calls.

        Multi-line prototypes are handled by the caller, which passes
        the full statement text (see c_parser.statement_text).
        """
        stripped = line.strip()
        if "(" not in stripped or name not in stripped:
            return False
        tail = stripped.split(name, 1)[1]
        if not tail.startswith("("):
            return False
        if stripped.endswith(";") and "{" not in stripped and "=" not in stripped.split("(", 1)[0]:
            # Only the return-type prefix (before the name itself) may
            # carry a type keyword: the name may legitimately contain
            # substrings like "int" (EVP_EncryptInit_ex) or "char".
            prefix = stripped.split(name, 1)[0]
            if re.search(r"\b(?:int|void|char|const|unsigned|long|short|size_t|"
                         r"struct|enum|static|extern|BOOL|HRESULT)\b", prefix):
                return True
        return False

    def _build_finding(self, *, file_path: Path, line: int,
                       function: Optional[str], lang: str,
                       classification: str, call_text: str, api_name: str,
                       resolved: dict, row: dict, args: list,
                       tool: str, detail_prefix: str,
                       wrapper_from: Optional[str]) -> Optional[ScannerFinding]:
        canonical_raw = resolved.get("canonical") or "OpenSSL"
        canonical_norm, original = normalize_algorithm(canonical_raw)
        op_type = self._op_type(resolved.get("op") or "ENCRYPT")
        confidence = float(resolved.get("confidence", 0.85))
        usage_state = UsageState.CONFIRMED
        dependency_only = False
        if classification == "implementation":
            # Code that IMPLEMENTS algorithms (OpenSSL crypto/ tree):
            # capability/provision evidence, never application use. The
            # dependency_only marker is this codebase's provides-vs-uses
            # flag: normalize_finding preserves ProvidedOnly for it.
            usage_state = UsageState.PROVIDED_ONLY
            confidence = min(confidence, 0.55)
            dependency_only = True
        elif classification == "test-vector":
            # Test vectors prove test usage, not application use. Capped
            # below normalize_finding's 0.4 indirect-evidence band so the
            # terminal state stays Possible instead of Probable.
            usage_state = UsageState.POSSIBLE
            confidence = min(confidence, 0.39)
        elif classification == "header-capability":
            usage_state = UsageState.PROBABLE
            confidence = min(confidence, 0.80)

        extra = resolved.get("detail") or ""
        detail = (f"{detail_prefix}: {api_name} at {file_path}:{line}"
                  + (f" [{extra}]" if extra else ""))
        snippet_bits = [call_text.strip()[:160]]
        if args:
            snippet_bits.append("args: " + ", ".join(a[:60] for a in args[:4]))
        evidence = create_evidence_signal(
            tool=tool, detail=detail, confidence=round(confidence, 3),
            snippet=" | ".join(snippet_bits)[:500],
        )
        return ScannerFinding(
            canonical=canonical_norm,
            original=original,
            key_size=resolved.get("key_size"),
            mode=resolved.get("mode"),
            curve=resolved.get("curve"),
            protocol=resolved.get("protocol"),
            library=row.get("library") or lang,
            usage_state=usage_state,
            confidence=round(confidence, 3),
            evidence=[evidence],
            location=Location(file=str(file_path), line=line, function=function),
            operation_type=op_type,
            function=function,
            dependency_only=dependency_only,
            implementation=Implementation(
                library=row.get("library") or lang, api=api_name),
            context=Context(exposure=Exposure.INTERNAL),
        )

    @staticmethod
    def _op_type(name: str):
        try:
            return OperationType[str(name).strip().upper()]
        except Exception:
            return OperationType.ENCRYPT

    def _merge_semgrep(self, target_path: Path,
                       findings: list[ScannerFinding]) -> list[ScannerFinding]:
        """Phase 4: run the existing Semgrep integration when available.

        Opportunistic merge with (file, line, canonical) dedupe against
        native findings; unavailable Semgrep only records status (graceful
        degradation, never a failure).
        """
        try:
            from ecdat.scanners.source.semgrep_scanner import SemgrepScanner
            engine = SemgrepScanner()
            if not engine.is_available():
                self._last_stats["semgrep"] = "unavailable"
                return findings
            extra = engine.scan(target_path)
            self._last_stats["semgrep"] = f"available:{len(extra)}"
        except Exception as exc:
            self._last_stats["semgrep"] = f"error: {exc}"
            return findings
        seen = set()
        for item in findings:
            loc = item.location
            seen.add((loc.file if loc else "", loc.line if loc else 0,
                      item.canonical))
        merged = list(findings)
        for item in extra:
            loc = item.location
            key = (loc.file if loc else "", loc.line if loc else 0,
                   item.canonical)
            if key in seen:
                continue
            seen.add(key)
            merged.append(self._retag_semgrep(item))
        return merged

    @staticmethod
    def _retag_semgrep(item: ScannerFinding) -> ScannerFinding:
        """Normalise Semgrep evidence into the source signal taxonomy."""
        try:
            import dataclasses as _dc
            item.evidence = [
                _dc.replace(ev, tool="source:semgrep") for ev in item.evidence]
        except Exception:
            try:
                for ev in item.evidence:
                    ev.tool = "source:semgrep"
            except Exception:
                pass
        return item

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
        if not isinstance(node.func.value, ast.Attribute):
            # Simple obj.method() call
            if isinstance(node.func.value, ast.Name):
                obj_name = node.func.value.id
                method_name = node.func.attr
                full_call = f"{obj_name}.{method_name}"

                # First, try exact import alias matching (case-insensitive)
                obj_name_lower = obj_name.lower()
                for import_alias, full_import in self.imports.items():
                    if obj_name_lower == import_alias.lower():
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
            elif isinstance(node.func.value, ast.Call):
                # Constructor call: ClassName(...).method()
                # e.g., AESGCM(key).encrypt(...) or AESGCM(key).decrypt(...)
                constructor_call = node.func.value
                if isinstance(constructor_call.func, ast.Name):
                    class_name = constructor_call.func.id
                    method_name = node.func.attr
                    full_call = f"{class_name}(...).{method_name}"

                    # Check if the class name matches an imported crypto class
                    class_name_lower = class_name.lower()
                    for import_alias, full_import in self.imports.items():
                        if class_name_lower == import_alias.lower():
                            expected_prefix = full_import + "."
                            for pattern, (canonical, op_type) in PYTHON_CRYPTO_PATTERNS.items():
                                if pattern == expected_prefix + method_name or pattern == full_import + "." + method_name:
                                    self._create_finding(pattern, canonical, op_type, node.lineno, full_call, node)
                                    return
                                if pattern.endswith(f".{method_name}") and pattern.startswith(full_import):
                                    self._create_finding(pattern, canonical, op_type, node.lineno, full_call, node)
                                    return

                    # Fallback: Heuristic matching
                    self._check_heuristic_methods(node, class_name, method_name, full_call)
            return
        
        # Double attribute access: obj.attr.method() (e.g., self._cipher.encrypt)
        # Traverse the attribute chain
        attr_chain = []
        current = node.func
        while isinstance(current, ast.Attribute):
            attr_chain.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            attr_chain.append(current.id)
        
        if len(attr_chain) >= 2:
            # attr_chain is [method, attr, ..., obj] in reverse
            method_name = attr_chain[0]
            obj_name = attr_chain[-1]
            full_call = ".".join(reversed(attr_chain))
            
            # Check if this is a known crypto method on a wrapper/instance
            self._check_wrapper_methods(node, obj_name, method_name, full_call)
            return

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

    def _check_wrapper_methods(self, node: ast.Call, obj_name: str, method_name: str, full_call: str):
        """Heuristic matching for common crypto method names on wrapper/instance variables
        (e.g., self._cipher.encrypt, cipher.decrypt, self._hash.update)."""
        # Check if relevant crypto modules are imported
        has_cryptography = any("cryptography" in imp for imp in self.imports.values())
        has_pycryptodome = any("Crypto" in imp for imp in self.imports.values())
        has_hashlib = any("hashlib" in imp for imp in self.imports.values())
        
        # Determine operation type from method name
        op_type = None
        if method_name in ("encrypt", "decrypt"):
            op_type = OperationType.ENCRYPT if method_name == "encrypt" else OperationType.DECRYPT
        elif method_name in ("sign", "verify"):
            op_type = OperationType.SIGN if method_name == "sign" else OperationType.VERIFY
        elif method_name in ("digest", "hexdigest", "update", "finalize"):
            op_type = OperationType.HASH
        elif method_name in ("derive", "derive_key"):
            op_type = OperationType.KDF
        elif method_name in ("exchange",):
            op_type = OperationType.KEY_EXCHANGE
        
        if not op_type:
            return
        
        # Map method to likely algorithm based on imported modules
        if has_cryptography:
            # Common symmetric cipher methods
            if method_name in ("encrypt", "decrypt"):
                # Could be AES-GCM, ChaCha20-Poly1305, etc.
                # Default to AES-256-GCM as most common
                self._create_finding(
                    "cryptography.hazmat.primitives.ciphers.aead.AESGCM",
                    "AES-256-GCM", op_type, node.lineno, full_call, node
                )
                return
            elif method_name in ("sign", "verify"):
                # Could be RSA, ECDSA, Ed25519
                if has_pycryptodome or "rsa" in str(self.imports).lower():
                    self._create_finding(
                        "cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey",
                        "RSA", op_type, node.lineno, full_call, node
                    )
                    return
            elif method_name in ("digest", "hexdigest", "update", "finalize"):
                # Hash context
                self._create_finding(
                    "cryptography.hazmat.primitives.hashes.Hash",
                    "SHA-256", OperationType.HASH, node.lineno, full_call, node
                )
                return
        
        if has_pycryptodome:
            if method_name in ("encrypt", "decrypt"):
                self._create_finding(
                    "Crypto.Cipher.AES",
                    "AES", op_type, node.lineno, full_call, node
                )
                return
            elif method_name in ("sign", "verify"):
                self._create_finding(
                    "Crypto.Signature.pkcs1_15",
                    "RSA", op_type, node.lineno, full_call, node
                )
                return
        
        if has_hashlib:
            if method_name in ("digest", "hexdigest", "update", "finalize"):
                self._create_finding(
                    "hashlib.sha256",
                    "SHA-256", OperationType.HASH, node.lineno, full_call, node
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
        
        # Determine library from pattern
        if "cryptography" in pattern:
            lib = "cryptography"
        elif "Crypto" in pattern:
            lib = "pycryptodome"
        elif pattern.startswith("hashlib."):
            lib = "hashlib"
        elif pattern.startswith("hmac."):
            lib = "hmac"
        else:
            lib = "stdlib"
        
        finding = ScannerFinding(
            canonical=canonical_norm,
            original=original,
            key_size=key_size,
            mode=mode,
            curve=curve,
            library=lib,
            usage_state=UsageState.CONFIRMED,
            confidence=0.92,
            evidence=[evidence],
            location=Location(file=str(self.file_path), line=line_no, function=self.current_function),
            operation_type=op_type,
            function=self.current_function,
            implementation=Implementation(
                library=lib,
                api=call_str,
            ),
            context=Context(exposure=Exposure.INTERNAL),
        )
        self.findings.append(finding)


ScannerRegistry.register(SourceScanner())
