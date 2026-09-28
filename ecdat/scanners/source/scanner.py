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
    "argon2.PasswordHasher": ("Argon2", OperationType.KDF),
    "argon2.low_level.hash_secret": ("Argon2", OperationType.KDF),
    "argon2.low_level.verify_secret": ("Argon2", OperationType.KDF),
    "passlib.hash.argon2": ("Argon2", OperationType.KDF),
    "passlib.hash.bcrypt": ("bcrypt", OperationType.KDF),
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
        # Phase 5 cross-file context: path -> {sites, defs, impl, classification}
        self._brace_ctx: dict[str, dict[str, Any]] = {}
        # Same-directory Java texts for enum resolution (dir -> siblings,
        # current file prepended per call; capped; reset per scan).
        self._java_enum_texts: dict[str, list[str]] = {}
        # Cross-file crypto delegates: file -> {func: spec} for factory
        # wrappers (CipherUtils.newCipher -> Cipher.getInstance). Filled
        # during the brace scan, consumed by the post-pass. Reset per scan.
        self._crypto_delegates: dict[str, dict[str, dict]] = {}
        # Phase 13: bounded content-hash result cache for brace-language
        # files. Keyed by (path, content sha256, lang, registry version,
        # scanner version); stores (findings, suppressed, classification)
        # so repeated scans skip re-parse while stats stay honest.
        self._brace_cache: dict[tuple, tuple[list, int, str]] = {}
        self._brace_cache_max = 512

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
        self._brace_ctx = {}
        self._java_enum_texts = {}
        self._crypto_delegates = {}

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
        findings.extend(self._resolve_custom_invocations())
        findings.extend(self._resolve_cross_file_wrappers(findings))
        return [normalize_finding(f) for f in findings]

    def _java_enum_texts_for(self, file_path: Path,
                               content: str) -> list[str]:
        """Original texts for enum resolution: file + same-dir siblings.

        Cached per directory per scan; capped at 50 siblings / ~2 MB so a
        pathological directory cannot blow up a scan. Pure file reads;
        never raises.
        """
        try:
            key = str(file_path.parent)
            siblings = self._java_enum_texts.get(key)
            if siblings is None:
                siblings = []
                budget = 2 * 1024 * 1024
                try:
                    candidates = sorted(file_path.parent.glob("*.java"))[:50]
                except Exception:
                    candidates = []
                for sib in candidates:
                    if sib.name == file_path.name:
                        continue
                    try:
                        text = sib.read_text(encoding="utf-8",
                                             errors="ignore")
                    except Exception:
                        continue
                    if len(text) > budget:
                        break
                    budget -= len(text)
                    siblings.append(text)
                self._java_enum_texts[key] = siblings
            return [content, *siblings]
        except Exception:
            return [content]

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
        elif pattern.startswith("argon2."):
            lib = "argon2-cffi"
        elif pattern.startswith("passlib."):
            lib = "passlib"
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
        from ecdat.scanners.source.api_knowledge import (
            compile_matchers,
            lex_prefilter,
            lookup_exact,
        )
        from ecdat.scanners.source.api_knowledge import (
            REGISTRY_VERSION as _AK_REGISTRY,
        )

        findings: list[ScannerFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings
        if len(content) > 2 * 1024 * 1024:
            return findings
        self._file_cache[str(file_path)] = content
        # Phase 13: content-hash result cache (hits still update stats).
        content_hash = hashlib.sha256(content.encode("utf-8",
                                                     errors="ignore")).hexdigest()
        cache_key = (str(file_path), content_hash, lang,
                     str(_AK_REGISTRY), str(self.version))
        cached = self._brace_cache.get(cache_key)
        classification = _cp.classify_source_file(file_path)
        if cached is not None:
            cached_findings, cached_suppressed, cached_class = cached[:3]
            cached_ctx = cached[3] if len(cached) > 3 else None
            if cached_ctx is not None:
                self._brace_ctx[str(file_path)] = cached_ctx
            self._last_stats["files"] = self._last_stats.get("files", 0) + 1
            langs = self._last_stats.setdefault("by_language", {})
            langs[lang] = langs.get(lang, 0) + 1
            if cached_class == "test-vector":
                self._last_stats["test_files"] = \
                    self._last_stats.get("test_files", 0) + 1
            elif cached_class == "implementation":
                self._last_stats["impl_files"] = \
                    self._last_stats.get("impl_files", 0) + 1
            self._last_stats["suppressed_noise"] = \
                self._last_stats.get("suppressed_noise", 0) + cached_suppressed
            self._last_stats["brace_cache_hits"] = \
                self._last_stats.get("brace_cache_hits", 0) + 1
            return list(cached_findings)
        self._last_stats["files"] = self._last_stats.get("files", 0) + 1
        langs = self._last_stats.setdefault("by_language", {})
        langs[lang] = langs.get(lang, 0) + 1

        if classification == "test-vector":
            self._last_stats["test_files"] = self._last_stats.get("test_files", 0) + 1
        elif classification == "implementation":
            self._last_stats["impl_files"] = self._last_stats.get("impl_files", 0) + 1

        masked, suppressed = _cp.mask_source(content)
        self._last_stats["suppressed_noise"] = \
            self._last_stats.get("suppressed_noise", 0) + suppressed
        # Phase 1 prefilter is advisory only: a negative result skips the
        # API row loop, but call extraction + the Phase 5 fingerprint pass
        # still run — custom implementations contain no known API tokens
        # by definition, and caller files need their sites recorded for
        # the cross-file invocation pass.
        prefilter_hit = lex_prefilter(masked, lang)
        if not prefilter_hit:
            self._last_stats["prefilter_skip"] = \
                self._last_stats.get("prefilter_skip", 0) + 1
        lines = content.splitlines()
        # Phase 1: matchers compiled once per (lang, registry version).
        compiled = compile_matchers(lang)
        if not compiled:
            self._remember_brace(cache_key, [], suppressed, classification)
            return findings
        rows = [row for row, _ in compiled]
        api_names = {row["call"] for row in rows}

        sites = _cp.extract_calls(masked)
        consts = _cp.collect_constants(masked)
        if lang == "java":
            # Masking blanks string contents, so Java string constants
            # need the original text (same one-hop contract as above).
            for key, value in _cp.collect_java_string_consts(
                    content).items():
                consts.setdefault(key, value)
        matched_sites: set[int] = set()
        # (finding, site, row_id) for the subsumption post-pass.
        produced: list[tuple[Any, Any, str]] = []

        # Phase 1: exact-first matching with ordered regex fallback.
        # Exact-type rows absent from the candidate set cannot match
        # (their tokens enumerate the regex); regex-type rows are
        # always checked. This preserves first-row-wins semantics.
        compiled_by_id: dict[str, tuple[dict, Any]] = {}
        for row, rx in compiled:
            compiled_by_id.setdefault(str(row.get("id", "")), (row, rx))
        for index, site in enumerate(sites):
            raw_line = lines[site.line - 1] if 0 < site.line <= len(lines) else ""
            if raw_line.strip().startswith("#"):
                continue
            statement = _cp.statement_text(lines, site.line)
            if self._looks_like_declaration(statement, site.name):
                continue
            literals = _cp.string_literals_of_line(raw_line)
            exact_rows = lookup_exact(site.name, lang)
            exact_ids = {str(r.get("id", "")) for r in exact_rows}
            probe = site.name + "("
            # Prefilter-negative files cannot match any API row; iterate
            # zero rows so sites/consts stay available for fingerprints
            # and invocation resolution.
            for row, rx in (compiled if prefilter_hit else ()):
                row_id = str(row.get("id", ""))
                match_type = str(row.get("match_type", "") or "")
                if match_type in ("exact", "prefix", "constructor",
                                  "string-parameter") and row_id not in exact_ids:
                    continue
                # Rows are written as call patterns (name + opening
                # paren); match against the site name with a synthetic
                # paren so both ``\bName\b`` and ``Name\s*\(`` rows work.
                try:
                    if not rx.search(probe):
                        continue
                except re.error:
                    continue
                resolved = _cp.resolve_entry(row, site.args, consts,
                                             site.name, literals)
                if lang == "java" and row.get("id") == "jca-cipher" \
                        and "getJceName" in site.args \
                        and "transformation" not in str(
                            resolved.get("detail", "")):
                    # Enum-dispatched transformation (RsaAlgorithm.DEFAULT
                    # -> "RSA"): resolve through same-directory enums before
                    # accepting the row default. Never guesses: unresolved
                    # receivers keep the default canonical. Original text
                    # (not masked: string contents are blanked there).
                    enum_hit = _cp.resolve_java_enum_string(
                        self._java_enum_texts_for(file_path, content),
                        site.args)
                    if enum_hit:
                        resolved = _cp.resolve_entry(
                            row, f'"{enum_hit}"', consts, site.name,
                            [enum_hit])
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

        # Phase 3 demand-driven parameter completion (same-file, bounded):
        # JCA `KeyPairGenerator.initialize(<bits>)` carries the key size
        # for a `getInstance("RSA")` call in the same file. Attach it to
        # RSA findings lacking a key size instead of guessing.
        if lang == "java" and findings:
            init_m = re.search(
                r"\.initialize\s*\(\s*(1024|2048|3072|4096)\b", masked)
            if init_m:
                bits = int(init_m.group(1))
                for finding in findings:
                    if finding.canonical == "RSA" and finding.key_size is None:
                        finding.key_size = bits

        # One-hop wrapper resolution: local functions wrapping a crypto
        # API inherit the wrapped call's resolved semantics at reduced
        # confidence (Probable); chains are not followed. Definition and
        # prototype lines never fire (they are not calls), and call arity
        # must match a crypto overload's arity (overload-safe: a 1-arg
        # call to a 2-arg crypto overload is a different function).
        wrappers = _cp.find_wrappers(
            [s for i, s in enumerate(sites) if i in matched_sites], api_names)
        if wrappers:
            try:
                deflines_all = _cp._def_lines_all(masked)
            except Exception:
                deflines_all = {}
            crypto_arities: dict[str, set[int]] = {}
            for _finding, wsite, _row_id in produced:
                wfunc = getattr(wsite, "function", None)
                if not wfunc or wfunc not in wrappers:
                    continue
                try:
                    wline = int(getattr(wsite, "line", 0) or 0)
                except Exception:
                    continue
                overloads = [ln for ln in deflines_all.get(wfunc, [])
                             if ln <= wline]
                if not overloads:
                    continue
                try:
                    params = self._def_params(masked, lines, wfunc,
                                              at_line=max(overloads))
                    crypto_arities.setdefault(wfunc, set()).add(len(params))
                except Exception:
                    continue
            func_semantics: dict[str, dict] = {}
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
                try:
                    if int(site.line) in deflines_all.get(base, []):
                        continue  # the definition itself is not a call
                    statement = _cp.statement_text(
                        list(lines or []), int(site.line))
                    if self._looks_like_declaration(statement, base):
                        continue  # prototypes are not calls
                    arities = crypto_arities.get(base)
                    if arities:
                        call_arity = len(_cp.split_args(
                            str(getattr(site, "args", "") or "")))
                        if call_arity not in arities:
                            continue
                except Exception:
                    pass
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
        # Phase 5: structural fingerprint pass for custom implementations
        # (files that implement crypto without calling a known API).
        # Families already covered by API findings are skipped.
        findings.extend(self._fingerprint_findings(
            file_path, lang, masked, classification, findings))
        # Cross-file crypto delegates (Java JCA factories): record local
        # factory wrappers for the post-pass (call sites in other files).
        if lang == "java" and produced:
            self._stash_delegates(file_path, masked, lines, consts,
                                  produced)
        self._remember_brace(cache_key, findings, suppressed, classification)
        self._stash_brace_ctx(file_path, sites, masked, classification,
                              findings)
        return findings

    def _stash_delegates(self, file_path: Path, masked: str,
                           lines: list, consts: dict,
                           produced: list) -> None:
        """Record local factory wrappers for cross-file attribution.

        A produced direct finding (``source:api-call``) inside a locally
        defined function makes that function a delegate: other files'
        calls to it (exact base-name match) resolve through the wrapped
        API. Forwarded wrapper-parameter indexes are recorded so
        call-site literals resolve precisely; unresolvable arguments
        fall back to the delegate default (never guessed).
        """
        from ecdat.scanners.source import c_parser as _cp
        try:
            defs = set(_cp._def_lines(masked))
        except Exception:
            defs = set()
        except Exception:
            defs = set()
        if not defs:
            return
        table: dict[str, dict] = {}
        for finding, site, row_id in produced:
            func = getattr(site, "function", None)
            if not func or func not in defs or func in table:
                continue
            try:
                tool = str((finding.evidence or [None])[0].tool or "")
            except Exception:
                tool = ""
            if tool != "source:api-call":
                continue
            params = self._def_params(masked, lines, func)
            fwd: list[int] = []
            try:
                for i, part in enumerate(_cp.split_args(
                        str(getattr(site, "args", "") or ""))):
                    if _cp.resolve_arg(part, consts) in params:
                        fwd.append(i)
            except Exception:
                pass
            table[func] = {
                "canonical": finding.canonical,
                "mode": finding.mode,
                "key_size": finding.key_size,
                "op": finding.operation_type.name
                if finding.operation_type else "ENCRYPT",
                "row_id": row_id,
                "call": getattr(site, "name", ""),
                "params": params,
                "fwd": fwd,
                "file": str(file_path),
            }
        if table:
            self._crypto_delegates[str(file_path)] = table

    @staticmethod
    def _def_params(masked: str, lines: list, func: str,
                    at_line: int | None = None) -> list[str]:
        """Formal parameter names of one local function (best effort).

        ``at_line`` selects a specific overload's definition line;
        otherwise the first definition wins.
        """
        from ecdat.scanners.source import c_parser as _cp
        try:
            if at_line is not None:
                lineno = int(at_line)
            else:
                lineno = _cp._def_lines(masked).get(func) or 0
            if not lineno:
                return []
            statement = _cp.statement_text(list(lines or []), int(lineno))
            inner = statement.split("(", 1)[1].rsplit(")", 1)[0]
            params = []
            for part in _cp.split_args(inner):
                tokens = re.findall(r"[A-Za-z_]\w*", part)
                if tokens:
                    params.append(tokens[-1])
            return params
        except Exception:
            return []

        except Exception:
            return []

    _WRAPPER_CIPHER_FAMILY_RE = re.compile(
        r"AES|RSA|DES|3DES|CHACHA|BLOWFISH|CAMELLIA|ARIA|SM4")

    def _resolve_cross_file_wrappers(
            self, findings: list) -> list:
        """Attribute cross-file delegate calls + field flows (Java-only).

        Consumes ``_crypto_delegates`` (factory wrappers recorded during
        the brace scan): call sites in other files whose base name
        exactly matches a delegate resolve through it, with forwarded
        string arguments re-parsed (call-site constants win) and the
        delegate default otherwise. Same-file cipher field flows
        (``this.f = newCipher(..)`` + ``initCipher`` direction +
        ``doFinal`` terminal) and instance ``doFinal`` anchored to a
        same-function cipher finding complete the one-hop picture.
        Everything emits at Probable (reachability, not direct params);
        anything unresolvable is skipped, never guessed.
        """
        from ecdat.scanners.source import c_parser as _cp
        table: dict[str, tuple] = {}
        for path in sorted(self._crypto_delegates):
            for func, spec in self._crypto_delegates[path].items():
                table.setdefault(func, (spec, path))
        covered: set[tuple] = set()
        for finding in findings or []:
            try:
                loc = finding.location
                covered.add((str(loc.file), int(loc.line or 0),
                             str(finding.canonical)))
            except Exception:
                continue
        out: list = []
        for path in sorted(self._brace_ctx):
            if not str(path).endswith(".java"):
                continue
            ctx = self._brace_ctx.get(path) or {}
            sites = ctx.get("sites") or []
            if not any(s[0] in table or s[0] in ("initCipher", "doFinal")
                       for s in sites):
                continue
            try:
                content = self._file_cache.get(str(path))
                if content is None:
                    content = Path(path).read_text(encoding="utf-8",
                                                   errors="ignore")
            except Exception:
                continue
            try:
                masked, _ = _cp.mask_source(content)
                consts = _cp.collect_constants(masked)
                for key, value in _cp.collect_java_string_consts(
                        content).items():
                    consts.setdefault(key, value)
                lines = content.splitlines()
                call_sites = _cp.extract_calls(masked)
            except Exception:
                continue
            classification = str(ctx.get("classification", "use") or "use")
            try:
                deflines = _cp._def_lines_all(masked)
            except Exception:
                deflines = {}
            for site in call_sites:
                base = site.name.split(".")[-1].split(":")[-1]
                if base in table:
                    if self._site_is_def(lines, site, base, deflines):
                        continue
                    item = self._delegate_call_finding(
                        site, base, table[base], Path(path),
                        classification, consts, lines, covered)
                    if item is not None:
                        out.append(item)
                        try:
                            covered.add((str(path), int(site.line),
                                         str(item.canonical)))
                        except Exception:
                            pass
            out.extend(self._field_flow_findings(
                Path(path), call_sites, consts, lines, classification,
                table, findings, covered, deflines))
            for item in out:
                try:
                    loc = item.location
                    covered.add((str(loc.file), int(loc.line or 0),
                                 str(item.canonical)))
                except Exception:
                    pass
        return out

    @staticmethod
    def _site_is_def(lines: list, site, base: str,
                     deflines: dict) -> bool:
        """True when a call site IS the named definition (not a call).

        Covers `{`-style definitions (site line equals a def line) and
        `;` prototypes (declaration check mirrors the API loop).
        """
        from ecdat.scanners.source import c_parser as _cp
        try:
            if int(getattr(site, "line", 0) or 0) in \
                    (deflines or {}).get(base, []):
                return True
            statement = _cp.statement_text(list(lines or []),
                                           int(site.line))
            return bool(SourceScanner._looks_like_declaration(
                statement, base))
        except Exception:
            return False

    def _delegate_call_finding(self, site, base: str, entry: tuple,
                               file_path: Path, classification: str,
                               consts: dict, lines: list,
                               covered: set) -> object | None:
        """One cross-file delegate finding (or None when unresolvable).

        Only cross-file sites are handled here (same-file wrapper calls
        belong to the same-file wrapper pass, which also owns overload
        arity). Attribution requires a qualified call
        (``CipherUtils.newCipher``, qualifier = defining file's type
        name) or a capitalized factory/constructor call — bare lowercase
        cross-file helper names (``encrypt``) are skipped to avoid
        cross-file name collisions.
        """
        from ecdat.scanners.source import c_parser as _cp
        from ecdat.core.cir_models import UsageState
        try:
            spec, deffile = entry
            if site.function == base and str(file_path) == str(deffile):
                return None  # the delegate's own body: already covered
            if str(file_path) == str(deffile):
                return None  # same file: same-file wrapper pass owns it
            if "." in (site.name or ""):
                qual = site.name.rsplit(".", 1)[0].split(".")[-1]
                try:
                    stem = Path(str(deffile)).stem
                except Exception:
                    stem = ""
                if qual != stem:
                    return None
            elif not base[:1].isupper():
                return None  # bare lowercase cross-file: collision risk
            parts = _cp.split_args(str(getattr(site, "args", "") or ""))
            token = ""
            for i in (spec.get("fwd") or []):
                if 0 <= int(i) < len(parts):
                    token = self._java_call_token(parts[int(i)], consts,
                                                  lines, site.line)
                    if token:
                        break
            parsed = False
            resolved = None
            if token:
                parser = "jca-transformation" if "/" in token else "jca-name"
                synth = {"id": str(spec.get("row_id", "")),
                         "call": str(spec.get("call", "")),
                         "parser": parser,
                         "canonical": str(spec.get("canonical", "AES")),
                         "op": str(spec.get("op", "ENCRYPT")),
                         "confidence": 0.70}
                candidate = _cp.resolve_entry(
                    synth, f'"{token}"', {}, str(spec.get("call", "")),
                    [token])
                detail = str(candidate.get("detail", "") or "")
                if "transformation" in detail or "algorithm" in detail \
                        or "fetch" in detail or "signature" in detail:
                    candidate["confidence"] = 0.70
                    resolved = candidate
                    parsed = True
            if resolved is None:
                resolved = {
                    "canonical": str(spec.get("canonical", "AES")),
                    "key_size": spec.get("key_size"),
                    "mode": spec.get("mode"),
                    "curve": None, "protocol": None,
                    "op": str(spec.get("op", "ENCRYPT")),
                    "confidence": 0.65,
                    "detail": f"delegate default ({spec.get('call', '')})",
                }
            if (str(file_path), int(site.line),
                    str(resolved.get("canonical"))) in covered:
                return None
            finding = self._build_finding(
                file_path=file_path, line=site.line,
                function=site.function, lang="java",
                classification=classification,
                call_text=site.call_text, api_name=site.name,
                resolved=resolved,
                row={"id": str(spec.get("row_id", "")),
                     "call": str(spec.get("call", "")),
                     "library": "jca"},
                args=[], tool="source:wrapper-call",
                detail_prefix="cross-file wrapper resolving to "
                              f"{spec.get('call', '')}",
                wrapper_from=base,
            )
            if finding is not None and finding.usage_state == \
                    UsageState.CONFIRMED:
                finding.usage_state = UsageState.PROBABLE
            return finding
        except Exception:
            return None

    @staticmethod
    def _java_call_token(part: str, consts: dict, lines: list,
                         lineno: int) -> str:
        """Resolve one call-site argument to an algorithm string (or "")."""
        from ecdat.scanners.source import c_parser as _cp
        try:
            piece = str(part or "").strip()
            if not piece:
                return ""
            if '"' in piece:
                try:
                    raw = lines[int(lineno) - 1] \
                        if 0 < int(lineno) <= len(lines) else ""
                except Exception:
                    raw = ""
                for lit in _cp.string_literals_of_line(raw or ""):
                    if lit:
                        return lit
                return ""
            token = _cp.resolve_arg(piece, consts).strip().strip('"')
            if not token or token in ("this", "null"):
                return ""
            return token
        except Exception:
            return ""

    def _field_flow_findings(self, file_path: Path, sites: list,
                             consts: dict, lines: list,
                             classification: str, table: dict,
                             findings: list, covered: set,
                             deflines: dict | None = None) -> list:
        """Cipher field flows: ``this.f = factory(..)`` + init + doFinal."""
        from ecdat.scanners.source import c_parser as _cp
        from ecdat.core.cir_models import UsageState
        out: list = []
        try:
            deflines = deflines or {}
            fields: dict[str, dict] = {}
            assign_re = re.compile(
                r"(?:this\.)?([A-Za-z_]\w*)\s*(?<![=!<>])=(?!=)\s*"
                r"([^;]{1,300}?);", re.DOTALL)
            for match in assign_re.finditer("\n".join(lines or [])):
                field, rhs = match.group(1), match.group(2)
                if not re.search(r"newCipher|newSecretKey|getInstance|"
                                 r"SecretKeySpec", rhs):
                    continue
                sem = self._java_rhs_semantics(rhs, consts, table)
                if sem is not None:
                    fields.setdefault(field, sem)
            inits: dict[str, str] = {}
            for site in sites or []:
                base = site.name.split(".")[-1].split(":")[-1]
                if base != "initCipher":
                    continue
                if self._site_is_def(lines, site, base, deflines):
                    continue
                parts = _cp.split_args(str(getattr(site, "args", "") or ""))
                if not parts:
                    continue
                field = parts[0].strip()
                if field.startswith("this."):
                    field = field[5:]
                if not re.fullmatch(r"[A-Za-z_]\w*", field):
                    continue
                direction = ""
                if re.search(r"\bDECRYPT_MODE\b", site.args or ""):
                    direction = "DECRYPT"
                elif re.search(r"\bENCRYPT_MODE\b", site.args or ""):
                    direction = "ENCRYPT"
                if direction:
                    inits.setdefault(field, direction)
            anchorable = []
            for finding in findings or []:
                try:
                    loc = finding.location
                    if str(loc.file) != str(file_path):
                        continue
                    if self._WRAPPER_CIPHER_FAMILY_RE.search(
                            str(finding.canonical or "").upper()):
                        anchorable.append(finding)
                except Exception:
                    continue
            for site in sites or []:
                base = site.name.split(".")[-1].split(":")[-1]
                if base != "doFinal":
                    continue
                if self._site_is_def(lines, site, base, deflines):
                    continue
                parts = _cp.split_args(str(getattr(site, "args", "") or ""))
                first = parts[0].strip() if parts else ""
                if first.startswith("this."):
                    first = first[5:]
                canonical = mode = direction = None
                if re.fullmatch(r"[A-Za-z_]\w*", first or "") \
                        and first in fields and first in inits:
                    canonical = fields[first].get("canonical")
                    mode = fields[first].get("mode")
                    direction = inits[first]
                else:
                    receiver = site.name.rsplit(".", 1)[0] \
                        if "." in site.name else ""
                    recv_base = receiver.split(".")[-1]
                    if not recv_base or not recv_base[:1].islower():
                        continue
                    best = None
                    for finding in anchorable:
                        try:
                            if str(finding.location.function or "") != \
                                    str(site.function or ""):
                                continue
                            dist = abs(int(finding.location.line or 0)
                                       - int(site.line))
                            if best is None or dist < best[0]:
                                best = (dist, finding)
                        except Exception:
                            continue
                    if best is None:
                        continue
                    canonical = best[1].canonical
                    mode = best[1].mode
                    method = str(site.function or "").lower()
                    if method.startswith("encrypt"):
                        direction = "ENCRYPT"
                    elif method.startswith("decrypt"):
                        direction = "DECRYPT"
                    else:
                        continue
                if not canonical or not direction:
                    continue
                key = (str(file_path), int(site.line), str(canonical))
                if key in covered:
                    continue
                resolved = {"canonical": str(canonical),
                            "key_size": None, "mode": mode, "curve": None,
                            "protocol": None, "op": direction,
                            "confidence": 0.70,
                            "detail": "cipher field flow to doFinal"}
                finding = self._build_finding(
                    file_path=file_path, line=site.line,
                    function=site.function, lang="java",
                    classification=classification,
                    call_text=site.call_text, api_name=site.name,
                    resolved=resolved,
                    row={"id": "jca-field-flow", "call": site.name,
                         "library": "jca"},
                    args=[], tool="source:wrapper-call",
                    detail_prefix="cipher field flow to doFinal",
                    wrapper_from=base,
                )
                if finding is not None:
                    if finding.usage_state == UsageState.CONFIRMED:
                        finding.usage_state = UsageState.PROBABLE
                    out.append(finding)
                    covered.add(key)
        except Exception:
            pass
        return out

    @staticmethod
    def _java_rhs_semantics(rhs: str, consts: dict, table: dict) -> dict | None:
        """Resolve a cipher-factory RHS to {canonical, mode} (or None)."""
        from ecdat.scanners.source import c_parser as _cp
        try:
            text = str(rhs or "")
            lits = re.findall(r'"((?:[^"\\]|\\.)*)"', text)
            token = ""
            if lits:
                token = str(lits[0] or "")
            else:
                for ident in re.findall(r"[A-Za-z_]\w*", text):
                    if ident in ("this", "new", "return", "CipherUtils",
                                 "Cipher", "newCipher", "newSecretKey",
                                 "getInstance", "SecretKeySpec"):
                        continue
                    resolved = _cp.resolve_arg(ident, consts)
                    candidate = str(resolved or "").strip().strip('"')
                    if candidate and candidate != ident:
                        token = candidate
                        break
                    if ident in consts:
                        continue
                    token = ident
                    break
            if token:
                synth = {"id": "jca-field", "call": "Cipher.getInstance",
                         "parser": "jca-transformation", "canonical": "AES",
                         "op": "ENCRYPT", "confidence": 0.70}
                resolved = _cp.resolve_entry(synth, f'"{token}"', {},
                                             "Cipher.getInstance", [token])
                detail = str(resolved.get("detail", "") or "")
                if "transformation" in detail or "algorithm" in detail:
                    return {"canonical": str(resolved.get("canonical")),
                            "mode": resolved.get("mode")}
                return None
            base = re.search(r"(\w+)\s*\(", text)
            if base and base.group(1) in table:
                spec = table[base.group(1)][0]
                return {"canonical": str(spec.get("canonical", "AES")),
                        "mode": spec.get("mode")}
        except Exception:
            pass
        return None

    def _stash_brace_ctx(self, file_path: Path, sites: list,
                           masked: str, classification: str,
                           findings: list[ScannerFinding]) -> None:
        """Record per-file call/definition context for the custom-API pass."""
        from ecdat.scanners.source import fingerprints as _fp
        from ecdat.scanners.source import c_parser as _cp
        try:
            defs = _fp.defined_functions(masked)
        except Exception:
            defs = []
        try:
            def_qual = _fp.definition_qualifiers(masked)
        except Exception:
            def_qual = {}
        try:
            consts = _cp.collect_constants(masked)
        except Exception:
            consts = {}
        try:
            # Configurable AES sizes from preprocessor conditionals
            # (e.g. ``#if defined(AES256)``): merged repo-wide by the
            # custom-invocation pass for active-vs-supported key config.
            aes_cond = _cp.aes_key_config({}, masked)[1]
        except Exception:
            aes_cond = []
        impl: dict[str, float] = {}
        for finding in findings:
            try:
                for ev in (finding.evidence or []):
                    if str(getattr(ev, "tool", "")) == "source:fingerprint":
                        impl[str(finding.canonical)] = max(
                            impl.get(str(finding.canonical), 0.0),
                            float(finding.confidence or 0.0))
            except Exception:
                continue
        ctx = {
            "sites": self._ctx_sites(file_path, sites),
            "defs": defs,
            "def_qual": def_qual,
            "impl": impl,
            "classification": classification,
            "consts": consts,
            "aes_cond": aes_cond,
        }
        self._brace_ctx[str(file_path)] = ctx
        # Attach context to the cached entry as well.
        try:
            for key, value in list(self._brace_cache.items()):
                if key[0] == str(file_path):
                    vals = list(value)
                    while len(vals) < 4:
                        vals.append(None)
                    vals[3] = ctx
                    self._brace_cache[key] = tuple(vals)
        except Exception:
            pass

    @staticmethod
    def _ctx_sites(file_path: Path, sites: list) -> list[tuple]:
        """Sites with a prototype flag (one file read for the whole file)."""
        from ecdat.scanners.source import c_parser as _cp
        try:
            lines = Path(file_path).read_text(
                encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            lines = []
        out: list[tuple] = []
        for s in sites:
            base = s.name.split(".")[-1].split(":")[-1]
            is_decl = False
            try:
                if lines:
                    statement = _cp.statement_text(lines, s.line)
                    is_decl = SourceScanner._looks_like_declaration(
                        statement, base)
            except Exception:
                is_decl = False
            out.append((base, s.line, s.function, s.call_text, is_decl))
        return out

    @staticmethod
    def _site_is_declaration(file_path: Path, site) -> bool:
        """Prototype check for the custom-invocation pass (mirrors the
        API loop's `_looks_like_declaration` filter)."""
        try:
            from ecdat.scanners.source import c_parser as _cp
            content = Path(file_path).read_text(encoding="utf-8",
                                                errors="ignore")
            lines = content.splitlines()
            base = site.name.split(".")[-1].split(":")[-1]
            statement = _cp.statement_text(lines, site.line)
            return SourceScanner._looks_like_declaration(statement, base)
        except Exception:
            return False

    @staticmethod
    def _family_of(canonical: str) -> str | None:
        """Map a finding canonical to a fingerprint family (or None)."""
        from ecdat.scanners.source import fingerprints as _fp
        upper = str(canonical or "").upper().replace("-", "").replace("_", "")
        for family in _fp.FINGERPRINT_FAMILIES:
            fkey = family.upper().replace("-", "").replace("_", "")
            if upper == fkey or upper.startswith(fkey):
                return family
        return None

    def _fingerprint_findings(self, file_path: Path, lang: str,
                              masked: str, classification: str,
                              findings: list[ScannerFinding]
                              ) -> list[ScannerFinding]:
        """Structural implementation findings for one file (Phase 5)."""
        from ecdat.scanners.source import fingerprints as _fp
        if lang not in ("c", "cpp"):
            return []
        if classification == "test-vector":
            # Test files embed vectors/tables as *data*; they never
            # establish an implementation. Their invocations are still
            # resolved via the cross-file pass.
            return []
        covered = {self._family_of(f.canonical) for f in findings}
        covered.discard(None)
        try:
            hits = _fp.analyze_file(masked, lang)
        except Exception:
            return []
        out: list[ScannerFinding] = []
        for hit in hits:
            if hit.canonical in covered:
                continue
            self._last_stats["fingerprints"] = \
                self._last_stats.get("fingerprints", 0) + 1
            detail = (f"custom {hit.canonical} implementation at "
                      f"{file_path} [{hit.detail}]")
            evidence = create_evidence_signal(
                tool="source:fingerprint", detail=detail,
                confidence=round(hit.confidence, 3),
                snippet=f"{hit.canonical} structural fingerprint: "
                        f"{len(hit.signals)} signal(s)",
            )
            out.append(ScannerFinding(
                canonical=hit.canonical,
                original=hit.canonical,
                library="custom",
                usage_state=UsageState.PROVIDED_ONLY,
                confidence=round(hit.confidence, 3),
                evidence=[evidence],
                location=Location(file=str(file_path), line=1),
                operation_type=None,
                implementation=Implementation(
                    library="custom", api="structural-fingerprint"),
                context=Context(exposure=Exposure.INTERNAL),
                dependency_only=True,
            ))
        return out

    def _resolve_custom_invocations(self) -> list[ScannerFinding]:
        """Cross-file invocations of repo-defined crypto functions.

        A call in file B to a function *defined* in file A (where file A
        carries a structural implementation fingerprint) is a confirmed
        cryptographic operation — Cryptoscope-style reconstruction for
        custom APIs. Same-file calls are implementation detail (covered
        by the fingerprint finding); names without an operation hint
        are skipped rather than guessed.

        Definitions themselves also refine the fingerprinted signal
        (P1): a definition such as ``aes_encrypt_cbc`` in a file with
        AES implementation evidence yields a mode-aware custom
        operation (``AES-CBC``/``Encrypt``). Names never create a
        signal alone — the fingerprint gate is required. Prototypes
        are never invocations (P2).
        """
        from ecdat.scanners.source import c_parser as _cp
        from ecdat.scanners.source import fingerprints as _fp
        # def base name -> (defining file, canonical, confidence, qualifier)
        providers: dict[str, tuple[str, str, float, str]] = {}
        for path, ctx in self._brace_ctx.items():
            impl = ctx.get("impl") or {}
            if not impl:
                continue
            qual_map = ctx.get("def_qual") or {}
            for canonical, confidence in impl.items():
                if float(confidence or 0.0) < 0.65:
                    continue
                for def_name, _line in ctx.get("defs") or []:
                    qual = str(qual_map.get(def_name, "") or "")
                    qname = f"{qual}::{def_name}" if qual else def_name
                    if _fp.def_name_matches_family(qname, canonical):
                        providers.setdefault(
                            def_name,
                            (path, canonical, float(confidence), qual))
        # Repo-level compile-time AES key config (P4): merged defines
        # plus preprocessor-conditional sizes across scanned files.
        merged_consts: dict[str, str] = {}
        cond_sizes: set[int] = set()
        for ctx in self._brace_ctx.values():
            try:
                merged_consts.update(ctx.get("consts") or {})
            except Exception:
                pass
            try:
                cond_sizes.update(ctx.get("aes_cond") or [])
            except Exception:
                pass
        try:
            key_active, key_supported = _cp.aes_key_config(merged_consts, "")
            key_supported = sorted(set(key_supported) | cond_sizes)
        except Exception:
            key_active, key_supported = None, []
        key_note = ""
        if key_active is not None or key_supported:
            active_txt = f"AES-{key_active} active" if key_active is not None \
                else "active size unknown"
            supported_txt = "/".join(f"AES-{s}" for s in key_supported) \
                if key_supported else "unknown"
            key_note = f"; key-config: {active_txt}; supported {supported_txt}"
        out: list[ScannerFinding] = []
        for path, ctx in self._brace_ctx.items():
            classification = str(ctx.get("classification") or "use")
            for site_entry in ctx.get("sites") or []:
                base, line, function, call_text = site_entry[:4]
                is_decl = bool(site_entry[4]) if len(site_entry) > 4 else False
                if is_decl:
                    continue  # prototype, not an invocation
                provider = providers.get(base)
                if provider is None:
                    continue
                def_path, canonical, _conf, def_qual = provider
                if def_path == path:
                    continue  # implementation detail, not an invocation
                sem_name = f"{def_qual}::{base}" if def_qual else base
                op_name = _fp.op_hint_for_name(sem_name)
                if op_name is None:
                    continue
                try:
                    op_type = OperationType[op_name]
                except KeyError:
                    continue
                invoked_canonical, invoked_mode = self._invoked_canonical(
                    sem_name, canonical)
                if classification == "test-vector":
                    usage, confidence = UsageState.POSSIBLE, 0.39
                else:
                    usage, confidence = UsageState.CONFIRMED, 0.85
                detail = (f"invocation of repo-defined {canonical} "
                          f"function {base} at {path}:{line} "
                          f"(defined in {def_path})")
                if invoked_mode:
                    detail += f" [mode {invoked_mode}]"
                out.append(ScannerFinding(
                    canonical=invoked_canonical,
                    original=invoked_canonical,
                    library="custom",
                    key_size=(key_active if canonical == "AES" else None),
                    mode=invoked_mode,
                    usage_state=usage,
                    confidence=confidence,
                    evidence=[create_evidence_signal(
                        tool="source:custom-invocation",
                        detail=detail,
                        confidence=confidence,
                        snippet=str(call_text or "")[:200],
                    )],
                    location=Location(file=str(path), line=line,
                                      function=function),
                    operation_type=op_type,
                    function=function,
                    implementation=Implementation(
                        library="custom", api=base),
                    context=Context(exposure=Exposure.INTERNAL),
                ))
        out.extend(self._definition_findings(key_active, key_note))
        if out:
            self._last_stats["custom_invocations"] = len(out)
        return out

    @staticmethod
    def _invoked_canonical(base: str,
                           provider_canonical: str) -> tuple[str, str | None]:
        """Mode-aware canonical for an invoked custom function name.

        The mode token refines the provider family (``aes_encrypt_cbc``
        -> ``AES-CBC``); a missing token keeps the generic family, and a
        conflicting family keeps the provider (collision-safe: never
        guessed from the name alone).
        """
        from ecdat.scanners.source import fingerprints as _fp
        try:
            sem_fam, sem_mode, _ops = _fp.function_semantics(base)
        except Exception:
            return provider_canonical, None
        if sem_mode and (sem_fam is None or sem_fam == provider_canonical):
            try:
                composed = _fp.canonical_for_semantics(
                    provider_canonical, sem_mode)
            except Exception:
                composed = None
            if composed:
                return composed, sem_mode
        return provider_canonical, None

    def _definition_findings(self, key_active: int | None,
                             key_note: str) -> list[ScannerFinding]:
        """Mode-aware operations from custom crypto definitions (P1/P6).

        For files carrying fingerprint implementation evidence, each
        defined function whose name refines that signal (family token +
        operation) becomes a custom operation finding via the existing
        ``_build_finding`` path (usage/confidence by file
        classification; test and header files excluded). Bodies are
        checked for bounded local-structure corroboration (IV/counter/
        hash staging) which enriches the evidence detail.
        """
        from ecdat.scanners.source import c_parser as _cp
        from ecdat.scanners.source import fingerprints as _fp
        out: list[ScannerFinding] = []
        for path, ctx in self._brace_ctx.items():
            classification = str(ctx.get("classification") or "use")
            if classification in ("test-vector", "header-capability"):
                continue
            impl = ctx.get("impl") or {}
            try:
                strong = {fam for fam, conf in impl.items()
                          if float(conf or 0.0) >= 0.65}
            except Exception:
                continue
            if not strong:
                continue
            defs = ctx.get("defs") or []
            if not defs:
                continue
            qual_map = ctx.get("def_qual") or {}
            bodies = self._definition_bodies(str(path))
            for def_name, def_line in defs:
                qual = str(qual_map.get(def_name, "") or "")
                qname = f"{qual}::{def_name}" if qual else def_name
                try:
                    fam, mode, ops = _fp.function_semantics(qname)
                except Exception:
                    continue
                if fam is None or fam not in strong or not ops:
                    continue
                canonical = _fp.canonical_for_semantics(fam, mode) or fam
                notes = _fp.corroborate_definition(
                    bodies.get(def_name, ""), mode, ops)
                confidence = 0.90 if notes else 0.85
                detail = f"custom {fam} implementation"
                if notes:
                    detail += "; structure " + ",".join(notes)
                if fam == "AES" and key_note:
                    detail += key_note
                for op_name in ops:
                    resolved = {
                        "canonical": canonical,
                        "key_size": (key_active if fam == "AES" else None),
                        "mode": mode,
                        "curve": None,
                        "protocol": None,
                        "detail": detail,
                        "confidence": confidence,
                        "op": op_name,
                    }
                    try:
                        finding = self._build_finding(
                            file_path=Path(path), line=int(def_line or 1),
                            function=def_name, lang="c",
                            classification=classification,
                            call_text=f"{def_name}(...)",
                            api_name=def_name,
                            resolved=resolved,
                            row={"library": "custom"},
                            args=[],
                            tool="source:custom-invocation",
                            detail_prefix=(
                                f"repo-defined {canonical} function "
                                f"{def_name} defined"),
                            wrapper_from=None,
                        )
                    except Exception:
                        continue
                    if finding is not None:
                        out.append(finding)
        return out

    def _definition_bodies(self, path: str) -> dict[str, str]:
        """Masked function bodies by name for one file (bounded, P6).

        Only consulted for fingerprint-backed implementation files;
        bodies are capped so pathological files cannot blow up the
        scan. Never raises.
        """
        from ecdat.scanners.source import c_parser as _cp
        try:
            content = self._file_cache.get(str(path))
            if content is None:
                content = Path(path).read_text(encoding="utf-8",
                                               errors="ignore")
            masked, _ = _cp.mask_source(content)
            bodies: dict[str, str] = {}
            for start, end, name in _cp._function_spans(masked):
                if name not in bodies:
                    bodies[name] = masked[start:end][:4000]
            return bodies
        except Exception:
            return {}

    def _remember_brace(self, cache_key: tuple, findings: list,
                        suppressed: int, classification: str) -> None:
        """Store brace-file results in the bounded Phase 13 cache."""
        try:
            if len(self._brace_cache) >= self._brace_cache_max:
                # Evict oldest entry (dict insertion order).
                oldest = next(iter(self._brace_cache))
                del self._brace_cache[oldest]
            self._brace_cache[cache_key] = (list(findings), suppressed,
                                            classification)
        except Exception:
            pass

    @staticmethod
    def _looks_like_declaration(line: str, name: str) -> bool:
        """Filter C-style prototypes (``int EVP_x(...);``), not calls.

        Multi-line prototypes are handled by the caller, which passes
        statement text (see c_parser.statement_text). A trailing comment
        after the terminator (``void f(...); // comment``) is stripped
        first: callers read original (unmasked) lines, which end with the
        comment rather than ``;``. Only the comment following the
        statement is removed — mid-statement ``//`` notes (common in
        multi-line prototypes) are left intact.
        """
        stripped = line.strip()
        stripped = re.sub(r";\s*//.*$", ";", stripped).strip()
        stripped = re.sub(r";\s*/\*.*?\*/\s*$", ";", stripped).strip()
        if "(" not in stripped or name not in stripped:
            return False
        tail = stripped.split(name, 1)[1]
        if not tail.startswith("("):
            return False
        # The brace check applies to the tail (after the name): a `{`
        # there opens a definition body (``void f() {``). A brace
        # *before* the name (``class AES { ... f(...);``) is a class
        # context, not a body — inline member declarations still end
        # with ``;`` and must stay declarations.
        if stripped.endswith(";") and "{" not in tail and "=" not in stripped.split("(", 1)[0]:
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
    # PyCryptodome block ciphers whose `.new()` constructor takes a mode
    # argument (positional #2 or `mode=` keyword). When a mode is resolved
    # the canonical embeds it (AES-ECB), matching the risk/recommend
    # registry convention (risk.py QUANTUM_VULN, recommend.py registry).
    _MODED_CIPHERS = frozenset({"AES", "DES", "DES3", "Blowfish"})

    # Mode tokens accepted from constructor args (PyCryptodome + generic).
    _MODE_TOKENS = frozenset({
        "ECB", "CBC", "CFB", "OFB", "CTR", "OPENPGP",
        "CCM", "EAX", "GCM", "SIV", "OCB",
    })

    def __init__(self, file_path: Path, content: str):
        self.file_path = file_path
        self.content = content
        self.lines = content.splitlines()
        self.findings: list[ScannerFinding] = []
        self.imports: dict[str, str] = {}
        # Module-level NAME -> assigned expression text (for mode aliases
        # such as `MODE = AES.MODE_ECB`). Single bounded pass, no dataflow.
        self._constants: dict[str, str] = {}
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
                elif isinstance(node, ast.Assign) and len(node.targets) == 1 \
                        and isinstance(node.targets[0], ast.Name):
                    try:
                        self._constants[node.targets[0].id] = \
                            ast.unparse(node.value)
                    except Exception:
                        pass
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

    # Binding aliases / class definitions that name concrete primitives
    # (``AESGCM = rust_openssl.aead.AESGCM``, ``class AES:``) are
    # ProvidedOnly capabilities — never Confirmed operations. Only exact
    # allowlist hits emit; everything else (SIV variants without a
    # canonical, generic classes, mode constants) stays silent.
    _CRYPTO_ALIAS_ATTRS = {
        "AESGCM": "AES-256-GCM",
        "ChaCha20Poly1305": "ChaCha20-Poly1305",
    }
    _CRYPTO_MODE_CLASSES = frozenset({
        "ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "CCM", "XTS", "OCB",
    })
    # Class names that denote concrete primitives (pyca-style layout).
    # The signature registry has no bare family names (only AES-128-CBC
    # style entries), so this explicit map stands in for it here.
    _CRYPTO_CLASS_ALGOS = {
        "AES": "AES", "AES128": "AES", "AES256": "AES",
        "ChaCha20": "ChaCha20", "TripleDES": "3DES", "DES": "DES",
        "Blowfish": "Blowfish", "Camellia": "Camellia", "SEED": "SEED",
        "SM4": "SM4", "IDEA": "IDEA", "CAST5": "CAST5", "RC4": "RC4",
        "MD5": "MD5", "SHA1": "SHA-1", "SHA256": "SHA-256",
        "SHA512": "SHA-512", "RSA": "RSA", "DSA": "DSA", "DH": "DH",
        "ECDSA": "ECDSA", "Ed25519": "Ed25519", "X25519": "X25519",
        "HMAC": "HMAC", "PBKDF2": "PBKDF2",
    }

    def visit_Assign(self, node: ast.Assign):
        try:
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                    and isinstance(node.value, ast.Attribute):
                chain: list[str] = []
                current: ast.expr = node.value
                while isinstance(current, ast.Attribute):
                    chain.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    chain.append(current.id)
                    tail = chain[0]
                    canonical = self._CRYPTO_ALIAS_ATTRS.get(tail)
                    if canonical is not None:
                        dotted = ".".join(reversed(chain))
                        root = chain[-1]
                        library = str(self.imports.get(root, root) or "")
                        library = library.split(".")[0]
                        self._create_capability_finding(
                            canonical, node.lineno,
                            f"crypto binding alias: {dotted}", library)
        except Exception:
            pass
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        try:
            name = str(getattr(node, "name", "") or "")
            canonical: Optional[str] = None
            if name in self._CRYPTO_MODE_CLASSES:
                canonical = name
            elif name in self._CRYPTO_CLASS_ALGOS:
                canonical = self._CRYPTO_CLASS_ALGOS[name]
            else:
                norm, _original = normalize_algorithm(name)
                if norm != name and get_category(norm) is not None \
                        and get_category(norm) != "library":
                    canonical = norm
            if canonical is not None:
                self._create_capability_finding(
                    canonical, node.lineno,
                    f"crypto class definition: {name}", "custom")
        except Exception:
            pass
        self.generic_visit(node)

    def _create_capability_finding(self, canonical: str, line_no: int,
                                   detail: str, library: str) -> None:
        """One ProvidedOnly capability finding (never a Confirmed op)."""
        canonical_norm, original = normalize_algorithm(canonical)
        snippet = self.lines[line_no - 1].strip() \
            if 0 < line_no <= len(self.lines) else ""
        self.findings.append(ScannerFinding(
            canonical=canonical_norm,
            original=original,
            library=None,
            usage_state=UsageState.PROVIDED_ONLY,
            confidence=0.45,
            evidence=[create_evidence_signal(
                tool="source:ast",
                detail=f"{detail} at {self.file_path}:{line_no}",
                confidence=0.45,
                snippet=snippet[:200],
            )],
            location=Location(file=str(self.file_path), line=line_no,
                              function=self.current_function),
            operation_type=None,
            function=self.current_function,
            implementation=Implementation(library=library, api=detail),
            context=Context(exposure=Exposure.INTERNAL),
            dependency_only=True,
        ))

    def _mode_token(self, text: str) -> Optional[str]:
        """Extract a cipher-mode token from one argument expression text.

        Accepts dotted constants (``AES.MODE_ECB``), bare names
        (``MODE_ECB``/``ECB``), and string literals (``"ECB"``).
        Returns the upper-cased mode or None (never guesses).
        """
        token = str(text or "").strip().strip("'\"")
        if not token:
            return None
        # Dotted constant: the attribute carries the mode (AES.MODE_ECB).
        # Bare name: suffix after the last underscore (MODE_ECB -> ECB).
        tail = token.split(".")[-1].upper()
        candidate = tail.split("_")[-1] if "_" in tail else tail
        if candidate in self._MODE_TOKENS:
            return candidate
        return None

    def _resolve_mode_expr(self, expr: "ast.expr", _seen: frozenset = frozenset()) -> Optional[str]:
        """Resolve a mode argument AST node to a mode token (bounded)."""
        if isinstance(expr, ast.Attribute):
            return self._mode_token(expr.attr)
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return self._mode_token(expr.value)
        if isinstance(expr, ast.Name):
            # Bare imported constant (from Crypto.Cipher.AES import
            # MODE_ECB): the name itself carries the mode.
            hit = self._mode_token(expr.id)
            if hit:
                return hit
            if expr.id in _seen:
                return None
            raw = self._constants.get(expr.id)
            if raw is None:
                return None
            # Alias may itself be dotted (AES.MODE_ECB) or a mode word.
            hit = self._mode_token(raw)
            if hit:
                return hit
            # One more hop: alias-to-alias (MODE2 = MODE).
            if re.fullmatch(r"[A-Za-z_]\w*", raw.strip()):
                try:
                    nxt = ast.parse(raw.strip(), mode="eval").body
                except Exception:
                    return None
                return self._resolve_mode_expr(nxt, _seen | {expr.id})
            return None
        return None

    def _constructor_mode(self, node: ast.Call) -> Optional[str]:
        """Mode for a cipher constructor call (PyCryptodome `.new()`).

        Positional arg #2 (``AES.new(key, AES.MODE_ECB)``) or the ``mode=``
        keyword. Absent/unresolvable -> None (no default-mode guessing).
        """
        candidates: list = []
        if len(node.args) >= 2:
            candidates.append(node.args[1])
        for kw in node.keywords:
            if kw.arg == "mode":
                candidates.append(kw.value)
        for expr in candidates:
            hit = self._resolve_mode_expr(expr)
            if hit:
                return hit
        return None

    def _create_cipher_constructor_finding(
        self, cipher_module: str, method_name: str,
        node: ast.Call, line_no: int, full_call: str,
    ) -> bool:
        """Emit a finding for ``<Cipher>.new(...)`` (PyCryptodome style).

        Returns True when handled (whether or not a mode resolved — the
        constructor itself is an Encrypt operation on the cipher).
        """
        pattern = f"Crypto.Cipher.{cipher_module}"
        entry = PYTHON_CRYPTO_PATTERNS.get(pattern)
        if entry is None:
            return False
        canonical, op_type = entry
        mode = self._constructor_mode(node)
        if mode and canonical in self._MODED_CIPHERS:
            canonical = f"{canonical}-{mode}"
        self._create_finding(pattern, canonical, op_type, line_no,
                             full_call, node, mode_override=mode)
        return True

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
                # PyCryptodome constructors: AES.new(key, AES.MODE_ECB).
                if method_name == "new":
                    for import_alias, full_import in self.imports.items():
                        if obj_name_lower == import_alias.lower() \
                                and full_import.startswith("Crypto.Cipher."):
                            cipher_module = full_import[len("Crypto.Cipher."):]
                            if self._create_cipher_constructor_finding(
                                    cipher_module, method_name, node,
                                    node.lineno, full_call):
                                return
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

            # Fully-qualified PyCryptodome constructor:
            # Crypto.Cipher.AES.new(key, AES.MODE_ECB).
            if method_name == "new" and len(attr_chain) >= 4 \
                    and attr_chain[-1] == "Crypto" \
                    and attr_chain[-2] == "Cipher":
                if self._create_cipher_constructor_finding(
                        attr_chain[-3], method_name, node,
                        node.lineno, full_call):
                    return
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
                       line_no: int, call_str: str, node: ast.Call = None,
                       mode_override: Optional[str] = None):
        canonical_norm, original = normalize_algorithm(canonical)
        category = get_category(canonical_norm)
        
        # Extract key_size and mode from canonical algorithm name
        key_sizes = get_key_sizes(canonical_norm)
        key_size = key_sizes[0] if key_sizes else None
        # An explicitly resolved constructor mode (e.g. AES.MODE_ECB) wins
        # over the registry default; never invent one when absent.
        mode = mode_override or get_mode(canonical_norm)
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
        elif pattern.startswith("argon2."):
            lib = "argon2-cffi"
        elif pattern.startswith("passlib."):
            lib = "passlib"
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
