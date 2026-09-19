"""Phase 9: structured crypto-misuse rules (Person-1).

Stdlib-only, pure, deterministic. Rules are data (YAML-like dicts in
:data:`MISUSE_RULES`); :func:`check_operation` evaluates one CIR-style
operation dict against every rule and returns a list of findings.
No I/O, no network.
"""

from __future__ import annotations

__all__ = ["MISUSE_RULES", "check_operation", "check_rule"]

_FIPS_800_38A = "https://csrc.nist.gov/pubs/sp/800/38/a/final"
_FIPS_800_131A = "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"
_RFC_9325 = "https://www.rfc-editor.org/rfc/rfc9325.html"
_NIST_GUIDE = "https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc"


def _rule(rule_id, title, applies_to, requires, condition, severity_basis,
          description, references, severity):
    return {
        "id": rule_id,
        "title": title,
        "applies_to": dict(applies_to),
        "requires": dict(requires),
        "condition": condition,
        "severity_basis": severity_basis,
        "description": description,
        "references": list(references),
        "severity": severity,
    }


MISUSE_RULES: dict[str, dict] = {
    "STATIC_KEY": _rule(
        "STATIC_KEY", "Static / hardcoded cryptographic key",
        {"primitive": "any-symmetric-or-private", "operation": "any-use"},
        {"parameter": "key_material"},
        "key is a literal/embedded constant rather than provisioned",
        "hardcoded keys ship to every install; extraction breaks all deployments",
        "Key material is statically embedded (literal, constant, checked-in "
        "secret) instead of provisioned via KMS/keystore/env.",
        [_FIPS_800_131A, _NIST_GUIDE], "High"),
    "PREDICTABLE_KEY": _rule(
        "PREDICTABLE_KEY", "Predictable key source",
        {"primitive": "any", "operation": "key-generation"},
        {"parameter": "key_source"},
        "key derived from time/pid/username/counter/small-int without CSPRNG",
        "predictable keys are brute-forceable regardless of algorithm strength",
        "Key is derived from a predictable source (wall-clock, pid, user "
        "name, counter, small integer range) without a CSPRNG.",
        [_FIPS_800_131A], "High"),
    "STATIC_IV_NONCE": _rule(
        "STATIC_IV_NONCE", "Static / reused IV or nonce where unsafe",
        {"primitive": "AES/ChaCha20", "operation": "encrypt"},
        {"parameter": "iv/nonce"},
        "constant, zero, or reused nonce with CBC/CTR/GCM/ChaCha20-Poly1305",
        "nonce reuse destroys GCM/ChaCha confidentiality and CBC semantic security",
        "IV/nonce is constant, zero, hardcoded, or reused across messages "
        "for a mode that requires uniqueness (CBC/CTR/GCM/ChaCha20-Poly1305).",
        [_FIPS_800_38A], "High"),
    "ECB_MODE": _rule(
        "ECB_MODE", "ECB mode where semantically unsafe",
        {"primitive": "block-cipher", "operation": "encrypt"},
        {"parameter": "mode"},
        "mode == ECB for multi-block or structured plaintext",
        "ECB leaks plaintext structure deterministically",
        "Block cipher used in ECB mode, which leaks plaintext equality and "
        "structure. Use an AEAD (GCM / ChaCha20-Poly1305).",
        [_FIPS_800_38A], "High"),
    "WEAK_RNG": _rule(
        "WEAK_RNG", "Weak / insecure RNG for security material",
        {"primitive": "any", "operation": "key-generation/nonce/iv/salt"},
        {"parameter": "rng"},
        "non-cryptographic PRNG (LCG/Mersenne/rand/Math.random) for secrets",
        "predictable output enables key/nonce recovery",
        "Security material (key, nonce, IV, salt) drawn from a "
        "non-cryptographic PRNG such as rand()/random/Math.random.",
        [_FIPS_800_131A], "High"),
    "CERT_VALIDATION_DISABLED": _rule(
        "CERT_VALIDATION_DISABLED", "Certificate validation disabled / bypassed",
        {"primitive": "X.509/TLS", "operation": "verify/connect"},
        {"parameter": "trust_policy"},
        "verify=False / verify_mode=CERT_NONE / trust-all hostname bypass",
        "disabled validation re-enables MITM on an otherwise safe channel",
        "Certificate chain or hostname verification is disabled (verify "
        "disabled, CERT_NONE, trust-all callback, hostname check skipped).",
        [_RFC_9325], "High"),
    "INSUFFICIENT_KEY_SIZE": _rule(
        "INSUFFICIENT_KEY_SIZE", "Insufficient key size",
        {"primitive": "any", "operation": "any-use"},
        {"parameter": "key_size"},
        "RSA<2048 / ECC<224 / DH<2048 / symmetric<112-bit effective",
        "NIST SP 800-131A disallowed key lengths (classical floor)",
        "Key size below the NIST SP 800-131A floor (RSA/DSA/DH < 2048, "
        "EC < 224, symmetric effective strength < 112 bits).",
        [_FIPS_800_131A], "High"),
    "INSECURE_PROTOCOL": _rule(
        "INSECURE_PROTOCOL", "Insecure protocol version",
        {"primitive": "TLS/SSL", "operation": "negotiate"},
        {"parameter": "protocol_version"},
        "SSLv2/SSLv3/TLS 1.0/TLS 1.1 negotiated or configured",
        "broken handshake/cipher negotiation per RFC 9325",
        "Insecure protocol version (SSLv2/SSLv3/TLS 1.0/TLS 1.1) is "
        "negotiated, configured, or accepted.",
        [_RFC_9325], "High"),
    "DEPRECATED_ALGO": _rule(
        "DEPRECATED_ALGO", "Deprecated / broken algorithm",
        {"primitive": "hash/symmetric", "operation": "any-use"},
        {"parameter": "algorithm"},
        "MD5/SHA-1/DES/3DES/RC4/Blowfish/RIPEMD for security use",
        "collision / key-recovery attacks are practical (classical floor)",
        "Deprecated or broken primitive (MD5, SHA-1, DES, 3DES, RC4, "
        "Blowfish, RIPEMD) used for a security purpose.",
        [_FIPS_800_131A], "High"),
    "LOW_KDF_FACTOR": _rule(
        "LOW_KDF_FACTOR", "Low KDF work factor",
        {"primitive": "PBKDF2/bcrypt/scrypt/Argon2", "operation": "derive"},
        {"parameter": "iterations/cost/memory"},
        "PBKDF2<100k iters / bcrypt cost<10 / trivial scrypt/Argon2 params",
        "low cost enables offline password guessing",
        "Password KDF work factor below policy (PBKDF2 < 100k iterations, "
        "bcrypt cost < 10, or trivially small scrypt/Argon2 memory/time).",
        [_FIPS_800_131A], "Medium"),
    "MISSING_AUTH": _rule(
        "MISSING_AUTH", "Missing authentication (unauthenticated encryption)",
        {"primitive": "symmetric", "operation": "encrypt"},
        {"parameter": "auth_tag/mac"},
        "CBC/CTR/CFB/OFB/ECB without MAC or AEAD tag",
        "malleability / padding-oracle attacks without integrity",
        "Encryption without authentication (CBC/CTR/CFB/OFB with no MAC, "
        "or AEAD tag absent) where integrity is required.",
        [_FIPS_800_38A], "Medium"),
    "PASSWORD_AS_KEY": _rule(
        "PASSWORD_AS_KEY", "Password used directly as encryption key",
        {"primitive": "symmetric", "operation": "encrypt/decrypt"},
        {"parameter": "key_derivation"},
        "human password fed to cipher with no KDF",
        "low-entropy secret becomes the full key space",
        "A human password is used directly as cipher key material with no "
        "KDF (PBKDF2/scrypt/Argon2/HKDF) in between.",
        [_FIPS_800_131A], "High"),
    "UNSAFE_SIG_HASH": _rule(
        "UNSAFE_SIG_HASH", "Unsafe signature / hash combination",
        {"primitive": "signature", "operation": "sign/verify"},
        {"parameter": "hash"},
        "MD5/SHA-1 (or truncated-weak) hash inside signatures/certs",
        "collision attacks forge signatures on colliding prefixes",
        "Signature or certificate uses a collision-broken hash (MD5, "
        "SHA-1) as the message digest.",
        [_FIPS_800_131A], "High"),
}

# -- helpers ---------------------------------------------------------------

_WEAK_RNG_TOKENS = (
    "RAND()", "RANDOM()", "MATH.RANDOM", "MERSENNE", "MT19937", "LCG",
    "RAND-RANGE", "NP.RANDOM", "RANDOM.RANDOM",
)
_PREDICTABLE_KEY_TOKENS = (
    "TIME", "CLOCK", "PID", "GETPID", "USERNAME", "HOSTNAME", "COUNTER",
    "SEQUENCE", "SMALL", "TIMESTAMP", "DATETIME", "NOW()",
)
_STATIC_KEY_TOKENS = (
    "HARDCODED", "STATIC", "EMBEDDED", "LITERAL", "CONSTANT", "CHECKED-IN",
    "PRIVATE-KEY-PEM", "BEGINPRIVATEKEY", "BEGINRSA",
)


def _norm(text) -> str:
    return "".join(str(text or "").upper().split()).replace("_", "-").replace("/", "-")


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _first(mapping: dict, *keys, default=None):
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return default


def _params(op: dict) -> dict:
    out: dict = {}
    for container in (op, _as_dict(op.get("parameters")), _as_dict(op.get("context")),
                      _as_dict(op.get("implementation"))):
        if isinstance(container, dict):
            for key, value in container.items():
                if key not in out and value not in (None, ""):
                    out[key] = value
    return out


def _text_blob(op: dict) -> str:
    parts: list[str] = []
    params = _as_dict(op.get("parameters"))
    for key in ("variant", "hash", "rng", "random_source", "key_source",
                "key_material", "iv", "nonce", "protocol", "protocol_version",
                "mode", "operation", "operation_type", "notes"):
        for container in (op, params, _as_dict(op.get("context")),
                          _as_dict(op.get("implementation"))):
            value = container.get(key) if isinstance(container, dict) else None
            if value not in (None, ""):
                parts.append(str(value))
    for ent in (op.get("evidence", []) or []):
        if isinstance(ent, dict):
            parts.append(str(ent.get("detail", "")))
            parts.append(str(ent.get("snippet", "")))
            parts.append(str(ent.get("tool", "")))
    notes = str(_as_dict(op.get("context")).get("notes", "") or "")
    if notes:
        parts.append(notes)
    return _norm(" ".join(parts))


def _finding(rule_id: str, detail: str) -> dict:
    rule = MISUSE_RULES[rule_id]
    return {
        "rule_id": rule_id,
        "severity": rule["severity"],
        "title": rule["title"],
        "description": rule["description"],
        "detail": detail,
        "references": list(rule["references"]),
    }


def _check_static_key(op, params, blob) -> dict | None:
    if params.get("key_static") is True or params.get("key_hardcoded") is True:
        return _finding("STATIC_KEY", "key_static flag set")
    source = _norm(params.get("key_source", ""))
    if source in ("STATIC", "HARDCODED", "EMBEDDED", "LITERAL", "CONSTANT"):
        return _finding("STATIC_KEY", f"key_source={params.get('key_source')}")
    if any(t in blob for t in _STATIC_KEY_TOKENS) and (
            "KEY" in blob and ("AES" in blob or "HMAC" in blob or "PRIVATE" in blob)):
        # Token evidence only counts alongside key context (avoid doc noise).
        if params.get("key_value") or params.get("key_material") or "HARDCODED" in blob:
            return _finding("STATIC_KEY", "hardcoded key material evidence")
    if isinstance(params.get("key_value"), str) and len(params["key_value"]) >= 8:
        if params.get("key_provisioned") is False:
            return _finding("STATIC_KEY", "literal key_value without provisioning")
    return None


def _check_predictable_key(op, params, blob) -> dict | None:
    source = _norm(params.get("key_source", ""))
    if any(t in source for t in _PREDICTABLE_KEY_TOKENS):
        return _finding("PREDICTABLE_KEY", f"key_source={params.get('key_source')}")
    if params.get("key_from_time") is True or params.get("key_from_pid") is True:
        return _finding("PREDICTABLE_KEY", "key derived from time/pid flag")
    return None


def _check_static_iv(op, params, blob) -> dict | None:
    if params.get("iv_static") is True or params.get("nonce_static") is True:
        return _finding("STATIC_IV_NONCE", "static iv/nonce flag set")
    if params.get("iv_reuse") is True or params.get("nonce_reuse") is True:
        return _finding("STATIC_IV_NONCE", "iv/nonce reuse flag set")
    mode = _norm(params.get("mode", "") or op.get("mode", ""))
    needs_nonce = any(m in mode for m in ("CBC", "CTR", "GCM", "CHACHA", "CCM", "EAX", "OCB"))
    canon = _norm(_first(op, "canonical_name", "canonical", "algorithm", default=""))
    if not needs_nonce and "AES" not in canon and "CHACHA" not in canon:
        return None
    iv_val = params.get("iv", params.get("nonce", None))
    if isinstance(iv_val, str) and iv_val.strip().lower() in (
            "0", "00", "0000000000000000", "zero", "constant", "static"):
        return _finding("STATIC_IV_NONCE", f"iv/nonce value={iv_val!r}")
    if "NONCEREUSE" in blob or "IVREUSE" in blob:
        return _finding("STATIC_IV_NONCE", "reuse evidence in blob")
    if ("ZEROIV" in blob or "ZERONONCE" in blob or "STATICIV" in blob
            or "STATICNONCE" in blob or "CONSTANTIV" in blob
            or "HARDCODEDIV" in blob):
        return _finding("STATIC_IV_NONCE", "static iv/nonce evidence")
    return None


def _check_ecb(op, params, blob) -> dict | None:
    mode = _norm(params.get("mode", "") or op.get("mode", ""))
    canon = _norm(_first(op, "canonical_name", "canonical", "algorithm", default=""))
    if "ECB" in mode or "ECB" in canon:
        return _finding("ECB_MODE", f"mode={params.get('mode', op.get('mode'))}")
    return None


def _check_weak_rng(op, params, blob) -> dict | None:
    rng = _norm(params.get("rng", params.get("random_source", "")))
    if rng and any(t in rng for t in _WEAK_RNG_TOKENS):
        return _finding("WEAK_RNG", f"rng={params.get('rng', params.get('random_source'))}")
    if params.get("weak_rng") is True or params.get("insecure_rng") is True:
        return _finding("WEAK_RNG", "weak_rng flag set")
    return None


def _check_cert_validation(op, params, blob) -> dict | None:
    for key in ("verify", "cert_validation", "tls_verify", "verify_mode",
                "check_hostname", "validate_certs"):
        value = params.get(key, None)
        if value is False or _norm(value) in ("NONE", "DISABLED", "CERT-NONE",
                                              "CERTNONE", "FALSE", "0", "NO"):
            return _finding("CERT_VALIDATION_DISABLED", f"{key}={value!r}")
    if "CERT-NONE" in blob or "VERIFY=FALSE" in blob or "VERIFYMODE=CERT-NONE" in blob:
        return _finding("CERT_VALIDATION_DISABLED", "disabled verification evidence")
    if "TRUST-ALL" in blob or "TRUSTALL" in blob or "INSECURETRUST" in blob:
        return _finding("CERT_VALIDATION_DISABLED", "trust-all evidence")
    if "HOSTNAME-BYPASS" in blob or "SKIP-HOSTNAME" in blob:
        return _finding("CERT_VALIDATION_DISABLED", "hostname bypass evidence")
    return None


def _key_size_of(op, params):
    for key in ("key_size", "keySize", "bits", "key_bits"):
        value = params.get(key, op.get(key, None))
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _check_key_size(op, params, blob) -> dict | None:
    canon = _norm(_first(op, "canonical_name", "canonical", "algorithm", default=""))
    size = _key_size_of(op, params)
    if size is None:
        return None
    if any(k in canon for k in ("RSA", "DSA")) and size < 2048 and "ML-DSA" not in canon and "SLH-DSA" not in canon:
        return _finding("INSUFFICIENT_KEY_SIZE", f"{canon or 'key'} size={size}")
    if ("DIFFIE" in canon or canon in ("DH", "FFDHE")) and size < 2048:
        return _finding("INSUFFICIENT_KEY_SIZE", f"DH size={size}")
    if any(k in canon for k in ("ECDSA", "ECDH", "X25519", "X448", "ED25519", "ED448", "EC")):
        # Curve-bit check: explicit small sizes only (names handled by posture).
        if size and size < 224:
            return _finding("INSUFFICIENT_KEY_SIZE", f"EC size={size}")
        return None
    if "AES" in canon and size < 128:
        return _finding("INSUFFICIENT_KEY_SIZE", f"AES size={size}")
    if "HMAC" in canon and size < 112:
        return _finding("INSUFFICIENT_KEY_SIZE", f"HMAC key size={size}")
    return None


def _check_protocol(op, params, blob) -> dict | None:
    proto = _norm(params.get("protocol_version",
                             params.get("protocol", op.get("protocol_version", op.get("protocol", "")))))
    if any(t in proto for t in ("SSLV2", "SSLV3", "TLS1.0", "TLS1.1",
                                "TLSV1", "TLSV1.0", "TLSV1.1")):
        # TLS1.2/1.3 contain "TLSV1" as substring guard: exact-prefix check.
        if "TLS1.2" in proto or "TLS1.3" in proto or "TLSV1.2" in proto or "TLSV1.3" in proto:
            return None
        return _finding("INSECURE_PROTOCOL", f"protocol={params.get('protocol_version', params.get('protocol'))}")
    if "SSLV2" in blob or "SSLV3" in blob:
        return _finding("INSECURE_PROTOCOL", "SSL evidence")
    return None


def _check_deprecated(op, params, blob) -> dict | None:
    canon = _norm(_first(op, "canonical_name", "canonical", "algorithm", default=""))
    mode = _norm(params.get("mode", "") or op.get("mode", ""))
    text = canon + "|" + mode
    # 3DES before DES (substring overlap).
    if any(k in text for k in ("3DES", "DESEDE", "TRIPLEDES", "TDEA")):
        return _finding("DEPRECATED_ALGO", "3DES use")
    if "DES" in text and "DESCRIBE" not in text and "ML-DSA" not in text and "AES" not in text:
        # Avoid flagging "description" blobs: require canonical-level DES.
        if "DES" in canon:
            return _finding("DEPRECATED_ALGO", f"DES use ({canon})")
    if "RC4" in text or "ARC4" in text:
        return _finding("DEPRECATED_ALGO", "RC4 use")
    if "BLOWFISH" in text:
        return _finding("DEPRECATED_ALGO", "Blowfish use")
    if "MD5" in text:
        return _finding("DEPRECATED_ALGO", "MD5 use")
    if "SHA1" in text or "SHA-1" in text:
        return _finding("DEPRECATED_ALGO", "SHA-1 use")
    if "RIPEMD" in text:
        return _finding("DEPRECATED_ALGO", "RIPEMD use")
    return None


def _check_kdf(op, params, blob) -> dict | None:
    canon = _norm(_first(op, "canonical_name", "canonical", "algorithm", default=""))
    if "PBKDF2" not in canon and "PBKDF" not in blob:
        # bcrypt / scrypt / argon2 explicit params.
        cost = params.get("cost", params.get("rounds", params.get("cost_factor")))
        try:
            if "BCRYPT" in canon and cost is not None and int(cost) < 10:
                return _finding("LOW_KDF_FACTOR", f"bcrypt cost={cost}")
        except (TypeError, ValueError):
            pass
        mem = params.get("memory_kb", params.get("memory", params.get("m")))
        try:
            if "ARGON2" in canon and mem is not None and int(mem) < 8192:
                return _finding("LOW_KDF_FACTOR", f"argon2 memory={mem}")
        except (TypeError, ValueError):
            pass
        return None
    iters = params.get("iterations", params.get("iteration_count", params.get("rounds")))
    try:
        if iters is not None and int(iters) < 100_000:
            return _finding("LOW_KDF_FACTOR", f"PBKDF2 iterations={iters}")
    except (TypeError, ValueError):
        pass
    if params.get("salt_static") is True or params.get("salt_reuse") is True:
        return _finding("LOW_KDF_FACTOR", "static/reused salt")
    if "NOSALT" in blob or "STATICSALT" in blob:
        return _finding("LOW_KDF_FACTOR", "salt evidence")
    return None


def _check_missing_auth(op, params, blob) -> dict | None:
    operation = _norm(params.get("operation", params.get("operation_type", op.get("operation_type", op.get("operation", "")))))
    mode = _norm(params.get("mode", "") or op.get("mode", ""))
    canon = _norm(_first(op, "canonical_name", "canonical", "algorithm", default=""))
    if not any(m in mode for m in ("CBC", "CTR", "CFB", "OFB")):
        return None
    if any(m in mode for m in ("GCM", "POLY1305", "CCM", "EAX", "OCB")):
        return None
    if params.get("has_mac") is True or params.get("authenticated") is True:
        return None
    if "ENCRYPT" not in operation and "AES" not in canon and "CHACHA" not in canon:
        return None
    if params.get("mac") or params.get("auth_tag") or params.get("tag"):
        return None
    return _finding("MISSING_AUTH", f"mode={mode or '?'} without MAC/AEAD")


def _check_password_as_key(op, params, blob) -> dict | None:
    if params.get("password_as_key") is True:
        return _finding("PASSWORD_AS_KEY", "password_as_key flag set")
    source = _norm(params.get("key_source", ""))
    kdf = _norm(params.get("kdf", params.get("key_derivation", "")))
    if "PASSWORD" in source and (not kdf or kdf in ("NONE", "RAW", "DIRECT")):
        if params.get("kdf") in (None, "", "none", "raw", "direct"):
            return _finding("PASSWORD_AS_KEY", f"key_source={params.get('key_source')}")
    return None


def _check_unsafe_sig_hash(op, params, blob) -> dict | None:
    operation = _norm(params.get("operation", params.get("operation_type",
                     op.get("operation_type", op.get("operation", "")))))
    is_sig = any(k in operation for k in ("SIGN", "VERIFY", "CERT", "CERTIFICATE"))
    canon = _norm(_first(op, "canonical_name", "canonical", "algorithm", default=""))
    if "X.509" in canon or "CERT" in canon:
        is_sig = True
    if not is_sig:
        return None
    digest = _norm(params.get("hash", params.get("digest", params.get("variant", ""))))
    text = digest + "|" + blob
    if "MD5" in text and ("SIGN" in operation or is_sig):
        # Require digest-level signal, not incidental blob mention.
        if "MD5" in digest or "MD5WITH" in blob or "MD5-WITH" in blob:
            return _finding("UNSAFE_SIG_HASH", "MD5-based signature")
    if ("SHA1" in text or "SHA-1" in text) and is_sig:
        if "SHA1" in digest or "SHA-1" in digest or "SHA1WITH" in blob or "ECDSA-SHA1" in blob:
            return _finding("UNSAFE_SIG_HASH", "SHA-1-based signature")
    return None


_CHECKERS = (
    ("STATIC_KEY", _check_static_key),
    ("PREDICTABLE_KEY", _check_predictable_key),
    ("STATIC_IV_NONCE", _check_static_iv),
    ("ECB_MODE", _check_ecb),
    ("WEAK_RNG", _check_weak_rng),
    ("CERT_VALIDATION_DISABLED", _check_cert_validation),
    ("INSUFFICIENT_KEY_SIZE", _check_key_size),
    ("INSECURE_PROTOCOL", _check_protocol),
    ("DEPRECATED_ALGO", _check_deprecated),
    ("LOW_KDF_FACTOR", _check_kdf),
    ("MISSING_AUTH", _check_missing_auth),
    ("PASSWORD_AS_KEY", _check_password_as_key),
    ("UNSAFE_SIG_HASH", _check_unsafe_sig_hash),
)


def check_rule(rule_id: str, operation: dict) -> dict | None:
    """Evaluate one rule against one operation dict. Pure."""
    if not isinstance(operation, dict):
        raise TypeError("check_rule expects an operation dict")
    for rid, checker in _CHECKERS:
        if rid == rule_id:
            return checker(operation, _params(operation), _text_blob(operation))
    raise KeyError(f"unknown misuse rule: {rule_id!r}")


def check_operation(operation: dict) -> list[dict]:
    """Evaluate all misuse rules against one operation dict.

    Returns a list of finding dicts
    ``{rule_id, severity, title, description, detail, references}``,
    deterministically ordered by rule id. Pure; ``[]`` means no misuse
    detected (not "secure" — absence of evidence only).
    """
    if not isinstance(operation, dict):
        raise TypeError("check_operation expects an operation dict")
    params = _params(operation)
    blob = _text_blob(operation)
    findings: list[dict] = []
    for _rid, checker in _CHECKERS:
        try:
            hit = checker(operation, params, blob)
        except Exception:
            continue
        if hit is not None:
            findings.append(hit)
    findings.sort(key=lambda f: f["rule_id"])
    return findings
