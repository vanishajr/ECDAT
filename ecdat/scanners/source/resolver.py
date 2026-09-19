"""Phase 3: bounded demand-driven resolver over Phase 2 facts.

Only resolves what a caller asks for, at most ``max_depth`` hops (default
3), with cycle detection, confidence decay per hop, and provenance chains.
Anything that cannot be grounded in a literal fact returns ``None``
(unresolved) rather than a guess. Module-level :data:`_STATS` records
aggregate outcomes for traceability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ecdat.scanners.source.facts import SourceFact

__all__ = [
    "MAX_DEPTH",
    "CONFIDENCE_DECAY",
    "ResolvedValue",
    "WrapperExpansion",
    "DemandResolver",
    "resolve_value",
    "resolve_algorithm",
    "resolve_curve",
    "resolve_key_size",
    "resolve_mode",
    "resolve_provider",
    "expand_wrapper",
    "get_stats",
    "reset_stats",
]

MAX_DEPTH = 3
CONFIDENCE_DECAY = 0.85

_INT_RE = re.compile(r"^-?\d+$")
_IDENT_RE = re.compile(r"^[A-Za-z_]\w*$")
_QUOTED_RE = re.compile(r"""^['"](.*)['"]$""", re.DOTALL)
_CURVE_RE = re.compile(r"(P-?256|P-?384|P-?521|prime256v1|secp256r1|"
                       r"secp384r1|secp521r1|nistP256|nistP384|nistP521|"
                       r"X25519|X448|Ed25519|Curve25519|secp256k1)",
                       re.IGNORECASE)
_MODE_RE = re.compile(r"\b(GCM|CBC|CTR|CCM|ECB|OFB|XTS|OCB3|POLY1305)\b",
                      re.IGNORECASE)
_KEYSIZE_RE = re.compile(r"\b(1024|2048|3072|4096|128|192|256)\b")

_ALGO_TOKENS = (
    "AES", "RSA", "ECDSA", "ECDH", "DES", "3DES", "CHACHA", "HMAC", "SHA",
    "MD5", "TLS", "SSL", "HKDF", "PBKDF2", "SCRYPT", "BCRYPT", "ARGON2",
    "KYBER", "DILITHIUM", "ED25519", "X25519", "BLOWFISH", "CAMELLIA",
)

_PROVIDER_BY_PREFIX = (
    ("EVP_", "openssl"), ("RSA_", "openssl"), ("EC_", "openssl"),
    ("ECDH_", "openssl"), ("DH_", "openssl"), ("DSA_", "openssl"),
    ("HMAC", "openssl"), ("RAND_", "openssl"), ("PKCS5_", "openssl"),
    ("SSL_", "openssl"), ("TLS_", "openssl"), ("AES_", "openssl"),
    ("SHA", "openssl"), ("MD5", "openssl"), ("DES_", "openssl"),
    ("crypto_aead_", "libsodium"), ("crypto_box_", "libsodium"),
    ("crypto_secretbox_", "libsodium"), ("crypto_sign", "libsodium"),
    ("crypto_kx_", "libsodium"), ("crypto_pwhash", "libsodium"),
    ("crypto_generichash", "libsodium"), ("randombytes_", "libsodium"),
    ("Cipher.getInstance", "jca"), ("MessageDigest.getInstance", "jca"),
    ("Mac.getInstance", "jca"), ("KeyAgreement.getInstance", "jca"),
    ("KeyPairGenerator.getInstance", "jca"),
    ("Signature.getInstance", "jca"),
    ("SecretKeyFactory.getInstance", "jca"),
    ("SSLContext.getInstance", "jca"),
    ("createCipheriv", "node-crypto"), ("createHash", "node-crypto"),
    ("createHmac", "node-crypto"), ("generateKeyPair", "node-crypto"),
    ("createECDH", "node-crypto"), ("pbkdf2", "node-crypto"),
    ("scrypt", "node-crypto"), ("subtle.", "webcrypto"),
    ("aes.NewCipher", "go-crypto"), ("cipher.NewGCM", "go-crypto"),
    ("rsa.GenerateKey", "go-crypto"), ("ecdsa.GenerateKey", "go-crypto"),
    ("ecdh.", "go-crypto"), ("ed25519.", "go-crypto"),
    ("sha256.", "go-crypto"), ("sha512.", "go-crypto"),
    ("hmac.New", "go-crypto"), ("tls.", "go-crypto"),
    ("Aes.Create", "dotnet"), ("RSA.Create", "dotnet"),
    ("ECDsa.Create", "dotnet"), ("ECDiffieHellman.Create", "dotnet"),
    ("SHA256.Create", "dotnet"), ("Rfc2898DeriveBytes", "dotnet"),
    ("Aes256Gcm", "rustcrypto"), ("Aes128Gcm", "rustcrypto"),
    ("ChaCha20Poly1305", "rustcrypto"), ("RsaPrivateKey", "rustcrypto"),
    ("SigningKey", "ed25519-dalek"), ("SecretKey::random", "p256"),
    ("Sha256", "sha2"), ("Hkdf", "hkdf"), ("Argon2", "argon2"),
    ("StaticSecret", "x25519-dalek"),
    ("hashlib.", "hashlib"), ("hmac.", "hmac"),
    ("cryptography.", "cryptography"), ("Crypto.", "pycryptodome"),
)

_STATS: dict[str, int] = {
    "resolutions": 0,
    "unresolved": 0,
    "wrappers_expanded": 0,
    "cycles_cut": 0,
    "max_depth_hit": 0,
}


def get_stats() -> dict[str, int]:
    """Copy of the module-level resolver counters."""
    return dict(_STATS)


def reset_stats() -> None:
    """Zero all module-level resolver counters (tests)."""
    for key in _STATS:
        _STATS[key] = 0


def _bump(key: str) -> None:
    _STATS[key] = _STATS.get(key, 0) + 1


@dataclass
class ResolvedValue:
    """A grounded resolution: literal value + how we got there."""

    value: object
    confidence: float = 1.0
    provenance: list[str] = field(default_factory=list)
    hops: int = 0


@dataclass
class WrapperExpansion:
    """Wrapper -> underlying crypto call mapping."""

    wrapper: str
    target: str
    confidence: float = 1.0
    provenance: list[str] = field(default_factory=list)
    hops: int = 0


def _strip_quotes(token: str) -> tuple[str, bool]:
    match = _QUOTED_RE.match(token.strip())
    if match:
        return match.group(1), True
    return token.strip(), False


def _assignment_index(facts: list[SourceFact]) -> dict[str, list[SourceFact]]:
    index: dict[str, list[SourceFact]] = {}
    for fact in facts:
        if fact.kind in ("assignment", "constant", "macro") and fact.name:
            index.setdefault(fact.name, []).append(fact)
    return index


def resolve_value(name: str | object, facts: list[SourceFact],
                  depth: int = 0, max_depth: int = MAX_DEPTH,
                  _seen: set[str] | None = None,
                  function: str | None = None) -> ResolvedValue | None:
    """Resolve ``name`` to a literal through facts (bounded, no guessing).

    ``name`` may itself be a quoted string / int literal (returned as-is
    with provenance ``["literal"]``), an identifier grounded by
    assignment/constant/macro facts, or an alias chain
    (``a = b; b = "AES"``). Anything else -> ``None``.
    """
    if isinstance(name, (int, float, bool)):
        _bump("resolutions")
        return ResolvedValue(value=name, confidence=1.0,
                             provenance=["literal"], hops=depth)
    token = str(name or "").strip()
    if not token:
        _bump("unresolved")
        return None
    if depth > max_depth:
        _bump("max_depth_hit")
        _bump("unresolved")
        return None
    seen = _seen if _seen is not None else set()
    if token in seen:
        _bump("cycles_cut")
        _bump("unresolved")
        return None

    unquoted, was_quoted = _strip_quotes(token)
    if was_quoted:
        _bump("resolutions")
        return ResolvedValue(value=unquoted, confidence=1.0,
                             provenance=["literal"], hops=depth)
    if _INT_RE.match(token):
        _bump("resolutions")
        return ResolvedValue(value=int(token), confidence=1.0,
                             provenance=["literal"], hops=depth)
    if not _IDENT_RE.match(token):
        # Complex expressions (calls, arithmetic, f-strings) are NOT resolved.
        _bump("unresolved")
        return None

    candidates = [f for f in _assignment_index(facts).get(token, [])]
    if function is not None:
        scoped = [f for f in candidates if f.function == function]
        unscoped = [f for f in candidates if not f.function]
        ordered = scoped + unscoped + [f for f in candidates
                                       if f not in scoped + unscoped]
    else:
        ordered = candidates
    if not ordered:
        _bump("unresolved")
        return None
    seen = seen | {token}
    for fact in ordered:
        raw = fact.value
        if isinstance(raw, (int, float, bool)):
            _bump("resolutions")
            return ResolvedValue(
                value=raw, confidence=round(CONFIDENCE_DECAY ** depth, 3),
                provenance=[f"{fact.kind}:{token}@{fact.line}"] if fact.line
                else [f"{fact.kind}:{token}"], hops=depth)
        text = str(raw or "").strip().strip(";")
        if not text:
            continue
        inner, quoted = _strip_quotes(text)
        if quoted:
            _bump("resolutions")
            return ResolvedValue(
                value=inner,
                confidence=round(CONFIDENCE_DECAY ** depth, 3),
                provenance=[f"{fact.kind}:{token}@{fact.line}"] if fact.line
                else [f"{fact.kind}:{token}"], hops=depth)
        if _INT_RE.match(text):
            _bump("resolutions")
            return ResolvedValue(
                value=int(text),
                confidence=round(CONFIDENCE_DECAY ** depth, 3),
                provenance=[f"{fact.kind}:{token}"], hops=depth)
        if _IDENT_RE.match(text) and text != token:
            if depth >= max_depth:
                _bump("max_depth_hit")
                continue
            sub = resolve_value(text, facts, depth + 1, max_depth, seen,
                                function=function)
            if sub is not None:
                _bump("resolutions")
                return ResolvedValue(
                    value=sub.value,
                    confidence=round(sub.confidence * CONFIDENCE_DECAY, 3),
                    provenance=[f"{fact.kind}:{token}"] + sub.provenance,
                    hops=sub.hops)
    _bump("unresolved")
    return None


def _call_args(call: SourceFact) -> list[str]:
    return [str(a or "") for a in (call.arguments or ())]


def _first_resolvable(args: list[str], facts: list[SourceFact],
                      function: str | None,
                      predicate=None) -> ResolvedValue | None:
    for arg in args:
        text = str(arg or "").strip()
        if not text:
            continue
        direct, quoted = _strip_quotes(text)
        check = direct if quoted else text
        if predicate is not None and quoted and predicate(check):
            _bump("resolutions")
            return ResolvedValue(value=check, confidence=1.0,
                                 provenance=["literal-arg"], hops=0)
        if predicate is None and quoted:
            _bump("resolutions")
            return ResolvedValue(value=direct, confidence=1.0,
                                 provenance=["literal-arg"], hops=0)
        if _IDENT_RE.match(text):
            sub = resolve_value(text, facts, 0, MAX_DEPTH, None,
                                function=function)
            if sub is not None and (
                    predicate is None or predicate(str(sub.value))):
                return sub
        elif quoted:
            continue
        else:
            match = (_KEYSIZE_RE.search(text) if predicate is None
                     else None)
            if match and predicate is None:
                _bump("resolutions")
                return ResolvedValue(value=int(match.group(1)),
                                     confidence=0.9,
                                     provenance=["embedded-literal"], hops=0)
    _bump("unresolved")
    return None


def _looks_like_algo(text: str) -> bool:
    upper = str(text or "").upper().replace("-", "").replace("_", "")
    return any(tok.replace("-", "") in upper for tok in _ALGO_TOKENS)


def resolve_algorithm(call: SourceFact, facts: list[SourceFact]) -> ResolvedValue | None:
    """Resolve the algorithm for one call fact (literal args only)."""
    if call.kind != "function_call":
        return None
    hit = _first_resolvable(_call_args(call), facts, call.function,
                            predicate=_looks_like_algo)
    if hit is not None:
        return hit
    _bump("unresolved")
    return None


def resolve_curve(call: SourceFact, facts: list[SourceFact]) -> ResolvedValue | None:
    """Resolve the curve for one call fact (None when absent/unknown)."""
    if call.kind != "function_call":
        return None
    for arg in _call_args(call):
        text = str(arg or "").strip()
        direct, quoted = _strip_quotes(text)
        candidate = direct if quoted else None
        if candidate is None and _IDENT_RE.match(text):
            sub = resolve_value(text, facts, 0, MAX_DEPTH, None,
                                function=call.function)
            candidate = str(sub.value) if sub is not None else None
            if sub is not None and _CURVE_RE.search(candidate or ""):
                return sub
        if candidate and _CURVE_RE.search(candidate):
            _bump("resolutions")
            return ResolvedValue(value=candidate, confidence=1.0,
                                 provenance=["literal-arg"], hops=0)
    _bump("unresolved")
    return None


def resolve_key_size(call: SourceFact, facts: list[SourceFact]) -> ResolvedValue | None:
    """Resolve the key size in bits (None when absent/unknown)."""
    if call.kind != "function_call":
        return None
    for arg in _call_args(call):
        text = str(arg or "").strip()
        direct, quoted = _strip_quotes(text)
        if quoted and _INT_RE.match(direct) and int(direct) in (
                1024, 2048, 3072, 4096, 128, 192, 256):
            _bump("resolutions")
            return ResolvedValue(value=int(direct), confidence=1.0,
                                 provenance=["literal-arg"], hops=0)
        if _IDENT_RE.match(text):
            sub = resolve_value(text, facts, 0, MAX_DEPTH, None,
                                function=call.function)
            if isinstance(getattr(sub, "value", None), int):
                return sub
            if sub is not None and _INT_RE.match(str(sub.value)):
                return sub
        elif not quoted:
            match = _KEYSIZE_RE.search(text)
            if match:
                continue  # bare numbers inside complex exprs: no guess
    _bump("unresolved")
    return None


def resolve_mode(call: SourceFact, facts: list[SourceFact]) -> ResolvedValue | None:
    """Resolve the cipher mode (None when absent/unknown)."""
    if call.kind != "function_call":
        return None
    for arg in _call_args(call):
        text = str(arg or "").strip()
        direct, quoted = _strip_quotes(text)
        candidate = direct if quoted else None
        if candidate is None and _IDENT_RE.match(text):
            sub = resolve_value(text, facts, 0, MAX_DEPTH, None,
                                function=call.function)
            candidate = str(sub.value) if sub is not None else None
            if sub is not None and _MODE_RE.search(candidate or ""):
                match = _MODE_RE.search(candidate or "")
                return ResolvedValue(
                    value=match.group(1).upper() if match else candidate,
                    confidence=sub.confidence,
                    provenance=sub.provenance, hops=sub.hops)
        if candidate:
            match = _MODE_RE.search(candidate)
            if match:
                _bump("resolutions")
                return ResolvedValue(value=match.group(1).upper(),
                                     confidence=1.0,
                                     provenance=["literal-arg"], hops=0)
    _bump("unresolved")
    return None


def resolve_provider(call: SourceFact, facts: list[SourceFact] | None = None) -> ResolvedValue | None:
    """Resolve the provider/library from the callee name (no guessing)."""
    _ = facts  # name-based only; facts reserved for future import Use.
    name = str(call.name or "")
    for prefix, provider in _PROVIDER_BY_PREFIX:
        if name == prefix or name.startswith(prefix) or name.endswith(prefix) \
                or prefix in name:
            _bump("resolutions")
            return ResolvedValue(value=provider, confidence=0.9,
                                 provenance=[f"callee:{name}"], hops=0)
    _bump("unresolved")
    return None


def expand_wrapper(name: str, facts: list[SourceFact],
                   max_depth: int = MAX_DEPTH,
                   _visited: tuple[str, ...] = ()) -> WrapperExpansion | None:
    """Expand a local wrapper to its underlying crypto call (bounded).

    Follows wrapper-to-wrapper chains up to ``max_depth`` with cycle
    detection; confidence decays per hop. Returns ``None`` on cycles,
    depth exhaustion, or when no callee is visible.
    """
    if name in _visited:
        _bump("cycles_cut")
        return None
    if len(_visited) >= max_depth:
        _bump("max_depth_hit")
        return None
    defs = {f.name for f in facts if f.kind == "function_definition"}
    if name not in defs:
        _bump("unresolved")
        return None
    visited = _visited + (name,)
    inner_calls = [f for f in facts
                   if f.kind == "function_call" and f.function == name]
    if not inner_calls:
        _bump("unresolved")
        return None
    for call in inner_calls:
        callee = str(call.name or "")
        base = callee.split(".")[-1].split(":")[-1]
        if base in defs and base != name:
            if base in visited:
                _bump("cycles_cut")
                continue
            sub = expand_wrapper(base, facts, max_depth, visited)
            if sub is not None:
                _bump("wrappers_expanded")
                return WrapperExpansion(
                    wrapper=name, target=sub.target,
                    confidence=round(sub.confidence * CONFIDENCE_DECAY, 3),
                    provenance=[name] + sub.provenance,
                    hops=sub.hops + 1)
            continue
        _bump("wrappers_expanded")
        return WrapperExpansion(
            wrapper=name, target=callee,
            confidence=round(CONFIDENCE_DECAY ** len(_visited), 3),
            provenance=list(visited) + [callee], hops=len(visited))
    _bump("unresolved")
    return None


class DemandResolver:
    """Stateful facade over the module functions with per-instance stats."""

    def __init__(self, facts: list[SourceFact] | None = None,
                 max_depth: int = MAX_DEPTH) -> None:
        self.facts: list[SourceFact] = list(facts or [])
        self.max_depth = max_depth
        self.stats: dict[str, int] = {
            "resolutions": 0, "unresolved": 0, "wrappers_expanded": 0,
            "cycles_cut": 0, "max_depth_hit": 0,
        }

    def _sync(self, before: dict[str, int]) -> None:
        after = get_stats()
        for key in self.stats:
            self.stats[key] += after.get(key, 0) - before.get(key, 0)

    def resolve_value(self, name: str | object,
                      function: str | None = None) -> ResolvedValue | None:
        """Resolve ``name`` against this resolver's facts."""
        before = get_stats()
        try:
            return resolve_value(name, self.facts, 0, self.max_depth, None,
                                 function=function)
        finally:
            self._sync(before)

    def resolve_call(self, call: SourceFact) -> dict[str, ResolvedValue | None]:
        """Resolve algorithm/curve/key_size/mode/provider for one call."""
        before = get_stats()
        try:
            return {
                "algorithm": resolve_algorithm(call, self.facts),
                "curve": resolve_curve(call, self.facts),
                "key_size": resolve_key_size(call, self.facts),
                "mode": resolve_mode(call, self.facts),
                "provider": resolve_provider(call, self.facts),
            }
        finally:
            self._sync(before)

    def expand_wrapper(self, name: str) -> WrapperExpansion | None:
        """Expand ``name`` through this resolver's facts."""
        before = get_stats()
        try:
            return expand_wrapper(name, self.facts, self.max_depth, ())
        finally:
            self._sync(before)
