"""Structural crypto-implementation fingerprints for source (Phase 5).

Detects cryptographic *implementations* that never call a known external
crypto API (e.g. tiny-AES-c, B-Con/crypto-algorithms): static algorithm
tables, round constants, and identifier clusters in masked source
(comments/strings already blanked, so test vectors in comments never fire).

Signal model (plan §9):
  one weak signal              -> candidate only (no finding)
  two independent weak signals -> probable implementation (0.65)
  strong constant + structure  -> high-confidence implementation (0.90)
  multiple strong signals      -> confirmed implementation (0.95)

Thresholds are explicit and benchmark-derived where fixtures exist.
Findings are *implementation* evidence (dependency_only / ProvidedOnly):
they inventory what the file PROVIDES, never an invocation.
Cross-file invocations of repo-defined crypto functions are resolved by
``SourceScanner`` via :func:`defined_functions`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "FINGERPRINT_FAMILIES",
    "FingerprintHit",
    "analyze_file",
    "defined_functions",
    "definition_qualifiers",
    "def_name_matches_family",
    "op_hint_for_name",
    "function_semantics",
    "canonical_for_semantics",
    "corroborate_definition",
    "EXCLUDED_IDENTIFIERS",
]

#: Identifiers that look crypto-ish but are encodings, not cryptography.
EXCLUDED_IDENTIFIERS = ("base64", "rot13", "rot47", "uuencode", "hexencode")

_AES_SBOX_PREFIX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
]
_AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
_SHA256_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
]
_SHA512_IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]
_MD_ABCD = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
_MD5_EXTRA = [0xD76AA478, 0xE8C7B756]
_SHA1_EXTRA = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
_CHACHA_SIGMA = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
_BLOWFISH_PI = [0x243F6A88, 0x85A308D3]

_HEX_RE = re.compile(r"0[xX]([0-9a-fA-F]+)")
_INT_RE = re.compile(r"(?<![\w.])(-?\d+)(?![\w])")
_BRACE_BLOCK_RE = re.compile(r"\{([^{}]*)\}")
_FUNC_DEF_RE = re.compile(
    r"^\s*(?:[\w:\<\>\*]+\s+)+[\*\&]?\s*"
    r"(?:([A-Za-z_]\w*)::)?([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:\{|$)",
    re.MULTILINE,
)
_KEYWORD_DEF_RE = re.compile(r"\b(?:if|for|while|switch|catch|return|sizeof)\b")


@dataclass
class FingerprintHit:
    canonical: str
    operation: str
    signals: list[str] = field(default_factory=list)
    confidence: float = 0.0
    detail: str = ""


def _family_identifiers(canonical: str, masked: str) -> list[str]:
    """Distinct crypto identifier families matched (token regexes)."""
    patterns: dict[str, list[str]] = {
        "AES": [r"\bAES(_ECB|_CBC|_CTR|_GCM|_init|_128|_192|_256)?\b",
                r"\baes(_encrypt|_decrypt|_init|_set|_ecb|_cbc|_ctr)?\b",
                r"\b(sbox|rsbox|rcon|Rcon|MixColumn|InvMixColumn|ShiftRow|xtime)\b"],
        "DES": [r"\bDES(_ede|_ecb|_cbc|_key|_crypt)?\b",
                r"\b(des_|Des_|DESEDE|TripleDES|tripledes)\w*\b"],
        "3DES": [r"\b(DES_ede|DESEDE|TripleDES|tripledes|des_ede)\w*\b",
                 r"\b(three_des|triple_des|THREE_DES|TRIPLE_DES)\w*\b",
                 r"\b(desede|des_ede|desede\d*|des3|tdea)\w*\b"],
        "RC4": [r"\b(RC4|rc4|ARCFOUR|arcfour)(_set_key|_crypt)?\b"],
        "Blowfish": [r"\b(blowfish|Blowfish|BLOWFISH)\w*\b"],
        "ChaCha20": [r"\b(chacha|ChaCha|CHACHA)(20)?\b"],
        "Poly1305": [r"\b(poly1305|Poly1305|POLY1305)\b", r"\bclamp\b"],
        "MD5": [r"\b(md5|MD5)(_init|_update|_final|_transform)?\b"],
        "SHA-1": [r"\b(sha1|SHA1)(_init|_update|_final|_transform)?\b"],
        "SHA-256": [r"\b(sha256|SHA256)(_init|_update|_final|_transform)?\b"],
        "SHA-512": [r"\b(sha512|SHA512)(_init|_update|_final|_transform)?\b"],
        "HMAC": [r"\b(hmac|HMAC)(_init|_update|_final)?\b"],
        "PBKDF2": [r"\b(pbkdf2|PBKDF2)\b"],
        "HKDF": [r"\b(hkdf|HKDF)\b"],
        "MD2": [r"\b(md2|MD2)(_init|_update|_final)?\b", r"\bchecksum\b"],
        "RSA": [r"\b(rsa|RSA)(_generate|_encrypt|_decrypt|_sign|_verify)?\b"],
        "DH": [r"\b(dh_|DH_|diffie)\w*\b"],
        "ECDSA": [r"\b(ecdsa|ECDSA|ec_key|EC_KEY)\b"],
        "ECDH": [r"\b(ecdh|ECDH)\b"],
        "X25519": [r"\bx25519\b"],
        "Ed25519": [r"\bed25519\b"],
    }
    matched: list[str] = []
    for pat in patterns.get(canonical, []):
        try:
            if re.search(_loosen_identifier(pat), masked):
                matched.append(pat)
        except re.error:
            continue
    return matched


_SUFFIXED_OPTIONAL = re.compile(r"\)\?\\b$")


def _loosen_identifier(pat: str) -> str:
    """Allow `_<verb>` suffixes on identifier stems.

    Custom implementations name entry points `sha256_update_blocks`,
    `arcfour_generate_stream`, `AES_ECB_encrypt` — the strict
    `(_init|_update|…)?\\b` endings miss them. A trailing `_\\w+`
    keeps the distinctive stem requirement while accepting real
    API shapes. Single-word patterns (`clamp`, `checksum`) stay exact.
    """
    if _SUFFIXED_OPTIONAL.search(pat):
        return _SUFFIXED_OPTIONAL.sub(r")?(?:_\\w+)?\\b", pat)
    return pat


def _hex_ints(masked: str) -> list[int]:
    vals: list[int] = []
    for token in _HEX_RE.findall(masked or ""):
        try:
            vals.append(int(token, 16))
        except ValueError:
            continue
    return vals


def _array_blocks(masked: str) -> list[list[int]]:
    """Integer contents of each flat `{...}` initializer block."""
    blocks: list[list[int]] = []
    for body in _BRACE_BLOCK_RE.findall(masked or ""):
        if "(" in body or ")" in body:
            continue
        nums: list[int] = []
        for token in _HEX_RE.findall(body):
            try:
                nums.append(int(token, 16))
            except ValueError:
                continue
        for token in _INT_RE.findall(body):
            try:
                value = int(token)
            except ValueError:
                continue
            if -2_147_483_648 <= value <= 4_294_967_295:
                nums.append(value & 0xFFFFFFFF)
        if len(nums) >= 4:
            blocks.append(nums)
    return blocks


def _ordered_run(block: list[int], needle: list[int], minimum: int) -> bool:
    """True when >=minimum needle items appear in order inside block."""
    need = 0
    for value in block:
        if need < len(needle) and value == needle[need]:
            need += 1
            if need >= minimum:
                return True
    return False


def _has_256_u8_table(masked: str) -> bool:
    return bool(re.search(r"\[\s*256\s*\]\s*(?:[A-Za-z_]\w*\s*)?=\s*\{", masked or ""))


def _sized_int_table(masked: str, sizes: tuple[int, ...]) -> bool:
    for size in sizes:
        if re.search(r"\[\s*%d\s*\]" % size, masked or ""):
            return True
    return False


def _strong_constants(canonical: str, hex_vals: list[int],
                      blocks: list[list[int]]) -> list[str]:
    """Strong constant-set hits for one family (ordered where it matters)."""
    found: set[int] = set(hex_vals)
    hits: list[str] = []
    if canonical == "AES":
        if sum(1 for v in _AES_SBOX_PREFIX if v in found) >= 8:
            hits.append("aes-sbox")
        if any(_ordered_run(b, _AES_RCON, 4) for b in blocks):
            hits.append("aes-rcon")
        if any(_ordered_run(b, _AES_SBOX_PREFIX, 6) for b in blocks):
            hits.append("aes-sbox-ordered")
    elif canonical == "SHA-256":
        if sum(1 for v in _SHA256_K if v in found) >= 3:
            hits.append("sha256-k")
    elif canonical == "SHA-512":
        if sum(1 for v in _SHA512_IV if v in found) >= 3:
            hits.append("sha512-iv")
    elif canonical == "MD5":
        if all(v in found for v in _MD_ABCD) and any(v in found for v in _MD5_EXTRA):
            hits.append("md5-iv+k")
    elif canonical == "SHA-1":
        if all(v in found for v in _MD_ABCD) and any(v in found for v in _SHA1_EXTRA):
            hits.append("sha1-h+f")
    elif canonical == "ChaCha20":
        if sum(1 for v in _CHACHA_SIGMA if v in found) >= 3:
            hits.append("chacha-sigma")
    elif canonical == "Blowfish":
        if any(v in found for v in _BLOWFISH_PI):
            hits.append("blowfish-pi")
    return hits


_FAMILY_OPS = {
    "AES": "ENCRYPT", "DES": "ENCRYPT", "3DES": "ENCRYPT",
    "RC4": "ENCRYPT", "Blowfish": "ENCRYPT", "ChaCha20": "ENCRYPT",
    "Poly1305": "HASH", "MD5": "HASH", "MD2": "HASH",
    "SHA-1": "HASH", "SHA-256": "HASH", "SHA-512": "HASH",
    "HMAC": "HASH", "PBKDF2": "KDF", "HKDF": "KDF",
    "RSA": "KEY_MANAGEMENT", "DH": "KEY_EXCHANGE",
    "ECDSA": "KEY_MANAGEMENT", "ECDH": "KEY_EXCHANGE",
    "X25519": "KEY_EXCHANGE", "Ed25519": "SIGN",
}

FINGERPRINT_FAMILIES = tuple(_FAMILY_OPS)


def analyze_file(masked: str, lang: str = "c") -> list[FingerprintHit]:
    """Fingerprint one masked file. Returns hits (possibly empty).

    ``masked`` must already have comments/strings blanked. Pure,
    deterministic, stdlib-only.
    """
    if lang not in ("c", "cpp"):
        return []
    if not masked or len(masked) > 2 * 1024 * 1024:
        return []
    lowered = masked.lower()
    if any(exc in lowered for exc in EXCLUDED_IDENTIFIERS) and not any(
            k in lowered for k in ("aes", "sha", "md5", "des", "hmac", "chacha")):
        return []
    hex_vals = _hex_ints(masked)
    blocks = _array_blocks(masked)
    table256 = _has_256_u8_table(masked)
    hits: list[FingerprintHit] = []
    for canonical in FINGERPRINT_FAMILIES:
        identifiers = _family_identifiers(canonical, masked)
        strong = _strong_constants(canonical, hex_vals, blocks)
        structural: list[str] = []
        if canonical in ("AES", "RC4") and table256 and identifiers:
            structural.append("u8-table-256")
        if canonical == "DES" and _sized_int_table(masked, (64, 48, 56, 32)) and identifiers:
            structural.append("perm-table")
        if canonical == "MD2" and table256:
            structural.append("u8-table-256")
        if _def_cluster(masked, canonical):
            # >=2 repo-defined functions of this family: the file does
            # not merely mention the algorithm, it implements entry
            # points for it (e.g. arcfour_key_setup + arcfour_crypt).
            structural.append("def-cluster")
        # Confidence ladder (plan §9).
        signals = [f"strong:{s}" for s in strong] + \
                  [f"ident:{i}" for i in identifiers] + \
                  [f"struct:{s}" for s in structural]
        weak_classes = (1 if identifiers else 0) + (1 if structural else 0)
        confidence = 0.0
        if len(strong) >= 2:
            confidence = 0.95
        elif strong and (identifiers or structural):
            confidence = 0.90
        elif weak_classes >= 2 or len(identifiers) >= 3:
            confidence = 0.65
        else:
            continue  # single weak signal -> candidate only, no finding
        detail_bits = []
        if strong:
            detail_bits.append("constants " + ",".join(sorted(strong)))
        if identifiers:
            detail_bits.append(f"{len(identifiers)} identifier group(s)")
        if structural:
            detail_bits.append("structure " + ",".join(sorted(structural)))
        hits.append(FingerprintHit(
            canonical=canonical,
            operation=_FAMILY_OPS[canonical],
            signals=signals,
            confidence=confidence,
            detail="custom implementation (" + "; ".join(detail_bits) + ")",
        ))
    # 3DES is a DES refinement: keep the more specific finding only,
    # unless the file defines DES-only entry points too (e.g. des_crypt
    # alongside three_des_crypt: both families are implemented).
    names = {h.canonical for h in hits}
    if "3DES" in names and "DES" in names:
        try:
            des_only = {name for name, _line in defined_functions(masked)
                        if def_name_matches_family(name, "DES")
                        and not def_name_matches_family(name, "3DES")}
        except Exception:
            des_only = set()
        if len(des_only) < 2:
            hits = [h for h in hits
                    if not (h.canonical == "DES" and h.confidence <= next(
                        x.confidence for x in hits if x.canonical == "3DES"))]
    return sorted(hits, key=lambda h: (-h.confidence, h.canonical))


def defined_functions(masked: str) -> list[tuple[str, int]]:
    """Top-level function definitions in masked source: (name, line).

    Names are bare method names (``EncryptECB`` for
    ``AES::EncryptECB``); class qualifiers are available separately via
    :func:`definition_qualifiers`.
    """
    if not masked:
        return []
    lines = masked.split("\n")
    out: list[tuple[str, int]] = []
    for match in _FUNC_DEF_RE.finditer(masked):
        name = match.group(2)
        if _KEYWORD_DEF_RE.fullmatch(name):
            continue
        line = masked.count("\n", 0, match.start()) + 1
        _ = lines
        out.append((name, line))
    return out


def definition_qualifiers(masked: str) -> dict[str, str]:
    """Class qualifiers for C++ out-of-class definitions: {method: class}.

    ``unsigned char *AES::EncryptECB(...)`` maps ``EncryptECB`` ->
    ``AES`` so the class name can corroborate the family (the method
    name alone, e.g. ``EncryptECB``, carries no family token). First
    definition wins. Pure; never raises.
    """
    out: dict[str, str] = {}
    if not masked:
        return out
    try:
        for match in _FUNC_DEF_RE.finditer(masked):
            qual, name = match.group(1), match.group(2)
            if qual and name and name not in out:
                out[name] = qual
    except Exception:
        pass
    return out


_OP_HINTS = (
    ("decrypt", "DECRYPT"),
    ("encrypt", "ENCRYPT"),
    ("verify", "VERIFY"),
    ("sign", "SIGN"),
    ("exchange", "KEY_EXCHANGE"),
    ("agree", "KEY_EXCHANGE"),
    ("derive", "KDF"),
    ("pbkdf", "KDF"),
    ("hash", "HASH"),
    ("digest", "HASH"),
    ("checksum", "HASH"),
    ("hmac", "HASH"),
    ("init", "KEY_MANAGEMENT"),
    ("key", "KEY_MANAGEMENT"),
    ("expand", "KEY_MANAGEMENT"),
    ("schedule", "KEY_MANAGEMENT"),
    ("generate", "KEY_MANAGEMENT"),
    ("cipher", "ENCRYPT"),
    # IV management (set_iv / iv setup) is key provisioning, not data
    # encryption. Last so directional verbs keep priority, and only
    # consulted after the directional pre-checks in function_semantics.
    ("iv", "KEY_MANAGEMENT"),
)


def _def_cluster(masked: str, canonical: str) -> bool:
    """True when >=2 defined functions belong to the family."""
    try:
        quals = definition_qualifiers(masked)
        names = set()
        for name, _line in defined_functions(masked):
            qual = quals.get(name, "")
            qname = f"{qual}::{name}" if qual else name
            if def_name_matches_family(qname, canonical):
                names.add(name)
    except Exception:
        return False
    return len(names) >= 2


def def_name_matches_family(name: str, canonical: str) -> bool:
    """True when a function name plausibly defines the family (token match).

    Used to link cross-file invocations to the implementing file.
    Conservative: the family token must appear in the name; generic
    helpers (``init``, ``update`` alone) never match.
    """
    lowered = str(name or "").lower()
    tokens: dict[str, tuple[str, ...]] = {
        "AES": ("aes",),
        "DES": ("des", "desede", "tripledes"),
        "3DES": ("desede", "tripledes", "des_ede", "three_des",
                 "triple_des", "des3", "tdea"),
        "RC4": ("rc4", "arcfour", "arc4"),
        "Blowfish": ("blowfish",),
        "ChaCha20": ("chacha",),
        "Poly1305": ("poly1305",),
        "MD5": ("md5",),
        "MD2": ("md2",),
        "SHA-1": ("sha1",),
        "SHA-256": ("sha256",),
        "SHA-512": ("sha512",),
        "HMAC": ("hmac",),
        "PBKDF2": ("pbkdf2",),
        "HKDF": ("hkdf",),
        "RSA": ("rsa",),
        "DH": ("dh_", "_dh", "diffie"),
        "ECDSA": ("ecdsa", "ec_key"),
        "ECDH": ("ecdh",),
        "X25519": ("x25519",),
        "Ed25519": ("ed25519",),
    }
    return any(tok in lowered for tok in tokens.get(canonical, ()))


def op_hint_for_name(name: str) -> str | None:
    """Operation hint from a custom crypto function name (None = unknown)."""
    sem = function_semantics(name)
    if sem[0] is None or not sem[2]:
        return None
    return sem[2][0]


#: Cipher mode tokens recognized inside custom implementation names.
#: Matched as whole `_`-separated tokens only (never substrings), so a
#: bare ``aes_encrypt`` stays mode-less instead of guessing ECB.
_MODE_TOKENS = ("ECB", "CBC", "CTR", "GCM", "CCM", "CFB", "OFB", "XTS", "SIV")

#: Families checked first when resolving a function name (3DES before DES:
#: ``three_des_crypt`` contains the ``des`` substring but is 3DES).
_FAMILY_PRIORITY = (
    "3DES", "DES", "AES", "RC4", "Blowfish", "ChaCha20", "Poly1305",
    "MD2", "MD5", "SHA-1", "SHA-256", "SHA-512", "HMAC", "PBKDF2",
    "HKDF", "RSA", "DH", "ECDSA", "ECDH", "X25519", "Ed25519",
)


def _camel_tokens(text: str) -> list[str]:
    """Split identifiers on separators and CamelCase boundaries.

    ``EncryptECB`` -> [``encrypt``, ``ecb``]; ``aes_encrypt_cbc`` ->
    [``aes``, ``encrypt``, ``cbc``]. Whole-token mode matching stays
    exact; previously glued spellings only gain modes, never lose them.
    """
    out: list[str] = []
    try:
        for piece in re.split(r"[^A-Za-z0-9]+", str(text or "")):
            if not piece:
                continue
            for tok in re.findall(
                    r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+", piece):
                if tok:
                    out.append(tok.lower())
    except Exception:
        pass
    return out


def function_semantics(name: str) -> tuple[str | None, str | None, tuple[str, ...]]:
    """Refine a crypto signal from a custom function name.

    Returns ``(family, mode, ops)`` where ``ops`` are ``OperationType``
    names. ``(None, None, ())`` when the name carries no family token —
    generic verbs (``encrypt``, ``hash``, ``key`` …) never resolve alone;
    callers must corroborate with fingerprint/constant evidence first.

    C++ ``Class::method`` definitions take the family from the class
    qualifier (``AES::EncryptECB``); then the method itself must carry
    an explicit operation/mode signal (helpers like ``XorBlocks`` and
    constructors yield nothing — no family-fallback guessing).

    Mode is only reported when a mode token is present (``_``-separated
    or CamelCase); ``aes_encrypt`` stays mode-less (never defaulted to
    ECB). ``xcrypt``/bare ``crypt`` entry points cover both directions
    (``[ENCRYPT, DECRYPT]``); CBC-MAC maps to ``HASH`` (the frozen CIR
    vocabulary has no MAC operation; message authentication is
    integrity-class evidence).
    """
    text = str(name or "")
    lowered = text.lower()
    qual, sep, method = text.rpartition("::")
    method = method if sep else text
    method_lower = method.lower()
    family: str | None = None
    family_in_method = False
    for candidate in _FAMILY_PRIORITY:
        if def_name_matches_family(method, candidate):
            family, family_in_method = candidate, True
            break
    if family is None and qual:
        for candidate in _FAMILY_PRIORITY:
            if def_name_matches_family(qual, candidate):
                family = candidate
                break
    if family is None:
        return (None, None, ())
    # Constructors/destructors name the family itself (``AES::AES``):
    # key provisioning, not a data operation — no ops from the name.
    method_core = method_lower.lstrip("~").lstrip("_")
    qual_core = qual.lower().lstrip("_") if qual else ""
    if method_core and (method_core == qual_core
                        or method_core == family.lower()):
        return (family, None, ())
    tokens = _camel_tokens(method)
    token_set = set(tokens)
    mode: str | None = None
    for token in tokens:
        if token.upper() in _MODE_TOKENS:
            mode = token.upper()
            break
    if mode == "CBC" and ("mac" in token_set or "cbcmac" in token_set):
        mode = "CBC-MAC"
    ops: tuple[str, ...]
    if mode == "CBC-MAC":
        ops = ("HASH",)
    elif "decrypt" in method_lower:
        ops = ("DECRYPT",)
    elif "encrypt" in method_lower:
        ops = ("ENCRYPT",)
    elif "xcrypt" in method_lower or "crypt" in method_lower:
        # Shared direction-flagged entry points (DES/3DES _crypt, CTR
        # xcrypt): one function implements both directions.
        ops = ("ENCRYPT", "DECRYPT")
    elif "stream" in method_lower:
        ops = ("ENCRYPT",)
    else:
        explicit: str | None = None
        for hint, op in _OP_HINTS:
            if hint in method_lower:
                explicit = op
                break
        if explicit is not None:
            # Explicit verb signal (init/key/schedule/…): always honored.
            ops = (explicit,)
        elif not family_in_method:
            # Bare family fallback (sha256_update -> HASH) only applies
            # when the name itself references the family; qualifier-only
            # helpers (XorBlocks, CheckLength) yield nothing.
            return (family, mode, ())
        else:
            fallback = _family_fallback_op(method_lower)
            if fallback is None:
                return (family, mode, ())
            ops = (fallback,)
    return (family, mode, ops)


_FAMILY_FALLBACK_OPS = (
    ("md2", "HASH"), ("md5", "HASH"), ("sha1", "HASH"),
    ("sha256", "HASH"), ("sha512", "HASH"),
    ("hmac", "HASH"), ("poly1305", "HASH"),
    ("pbkdf2", "KDF"), ("hkdf", "KDF"),
    ("aes", "ENCRYPT"), ("des", "ENCRYPT"),
    ("rc4", "ENCRYPT"), ("arcfour", "ENCRYPT"),
    ("blowfish", "ENCRYPT"), ("chacha", "ENCRYPT"),
    ("rsa", "KEY_MANAGEMENT"), ("dh", "KEY_EXCHANGE"),
    ("ecdh", "KEY_EXCHANGE"), ("ecdsa", "SIGN"),
    ("x25519", "KEY_EXCHANGE"), ("ed25519", "SIGN"),
)


def _family_fallback_op(lowered: str) -> str | None:
    """Dominant operation implied by the primitive itself or None."""
    for family, op in _FAMILY_FALLBACK_OPS:
        if family in lowered:
            return op
    return None


def _op_hint_fallback(lowered: str) -> str | None:
    """Non-directional operation hint (key/hash/sign-style verbs)."""
    for hint, op in _OP_HINTS:
        if hint in lowered:
            return op
    # Family fallback: the primitive itself implies the dominant
    # operation (sha256_update -> HASH). Explicit hints above win
    # (AES_init_ctx stays KEY_MANAGEMENT, not ENCRYPT).
    return _family_fallback_op(lowered)


def _op_hint_fallback(lowered: str) -> str | None:
    """Non-directional operation hint (key/hash/sign-style verbs)."""
    for hint, op in _OP_HINTS:
        if hint in lowered:
            return op
    # Family fallback: the primitive itself implies the dominant
    # operation (sha256_update -> HASH). Explicit hints above win
    # (AES_init_ctx stays KEY_MANAGEMENT, not ENCRYPT).
    for family, op in (("md2", "HASH"), ("md5", "HASH"), ("sha1", "HASH"),
                       ("sha256", "HASH"), ("sha512", "HASH"),
                       ("hmac", "HASH"), ("poly1305", "HASH"),
                       ("pbkdf2", "KDF"), ("hkdf", "KDF"),
                       ("aes", "ENCRYPT"), ("des", "ENCRYPT"),
                       ("rc4", "ENCRYPT"), ("arcfour", "ENCRYPT"),
                       ("blowfish", "ENCRYPT"), ("chacha", "ENCRYPT"),
                       ("rsa", "KEY_MANAGEMENT"), ("dh", "KEY_EXCHANGE"),
                       ("ecdh", "KEY_EXCHANGE"), ("ecdsa", "SIGN"),
                       ("x25519", "KEY_EXCHANGE"), ("ed25519", "SIGN")):
        if family in lowered:
            return op
    return None


def canonical_for_semantics(family: str | None,
                            mode: str | None) -> str | None:
    """Compose a canonical name from family + mode (None when no family).

    Only AES composes mode variants (``AES-CBC``, ``AES-ECB``, …);
    other families keep their canonical. A missing mode yields the
    generic family canonical — never a guessed default mode.
    """
    if not family:
        return None
    if family == "AES" and mode:
        return f"AES-{mode}"
    return family


def corroborate_definition(body: str, mode: str | None,
                           ops: tuple[str, ...]) -> list[str]:
    """Bounded local-structure notes for a definition body (P6).

    Pure substring checks on the masked body: IV handling / XOR chaining
    for CBC, counter+nonce/increment/XOR for CTR, init/update/transform
    staging for hashes. Returns short detail tokens (possibly empty);
    never raises, never invents operations.
    """
    try:
        text = str(body or "").lower()
    except Exception:
        return []
    notes: list[str] = []
    if mode == "CBC":
        if "iv" in text:
            notes.append("iv-handling")
        if "xor" in text:
            notes.append("xor-chaining")
    elif mode == "CTR":
        if "counter" in text or "nonce" in text or "ctr" in text:
            notes.append("counter-use")
        if "++" in text or "increment" in text or "+= 1" in text or "+ 1" in text:
            notes.append("counter-increment")
        if "xor" in text:
            notes.append("keystream-xor")
    if "HASH" in (ops or ()):
        if "transform" in text or "update" in text:
            notes.append("hash-staging")
        if "init" in text and "final" in text:
            notes.append("init-final-pair")
    return notes[:3]
