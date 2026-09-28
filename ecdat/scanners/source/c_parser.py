"""Fast syntax engine for C-like source (Phase 4).

"Tree-sitter or equivalent fast syntax parsing": neither tree-sitter
bindings nor Semgrep are guaranteed on scan hosts (both absent here), so
this module is the stdlib equivalent - a masking tokenizer (comments and
string/char literals blanked with offsets preserved, so line numbers
hold), balanced-paren call extraction, brace-depth function tracking,
candidate-only constant propagation, and one-hop same-file wrapper
resolution. No whole-program analysis: constants and wrappers resolve
only around crypto candidates.

Also shared by the Java/JS/Go/C#/Rust routers (all brace languages).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "mask_source",
    "extract_calls",
    "collect_constants",
    "resolve_arg",
    "classify_source_file",
    "resolve_entry",
    "find_wrappers",
    "aes_key_config",
    "TLS_VERSION_CONSTS",
    "TEST_DIR_NAMES",
    "IMPL_DIR_NAMES",
]

#: Path segments marking test vectors/examples (not application use).
TEST_DIR_NAMES = frozenset({"test", "tests", "testing", "testsuit", "demos", "examples", "doc"})
#: Path segments marking algorithm/library implementation (OpenSSL layout).
IMPL_DIR_NAMES = frozenset({"crypto", "providers", "engines", "fips"})

TLS_VERSION_CONSTS = {
    "TLS1_VERSION": "TLS1.0",
    "TLS1_1_VERSION": "TLS1.1",
    "TLS1_2_VERSION": "TLS1.2",
    "TLS1_3_VERSION": "TLS1.3",
    "DTLS1_VERSION": "DTLS1.0",
    "DTLS1_2_VERSION": "DTLS1.2",
}

#: First-argument key-type tokens for EVP_PKEY_new_raw_*_key.
_PKEY_TYPE_TABLE = {
    "EVP_PKEY_HMAC": "HMAC",
    "EVP_PKEY_RSA": "RSA",
    "EVP_PKEY_DSA": "DSA",
    "EVP_PKEY_DH": "DH",
    "EVP_PKEY_EC": "ECDSA",
    "EVP_PKEY_X25519": "X25519",
    "EVP_PKEY_X448": "X448",
    "EVP_PKEY_ED25519": "Ed25519",
}

#: Keywords counted inside stripped comments/strings (noise traceability).
_NOISE_KEYWORDS = (
    "AES", "RSA", "DES", "SHA", "MD5", "HMAC", "ECDSA", "ECDH", "TLS", "SSL",
    "ChaCha", "PBKDF2", "HKDF", "Ed25519", "X25519", "Kyber", "Dilithium",
)

_CALL_RE = re.compile(r"([A-Za-z_][\w:\.]*)\s*\(")
_FUNC_DEF_RE = re.compile(
    r"^\s*(?:@[\w.]+(?:\([^;{}]*\))?\s*)*"
    r"(?:[\w:\<\>\*\[\]]+\s+)*(?:\([^;{}]*\)\s+)?[\*\&]?\s*"
    r"(?:([A-Za-z_]\w*)::)?([A-Za-z_]\w*)\s*\([^;{}]*\)"
    r"\s*(?:throws\s+[\w,\s.]+)?\s*(?:[\w:\<\>\*\[\]\.]+\s+)?(?:\{|$)")
_KEYWORD_DECL_RE = re.compile(r"\b(?:if|for|while|switch|catch|return|sizeof)\b")
_DEFINE_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s+(.+?)\s*$")
_CONST_ASSIGN_RE = re.compile(
    r"\b(?:const\s+)?[A-Za-z_][\w:\<\>\*]*\s*[\*\&]?\s*([A-Za-z_]\w*)\s*=\s*"
    r"((?:\"(?:[^\"\\]|\\.)*\")|(?:\d+)|(?:[A-Za-z_]\w*(?:\(\))?))\s*;")
_STRING_LIT_RE = re.compile(r"\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)'")
_INT_RE = re.compile(r"^(\d+)$")


def mask_source(text: str) -> tuple[str, int]:
    """Blank comments/strings/chars, preserving offsets and newlines.

    Returns ``(masked, suppressed_keyword_hits)``: the count of crypto
    keywords that appeared ONLY inside removed regions (traceability for
    the noise-suppression claim; those regions never produce findings).
    """
    out: list[str] = []
    removed: list[str] = []
    i, n = 0, len(text)
    state = "code"
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line"
                out.append("  ")
                i += 2
            elif ch == "/" and nxt == "*":
                state = "block"
                out.append("  ")
                i += 2
            elif ch == '"':
                state = "string"
                removed.append('"')
                out.append(" ")
                i += 1
            elif ch == "'" and _likely_char_start(text, i):
                state = "char"
                removed.append("'")
                out.append(" ")
                i += 1
            else:
                out.append(ch)
                i += 1
        elif state == "line":
            if ch == "\n":
                state = "code"
                out.append(ch)
            else:
                removed.append(ch)
                out.append(" " if ch != "\t" else "\t")
            i += 1
        elif state == "block":
            if ch == "*" and nxt == "/":
                state = "code"
                out.append("  ")
                i += 2
            else:
                if ch == "\n":
                    out.append("\n")
                else:
                    removed.append(ch)
                    out.append(" ")
                i += 1
        elif state == "string":
            if ch == "\\":
                removed.append(text[i:i + 2])
                out.append("  ")
                i += 2
            elif ch == '"':
                state = "code"
                removed.append('"')
                out.append(" ")
                i += 1
            else:
                removed.append(ch)
                out.append("\n" if ch == "\n" else " ")
                i += 1
        else:  # char literal
            if ch == "\\":
                removed.append(text[i:i + 2])
                out.append("  ")
                i += 2
            elif ch == "'":
                state = "code"
                removed.append("'")
                out.append(" ")
                i += 1
            else:
                removed.append(ch)
                out.append("\n" if ch == "\n" else " ")
                i += 1
    blob = "".join(removed)
    suppressed = sum(blob.count(k) for k in _NOISE_KEYWORDS)
    masked = "".join(out)
    masked, disabled_hits = _blank_disabled_preprocessor_blocks(masked)
    return masked, suppressed + disabled_hits


def _blank_disabled_preprocessor_blocks(masked: str) -> tuple[str, int]:
    """Blank `#if 0 ... #endif` regions (Phase 6 build-state semantics).

    Disabled preprocessor blocks are not compiled; crypto-like symbols
    inside them are build-state DISABLED evidence, never application
    invocations. Offsets/newlines preserved so line numbers hold.
    Returns (masked, crypto_keyword_hits_in_disabled_regions).
    """
    lines = masked.split("\n")
    out: list[str] = []
    depth = 0  # nesting depth inside disabled regions
    cond_stack: list[bool] = []  # per-#if whether that level disabled
    hits = 0
    for line in lines:
        s = line.strip()
        m = re.match(r"#\s*if\s+(.*)", s)
        m_elif = re.match(r"#\s*elif\s+(.*)", s)
        m_else = re.match(r"#\s*else\b", s)
        m_endif = re.match(r"#\s*endif\b", s)
        m_ifdef = re.match(r"#\s*(ifdef|ifndef)\b", s)
        if m:
            disabled = s == "#if 0" or re.match(r"#\s*if\s+0\s*(//.*)?$", s) is not None
            cond_stack.append(bool(disabled))
            depth = sum(1 for c in cond_stack if c)
            out.append(" " * len(line))
            continue
        if m_ifdef:
            cond_stack.append(False)
            out.append(line)
            continue
        if m_elif is not None:
            if cond_stack:
                cond_stack[-1] = False  # conservative: elif re-enables
                depth = sum(1 for c in cond_stack if c)
            out.append(" " * len(line) if depth else line)
            continue
        if m_else is not None:
            if cond_stack:
                # #else of `#if 0` re-enables; #else of active stays active.
                was = cond_stack[-1]
                cond_stack[-1] = False if was else ("__else__" in cond_stack)
                depth = sum(1 for c in cond_stack if c)
            out.append(line if not depth else " " * len(line))
            continue
        if m_endif is not None:
            if cond_stack:
                cond_stack.pop()
                depth = sum(1 for c in cond_stack if c)
            out.append(" " * len(line))
            continue
        if depth:
            hits += sum(line.count(k) for k in _NOISE_KEYWORDS)
            out.append(" " * len(line))
        else:
            out.append(line)
    return "\n".join(out), hits


def _likely_char_start(text: str, i: int) -> bool:
    prev = text[i - 1] if i > 0 else ""
    return prev in ("", " ", "\t", "\n", "(", ",", "=", "[", "{", ";", ":", "!")


@dataclass
class CallSite:
    """One ``name(args)`` occurrence in masked code."""

    name: str
    args: str
    line: int
    function: str | None
    call_text: str


def _paren_balance(text: str) -> int:
    """Open minus close parens (masked text has no strings to confuse it)."""
    return text.count("(") - text.count(")")


def _function_spans(masked: str) -> list[tuple[int, int, str]]:
    """Brace-depth function spans: (start_off, end_off, name).

    Multi-line definitions are joined before matching (offsets still map
    to real lines because only the matcher sees the collapsed buffer).
    Prototypes (``;``) and control statements never open spans.
    Definitions nest (methods in classes, closures): sites attribute to
    the innermost enclosing definition. Both Allman (``f() {``) and K&R
    (``f()`` + ``{`` on the next line) styles open spans; Go receivers,
    Java ``throws``, Go return types, and ``[]`` return types are
    recognized. ``new X() {`` (anonymous classes) is not a definition.
    """
    spans: list[tuple[int, int, str]] = []
    lines = masked.splitlines(keepends=True)
    offsets: list[int] = []
    pos = 0
    for line in lines:
        offsets.append(pos)
        pos += len(line)
    depth = 0
    open_stack: list[list] = []  # [name, start_off, open_depth]
    pending: list | None = None  # [name, start_off, open_depth]
    buf = ""
    buf_start = 0
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if pending is None:
            if not buf:
                buf_start = offsets[idx]
            buf += " " + stripped
            if _paren_balance(buf) <= 0:
                candidate = buf.strip()
                buf = ""
                nxt = lines[idx + 1].strip() if idx + 1 < len(lines) else ""
                if "(" in candidate and (
                        candidate.endswith("{") or nxt.startswith("{")) \
                        and ";" not in candidate:
                    match = _FUNC_DEF_RE.match(candidate)
                    if match:
                        before = candidate[:candidate.index("(")]
                        if not _KEYWORD_DECL_RE.search(before) \
                                and not re.match(r"^\s*new\s+", before):
                            # Group 2 is the bare method name; an optional
                            # C++ ``Class::`` qualifier (group 1) is not
                            # part of span identity (bare names stay the
                            # cross-file provider key).
                            pending = [match.group(2), buf_start, depth]
        depth += line.count("{") - line.count("}")
        if depth < 0:
            depth = 0
        if pending is not None:
            _name, _start, _od = pending
            if depth > _od:
                open_stack.append([_name, _start, _od])
                pending = None
            elif depth < _od:
                pending = None  # malformed; drop
        while open_stack and depth <= open_stack[-1][2]:
            _name, _start, _od = open_stack.pop()
            spans.append((_start, offsets[idx] + len(line), _name))
            if _od == 0:
                depth = 0  # historical imbalance containment
    spans.sort()
    return spans


def _def_lines(masked: str) -> dict[str, int]:
    """Defined function/method names to 1-based definition lines.

    Derived from :func:`_function_spans` (brace-depth tracking), so K&R
    definitions, class methods, and Go receivers are all covered —
    unlike the fingerprint helper, which only sees a subset. Pure.
    """
    try:
        offsets: list[int] = []
        pos = 0
        for line in masked.splitlines(keepends=True):
            offsets.append(pos)
            pos += len(line)
        defs: dict[str, int] = {}
        for start, _end, name in _function_spans(masked):
            import bisect as _bisect
            lineno = _bisect.bisect_right(offsets, start)
            defs.setdefault(name, lineno)
        return defs
    except Exception:
        return {}


def _def_lines_all(masked: str) -> dict[str, list[int]]:
    """All definition lines per function name (overloads included)."""
    try:
        offsets: list[int] = []
        pos = 0
        for line in masked.splitlines(keepends=True):
            offsets.append(pos)
            pos += len(line)
        defs: dict[str, list[int]] = {}
        for start, _end, name in _function_spans(masked):
            import bisect as _bisect
            lineno = _bisect.bisect_right(offsets, start)
            defs.setdefault(name, [])
            if lineno not in defs[name]:
                defs[name].append(lineno)
        for lines in defs.values():
            lines.sort()
        return defs
    except Exception:
        return {}


def extract_calls(masked: str) -> list[CallSite]:
    """Extract ``name(args)`` sites with enclosing functions."""
    spans = _function_spans(masked)
    sites: list[CallSite] = []
    for match in _CALL_RE.finditer(masked):
        name = match.group(1)
        if _KEYWORD_DECL_RE.fullmatch(name):
            continue
        open_paren = match.end() - 1
        args, _ = _balanced(masked, open_paren)
        if args is None:
            continue
        line = masked.count("\n", 0, match.start()) + 1
        enclosing: str | None = None
        for start, end, fname in spans:
            if start <= match.start() < end:
                enclosing = fname
                break
        sites.append(CallSite(
            name=name, args=args, line=line, function=enclosing,
            call_text=f"{name}({args.strip()[:120]})"))
    return sites


def _balanced(text: str, open_idx: int, limit: int = 4000) -> tuple[str | None, int]:
    """Capture balanced parens from ``open_idx`` (bounded)."""
    depth = 0
    i = open_idx
    n = min(len(text), open_idx + limit)
    while i < n:
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i
        i += 1
    return None, open_idx


def split_args(args: str) -> list[str]:
    """Top-level comma split (nesting aware, bounded)."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    in_str = False
    escape = False
    for ch in args[:4000]:
        if in_str:
            current.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            current.append(ch)
        elif ch in "([":
            depth += 1
            current.append(ch)
        elif ch in ")]":
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    parts.append("".join(current).strip())
    return [p for p in parts if p]


def collect_constants(masked: str) -> dict[str, str]:
    """File-local constant map (candidate-only propagation source).

    ``#define NAME value``, ``const T NAME = value`` and simple
    ``T NAME = "literal"|123`` assignments. One hop, same file, values
    kept raw (callers interpret).
    """
    consts: dict[str, str] = {}
    for line in masked.splitlines():
        match = _DEFINE_RE.match(line)
        if match:
            consts[match.group(1)] = match.group(2).strip()
            continue
        for found in _CONST_ASSIGN_RE.finditer(line):
            consts[found.group(1)] = found.group(2).strip()
    return consts


_JAVA_STRING_CONST_RE = re.compile(
    r"\bString\s+([A-Za-z_]\w*)\s*=\s*\"((?:[^\"\\]|\\.)*)\"\s*;")


def collect_java_string_consts(original: str) -> dict[str, str]:
    """Java ``String NAME = "literal"`` constants (any modifiers).

    Runs on ORIGINAL text: masking blanks string contents, so the
    generic collector never sees Java string values. Values are stored
    quoted (same contract as :func:`collect_constants`); first
    definition wins. Pure; never raises.
    """
    out: dict[str, str] = {}
    try:
        for match in _JAVA_STRING_CONST_RE.finditer(original or ""):
            out.setdefault(match.group(1), f'"{match.group(2)}"')
    except Exception:
        pass
    return out


def resolve_arg(arg: str, consts: dict[str, str]) -> str:
    """Resolve one argument to a literal-ish token (one hop)."""
    token = arg.strip()
    if len(token) >= 2 and token.startswith('"') and token.endswith('"'):
        return token[1:-1]
    call = re.match(r"^([A-Za-z_]\w*)\s*\(", token)
    if call:
        return call.group(1)
    if token in consts:
        inner = consts[token].strip()
        if len(inner) >= 2 and inner.startswith('"') and inner.endswith('"'):
            return inner[1:-1]
        word = re.match(r"^([A-Za-z_]\w*)", inner)
        if word and word.group(1) != token:
            return word.group(1)
        if _INT_RE.match(inner):
            return inner
        return inner
    return token


_AES_KEY_DEFINE_RE = re.compile(r"\bAES(128|192|256)\b")
_AES_KEY_COND_RE = re.compile(r"defined\s*\(\s*AES(128|192|256)\s*\)")


def aes_key_config(consts: dict[str, str],
                   masked: str = "") -> tuple[int | None, list[int]]:
    """Active vs supported AES key sizes from compile-time configuration.

    ``consts`` is the merged ``#define`` map (masked text, so commented
    ``//#define AES192 1`` lines never appear). A size is *active* when
    ``AES<size>`` is defined as ``1`` (first of 128/192/256 wins);
    *supported* adds sizes with any explicit define plus sizes named in
    ``defined(AES<size>)`` preprocessor conditionals (configurable
    branches). Returns ``(active_size|None, sorted_supported)`` — empty
    evidence yields ``(None, [])`` (never guessed). Pure.
    """
    active: int | None = None
    supported: set[int] = set()
    try:
        for size in (128, 192, 256):
            raw = (consts or {}).get(f"AES{size}")
            if raw is None:
                continue
            token = str(raw).strip().split()[0] if str(raw).strip() else ""
            supported.add(size)
            if active is None and token == "1":
                active = size
        for match in _AES_KEY_COND_RE.finditer(masked or ""):
            try:
                supported.add(int(match.group(1)))
            except (TypeError, ValueError):
                continue
    except Exception:
        pass
    return active, sorted(supported)


def string_literals_of_line(line: str) -> list[str]:
    """String literals on one ORIGINAL source line (masked code hides them).

    Both quote styles (JS single quotes included); C char literals yield
    their single character, which semantic parsers ignore unless it maps.
    """
    return [a or b for a, b in _STRING_LIT_RE.findall(line or "")]


def _first_string(args: str, consts: dict[str, str],
                   literals: list[str] | tuple = ()) -> str:
    """First meaningful string-ish argument (one hop).

    Masked argument text keeps quote positions but blanks contents, so
    the original line's literals are matched positionally; propagated
    ``NAME = "literal"`` constants resolve through ``consts``. Dotted
    and call expressions (``a.b()``, ``x.y``) are never strings: without
    this guard ``secretKey.getEncoded()`` mis-resolves through the
    ``EC`` substring into a bogus canonical.
    """
    str_idx = 0
    for part in split_args(args):
        piece = part.strip()
        if '"' in piece:
            if str_idx < len(literals):
                return literals[str_idx]
            str_idx += 1
            continue
        resolved = resolve_arg(piece, consts)
        if resolved and not re.fullmatch(r"[A-Za-z_]\w*", resolved) \
                and "." not in resolved and "(" not in resolved \
                and "[" not in resolved:
            return resolved
    if literals:
        return literals[0]
    return ""


def _is_test_name(name: str) -> bool:
    """True when a filename marks test vectors (token match, not substring)."""
    stem = Path(str(name or "")).stem.lower()
    if stem in ("test", "tests"):
        return True
    return bool(re.search(r"(^|[_\-.])tests?([_\-.]|$)", stem))


def statement_text(lines: list[str], lineno: int, width: int = 12) -> str:
    """Join a possibly multi-line statement (prototypes span lines).

    From ``lineno`` forward until the first line holding ``;`` or ``{``
    (bounded by ``width``; custom crypto headers routinely use 8+ line
    prototypes with per-parameter comments). Offsets elsewhere still
    use real lines.
    """
    parts: list[str] = []
    for offset in range(width):
        idx = lineno - 1 + offset
        if idx >= len(lines):
            break
        parts.append(lines[idx].strip())
        if ";" in lines[idx] or "{" in lines[idx]:
            break
    return " ".join(parts)


def classify_source_file(path: str | Path) -> str:
    """use | test-vector | implementation | header-capability.

    - test-vector: under test/tests/examples/demos (vectors, not app use).
    - implementation: under crypto/providers/engines (OpenSSL layout:
      code that IMPLEMENTS algorithms rather than calling them).
    - header-capability: C/C++ headers (declarations, not calls).
    - use: everything else.
    """
    parts = [p.lower() for p in Path(str(path)).parts]
    name = Path(str(path)).name.lower()
    if any(p in TEST_DIR_NAMES for p in parts) or _is_test_name(name):
        return "test-vector"
    if any(p in IMPL_DIR_NAMES for p in parts):
        return "implementation"
    if name.endswith((".h", ".hpp", ".hxx")):
        return "header-capability"
    return "use"


def find_wrappers(sites: list[CallSite], api_names: set[str]) -> dict[str, str]:
    """Local functions whose bodies hold a crypto API call (one hop).

    Returns ``{wrapper_name: api_call_name}``. Wrapper-to-wrapper chains
    are deliberately NOT followed (bounded, candidate-only).
    """
    wrappers: dict[str, str] = {}
    api_basenames = {a.split("(")[0].split(".")[-1].split(":")[-1]
                     for a in api_names}
    for site in sites:
        base = site.name.split(".")[-1].split(":")[-1]
        if base in api_basenames and site.function \
                and site.function not in api_basenames:
            wrappers.setdefault(site.function, site.name)
    return wrappers


_ENUM_BODY_RE = re.compile(r"\benum\s+([A-Za-z_]\w*)\s*\{", re.MULTILINE)
_ENUM_TYPE_SUFFIXES = ("Algorithm", "Factory", "Generator", "Spec",
                        "Helper", "Util", "Utils", "Manager", "Context",
                        "Parameter", "Parameters", "Key")
_ENUM_TYPE_FAMILIES = frozenset({
    "RSA", "AES", "DES", "DESEDE", "DSA", "DH", "ECDSA", "ECDH", "HMAC",
    "MD5", "SHA1", "SHA256", "SHA384", "SHA512", "CHACHA", "BLOWFISH",
})


def _family_of_typename(typename: str) -> str | None:
    """Algorithm family from a Java type name (or None).

    Strips role suffixes (``RsaAlgorithm`` -> ``Rsa``) and requires an
    exact family token match — ``Cipher``/``SecretKey``/``PublicKey``
    yield nothing. Never guesses beyond the name itself.
    """
    try:
        stem = str(typename or "").strip()
        for suffix in _ENUM_TYPE_SUFFIXES:
            if len(stem) > len(suffix) and stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        return stem.upper() if stem.upper() in _ENUM_TYPE_FAMILIES else None
    except Exception:
        return None
_ENUM_CONST_RE = re.compile(r"([A-Za-z_]\w*)\s*\(\s*\"((?:[^\"\\]|\\.)*)\"")
_FIELD_INIT_RE = re.compile(
    r"([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\.([A-Za-z_]\w*)"
    r"(?:\s*[,;])")


def _java_enum_strings(original: str) -> dict[str, dict[str, str]]:
    """Same-file Java enums: {Enum: {CONSTANT: constructor string}}.

    Only constants whose FIRST constructor argument is a quoted string
    are recorded. Runs on ORIGINAL text (masked text blanks strings).
    Pure; never raises.
    """
    table: dict[str, dict[str, str]] = {}
    try:
        for match in _ENUM_BODY_RE.finditer(original or ""):
            name, open_idx = match.group(1), match.end() - 1
            inner, _ = _balanced(original, open_idx)
            if inner is None:
                continue
            consts: dict[str, str] = {}
            for cmatch in _ENUM_CONST_RE.finditer(inner):
                consts.setdefault(cmatch.group(1), cmatch.group(2))
            if consts:
                table.setdefault(name, consts)
    except Exception:
        pass
    return table


def _java_field_enum_inits(original: str) -> list[tuple[str, str, str, str]]:
    """Field/local ``E var = E.CONST`` groundings: [(enum, var, qual, const)].

    Runs on original text (identifiers survive masking, but one parse
    over the original serves both helpers). Pure; never raises.
    """
    out: list[tuple[str, str, str, str]] = []
    try:
        for fact in _FIELD_INIT_RE.finditer(original or ""):
            out.append((fact.group(1), fact.group(2), fact.group(3),
                        fact.group(4)))
    except Exception:
        pass
    return out


def resolve_java_enum_string(texts: str | list[str] | tuple[str, ...],
                             args: str) -> str | None:
    """Resolve a JCA argument through Java enums (one hop).

    ``texts`` is the file's original text plus same-directory siblings'
    (enum definitions usually live in their own file). Handles
    ``E.CONST.getX()`` directly, and ``var.getX()`` when a field/local
    ``E var = E.CONST`` grounds the receiver. Returns the constructor
    string or None (never guesses: the constant must carry a quoted
    literal, and unknown receivers stay unresolved).
    """
    try:
        texts_seq = [texts] if isinstance(texts, str) else list(texts or [])
        table: dict[str, dict[str, str]] = {}
        inits: list[tuple[str, str, str, str]] = []
        for body in texts_seq:
            if not body:
                continue
            for enum_name, consts in _java_enum_strings(body).items():
                table.setdefault(enum_name, consts)
            inits.extend(_java_field_enum_inits(body))
        if not table:
            return None
        text = str(args or "")
        direct = re.search(
            r"([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\.\s*[A-Za-z_]\w*\s*\(\s*\)",
            text)
        if direct and direct.group(1) in table:
            hit = table[direct.group(1)].get(direct.group(2))
            if hit:
                return hit
        receiver = re.search(
            r"([A-Za-z_]\w*)\s*\.\s*[A-Za-z_]\w*\s*\(\s*\)", text)
        if not receiver:
            return None
        var = receiver.group(1)
        if var == "this":
            return None
        for enum_name, var_name, qualifier, const in inits:
            if var_name != var or qualifier != enum_name:
                continue
            consts = table.get(enum_name)
            if consts is None:
                continue
            hit = consts.get(const)
            if hit:
                return hit
        # Family fallback: the receiver's declared type names the family
        # (RsaAlgorithm alg -> RSA). Declarations (params/fields/locals)
        # are searched in all texts; disagreement means no answer.
        fams: set[str] = set()
        try:
            decl_re = re.compile(
                r"\b([A-Za-z_]\w*)\s+" + re.escape(var)
                + r"\b(?!\s*\()")
            for body in texts_seq:
                for decl in decl_re.finditer(body or ""):
                    fam = _family_of_typename(decl.group(1))
                    if fam:
                        fams.add(fam)
        except Exception:
            pass
        if len(fams) == 1:
            return next(iter(fams))
    except Exception:
        pass
    return None


def resolve_entry(entry: dict, args: str, consts: dict[str, str],
                  call_name: str,
                  literals: list[str] | tuple = ()) -> dict:
    """Apply an api_knowledge row to one call's arguments.

    Returns ``{"canonical", "key_size", "mode", "curve", "protocol",
    "padding", "detail", "confidence", "op"}``. Unknowns stay unknown:
    nothing is invented (unresolved EVP ciphers fall back to the OpenSSL
    library capability with reduced confidence).
    """
    from ecdat.scanners.source.api_knowledge import (
        CURVE_ALIASES, EVP_CIPHER_TABLE)

    canonical = entry.get("canonical")
    op = str(entry.get("op", "ENCRYPT"))
    confidence = float(entry.get("confidence", 0.85))
    key_size: int | None = entry.get("key_size")
    mode: str | None = entry.get("mode")
    curve: str | None = None
    protocol: str | None = None
    padding: str | None = None
    detail = ""
    parts = split_args(args)

    def _arg(i: int) -> str:
        return resolve_arg(parts[i], consts) if i < len(parts) else ""

    # OpenSSL EVP cipher constructors / cipher arguments.
    cipher_names = [_arg(entry["cipher_arg"])] if entry.get("cipher_arg") is not None else []
    for cname in cipher_names:
        hit = EVP_CIPHER_TABLE.get(cname)
        if hit:
            canonical, key_size, mode = hit
            break
    else:
        if entry.get("cipher_arg") is not None and entry.get("canonical") is None:
            canonical = "OpenSSL"
            confidence = min(confidence, 0.70)
            detail = "cipher unresolved; library capability only"

    parser = str(entry.get("parser", ""))
    if parser == "int-arg:0" or parser == "int-arg:1":
        idx = int(parser.split(":")[1])
        token = _arg(idx)
        match = _INT_RE.match(token)
        if match:
            bits = int(match.group(1))
            if bits in (1024, 2048, 3072, 4096, 128, 192, 256):
                key_size = bits
    elif parser == "curve-arg:0":
        token = _arg(0)
        curve = CURVE_ALIASES.get(token)
        if curve is None and token:
            detail = f"curve {token}"
    elif parser == "sha-bits":
        match = re.search(r"SHA(\d+)", call_name + str(entry.get("call", "")))
        if match:
            canonical = f"SHA-{match.group(1)}"
    elif parser in ("jca-transformation", "jca-name", "jca-signature"):
        literal = _first_string(args, consts, literals)
        upper = literal.upper().replace("-", "")
        if parser == "jca-transformation" and "/" in literal:
            chunks = literal.split("/")
            algo = chunks[0].upper()
            mode = chunks[1].upper() if len(chunks) > 1 else None
            padding = chunks[2] if len(chunks) > 2 else None
            if "AES" in algo:
                canonical = "AES"
            elif "CHACHA" in algo:
                canonical = "ChaCha20-Poly1305" if mode == "GCM" or not mode else "ChaCha20"
            elif "RSA" in algo:
                canonical = "RSA"
                if "WRAP" in algo:
                    op = "KEY_MANAGEMENT"
            elif "DES" in algo:
                canonical = "3DES" if "DESEDE" in algo else "DES"
            detail = f"transformation {literal}"
        elif "SHA256WITH" in upper or "SHA384WITH" in upper or "SHA512WITH" in upper:
            canonical = "ECDSA" if "ECDSA" in upper else "RSA"
            detail = f"signature {literal}"
        elif any(k in upper for k in ("AES", "RSA", "EC", "HMAC", "DH", "DSA",
                                      "SHA", "MD5", "TLS", "SSL", "CHACHA",
                                      "PBKDF2", "GCM", "CBC", "KYBER", "DILITHIUM")):
            canonical = _name_to_canonical(literal) or canonical
            detail = f"algorithm {literal}"
    elif parser in ("node-cipher", "node-name", "node-curve", "node-keytype"):
        literal = _first_string(args, consts, literals)
        low = literal.lower().replace("-", "")
        if parser == "node-cipher":
            match = re.match(r"aes-?(\d+)-?(\w+)?", low)
            if match:
                key_size = int(match.group(1))
                mode = (match.group(2) or "").upper() or None
                canonical = f"AES-{key_size}-{mode}" if mode else f"AES-{key_size}"
            elif "chacha" in low:
                canonical = "ChaCha20-Poly1305"
        elif parser == "node-curve":
            curve = CURVE_ALIASES.get(literal, CURVE_ALIASES.get(low))
        elif parser == "node-keytype":
            canonical = {"rsa": "RSA", "ec": "ECDSA", "ed25519": "Ed25519",
                         "x25519": "X25519", "dsa": "DSA", "dh": "DH"}.get(low, canonical)
        else:
            canonical = _name_to_canonical(literal) or canonical
    elif parser in ("webcrypto-op", "webcrypto-name"):
        literal = _first_string(args, consts, literals)
        low = literal.lower().replace("-", "")
        if "aes-gcm" in low or "aesgcm" in low:
            canonical, mode = "AES-256-GCM", "GCM"
        elif "aes-cbc" in low:
            canonical, mode = "AES", "CBC"
        elif "rsa-oaep" in low:
            canonical, op = "RSA", "ENCRYPT"
        elif "rsassa" in low or "rsa-pss" in low or "ecdsa" in low or "eddsa" in low:
            canonical = "RSA" if "rsa" in low else ("ECDSA" if "ecdsa" in low else "Ed25519")
            op = {"encrypt": "ENCRYPT", "decrypt": "DECRYPT", "sign": "SIGN",
                  "verify": "VERIFY"}.get(_webcrypto_verb(call_name), op)
        elif "ecdh" in low or "x25519" in low or "derive" in (entry.get("id", "")):
            canonical, op = ("X25519" if "25519" in low else "ECDH"), "KEY_EXCHANGE"
        elif "hkdf" in low:
            canonical, op = "HKDF", "KDF"
        elif "pbkdf2" in low:
            canonical, op = "PBKDF2", "KDF"
        elif "hmac" in low:
            canonical = "HMAC"
        elif "sha" in low:
            canonical = _name_to_canonical(literal) or canonical
    elif parser == "tls-method":
        token = _arg(0)
        mapping = {"TLS_method": None, "TLS_client_method": None,
                   "TLS_server_method": None, "TLSv1_2_method": "TLS1.2",
                   "TLSv1_3_method": "TLS1.3", "SSLv23_method": "TLS",
                   "DTLS_method": "DTLS1.2"}
        protocol = mapping.get(token)
        detail = f"method {token}" if token else ""
    elif parser == "tls-version-const":
        protocol = TLS_VERSION_CONSTS.get(_arg(1), TLS_VERSION_CONSTS.get(_arg(0)))
    elif parser == "ossl-fetch-name":
        # Provider fetch (EVP_CIPHER_fetch / EVP_MD_fetch): resolve the
        # requested algorithm name when statically visible; otherwise
        # leave canonical unresolved (caller falls back to OpenSSL
        # library capability). Per plan §1.3 unknown stays unknown.
        literal = _first_string(args, consts, literals)
        mapped = _name_to_canonical(literal) if literal else None
        if mapped:
            canonical = mapped
            detail = f"fetch {literal}"
        else:
            detail = "provider fetch; algorithm unresolved" if not _arg(1) else f"fetch {_arg(1)}; algorithm unresolved"
    elif parser in ("go-curve", "go-ecdh-curve", "dotnet-curve"):
        token = _arg(0) if parser != "go-ecdh-curve" else call_name
        curve = CURVE_ALIASES.get(token)
        if curve is None:
            inner = re.search(r"P(256|384|521)", token)
            if inner:
                curve = f"P-{inner.group(1)}"
        if parser == "go-ecdh-curve":
            # Operation-correct primitive: X25519 is its own canonical
            # family (not generic ECDH); P-curves stay ECDH + curve.
            if "X25519" in token:
                canonical = "X25519"
            elif "X448" in token:
                canonical = "X448"
    elif parser == "ossl-pkey-type":
        # Raw PKEY constructors carry the key type as the first argument
        # (EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, ...)). Resolve it
        # through a fixed table; anything else stays the row-default
        # OpenSSL capability (never guessed).
        token = _arg(0)
        hit = _PKEY_TYPE_TABLE.get(token)
        if hit is not None:
            canonical = hit
            detail = f"pkey type {token}"
    elif parser == "ossl-cipher-encflag":
        # EVP_CipherInit_ex direction flag is the 6th argument (1/0);
        # anything else keeps the row-default ENCRYPT.
        flag = _arg(5)
        if flag == "0":
            op = "DECRYPT"
            detail = "cipher init (decrypt)"
        elif flag == "1":
            op = "ENCRYPT"
            detail = "cipher init (encrypt)"
    elif parser == "ossl-digest-arg":
        # X509_digest(cert, EVP_sha256(), ...): the digest comes from
        # the second argument; unresolvable stays the row-default X.509
        # (a cert digest of unknown type, never a guessed hash).
        token = _arg(1)
        mapped = _name_to_canonical(token) if token else None
        if mapped:
            canonical = mapped
            detail = f"cert digest {mapped}"
    elif parser in ("rust-aesgcm", "rust-bits", "rust-curve-hint"):
        if parser == "rust-aesgcm":
            if "128" in call_name:
                canonical, key_size = "AES-128-GCM", 128
            else:
                canonical, key_size = "AES-256-GCM", 256
            mode = "GCM"
        elif parser == "rust-bits":
            match = re.search(r"(\d{3,4})", args)
            if match and int(match.group(1)) in (1024, 2048, 3072, 4096):
                key_size = int(match.group(1))
        elif parser == "rust-curve-hint":
            curve = "P-256"
    return {"canonical": canonical or "OpenSSL", "key_size": key_size,
            "mode": mode, "curve": curve, "protocol": protocol,
            "padding": padding, "detail": detail, "confidence": confidence,
            "op": op}


def _webcrypto_verb(call_name: str) -> str:
    match = re.search(r"\.(encrypt|decrypt|sign|verify)\s*\(", call_name)
    return match.group(1) if match else ""


_HASH_NAMES = {
    "SHA256": "SHA-256", "SHA224": "SHA-224", "SHA384": "SHA-384",
    "SHA512": "SHA-512", "SHA1": "SHA-1", "MD5": "MD5",
    "SHA3-256": "SHA-3-256", "SHA3-512": "SHA-3-512",
    "SHA512/224": "SHA-512/224", "SHA512/256": "SHA-512/256",
}


def _name_to_canonical(literal: str) -> str | None:
    """Map a bare algorithm string to a canonical name (or None)."""
    if not literal:
        return None
    upper = literal.upper().replace("-", "").replace("_", "")
    table = {
        "AES": "AES", "AESGCM": "AES", "AES256GCM": "AES-256-GCM",
        "CHACHA20POLY1305": "ChaCha20-Poly1305", "CHACHA20": "ChaCha20",
        "RSA": "RSA", "ECDSA": "ECDSA", "ECDH": "ECDH", "DH": "DH",
        "DSA": "DSA", "ED25519": "Ed25519", "X25519": "X25519",
        "HMAC": "HMAC", "HMACSHA256": "HMAC", "HMACSHA512": "HMAC",
        "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
        "SHA1": "SHA-1", "MD5": "MD5", "SHA32256": "SHA-3-256",
        "PBKDF2": "PBKDF2", "PBKDF2WITHHMACSHA256": "PBKDF2",
        "HKDF": "HKDF", "SCRYPT": "scrypt", "BCRYPT": "bcrypt",
        "ARGON2": "Argon2", "TLS": "TLS", "TLSV12": "TLS1.2",
        "TLSV13": "TLS1.3", "TLSV1": "TLS1.0", "SSL": "TLS",
        "KYBER": "ML-KEM", "MLKEM": "ML-KEM", "DILITHIUM": "ML-DSA",
        "MLDSA": "ML-DSA",
    }
    if upper in table:
        return table[upper]
    for key, value in sorted(table.items(), key=lambda kv: -len(kv[0])):
        if key and key in upper:
            return value
    return _HASH_NAMES.get(literal.upper().replace("_", "-"), None)


@dataclass
class FileAnalysis:
    """Everything the router needs from one analyzed file."""

    language: str
    classification: str
    calls: list[CallSite] = field(default_factory=list)
    constants: dict[str, str] = field(default_factory=dict)
    suppressed_noise: int = 0
    lines: list[str] = field(default_factory=list)
