"""Phase 2: syntax facts for source scanners (additive, stdlib-only).

Neutral fact layer over Python (AST) and brace languages (C/C++/Java/JS/
Go/C#/Rust via the shared masking tokenizer in
:mod:`ecdat.scanners.source.c_parser`).

Existing scanners are untouched; this module only *reads* source and emits
:class:`SourceFact` rows that later stages (resolver, fingerprints,
knowledge) can consume.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "FACT_KINDS",
    "SourceFact",
    "extract_facts_python",
    "extract_facts_brace",
    "extract_facts",
    "get_cached_facts",
    "clear_fact_cache",
]

#: Closed fact vocabulary (Phase 2 contract).
FACT_KINDS = frozenset({
    "function_definition",
    "function_declaration",
    "function_call",
    "import",
    "include",
    "assignment",
    "constant",
    "macro",
    "array_constant",
    "string_literal",
    "type_reference",
    "return",
})

_BRACE_LANGS = {"c", "cpp", "java", "js", "go", "csharp", "rust"}

_SUFFIX_TO_LANG = {
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

_INCLUDE_RE = re.compile(
    r'^\s*#\s*include\s*[<"]([^>"]+)[>"]|'
    r'^\s*(?:import|from)\s+([A-Za-z_][\w\.]*)|'
    r'^\s*import\s+["\']([^"\']+)["\']|'
    r'^\s*use\s+([A-Za-z_][\w:]*)\s*;',
    re.MULTILINE,
)
_DEFINE_RE = re.compile(r'^\s*#\s*define\s+([A-Za-z_]\w*)(?:\s+(.*?))?\s*$', re.MULTILINE)
_PROTO_RE = re.compile(
    r"^\s*(?:[\w:\<\>\*]+\s+)+[\*\&]?\s*([A-Za-z_]\w*)\s*\([^;{}]*\)\s*;\s*$")
_RETURN_RE = re.compile(r"^\s*return\b(.*)$")
_STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'')
_ARRAY_INIT_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)?=\s*(\{[^;]{1,400}?\}|new\s+\w+[^\n;]{1,200})")
_TYPE_HINT_RE = re.compile(
    r"\b(EVP_CIPHER|EVP_MD|EVP_PKEY|RSA|DSA|DH|EC_KEY|EC_GROUP|AES_KEY|"
    r"HMAC_CTX|BIGNUM|SSL_CTX|SSL|X509|Cipher|MessageDigest|Mac|"
    r"KeyPairGenerator|Signature|SecretKeyFactory|SSLContext)\b")
_INT_RE = re.compile(r"^-?\d+$")
_IDENT_RE = re.compile(r"^[A-Za-z_]\w*$")


@dataclass
class SourceFact:
    """One syntactic observation (Phase 2 fact)."""

    kind: str
    language: str
    name: str
    file: str
    line: int
    column: int = 0
    function: str | None = None
    arguments: tuple = field(default_factory=tuple)
    value: str | int | float | bool | None = None
    type_name: str | None = None
    metadata: dict = field(default_factory=dict)


def _render(node: ast.AST | None) -> str | int | float | bool | None:
    """Best-effort literal rendering; None when not a plain literal."""
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(
            node.value, (str, int, float, bool, type(None))):
        return node.value
    try:  # py3.9+: structural rendering for non-literals (names, calls)
        text = ast.unparse(node).strip()  # type: ignore[attr-defined]
        return text[:200] if text else None
    except Exception:
        return None


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    cur: ast.AST | None = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    parts.reverse()
    return ".".join(parts) if parts else ""


class _PythonFactVisitor(ast.NodeVisitor):
    def __init__(self, file: str) -> None:
        self.file = file
        self.facts: list[SourceFact] = []
        self.current_function: str | None = None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.facts.append(SourceFact(
                kind="import", language="py", name=alias.asname or alias.name,
                file=self.file, line=node.lineno, column=node.col_offset,
                metadata={"module": alias.name,
                           "asname": alias.asname or alias.name}))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            full = f"{module}.{alias.name}" if module else alias.name
            self.facts.append(SourceFact(
                kind="import", language="py",
                name=alias.asname or alias.name,
                file=self.file, line=node.lineno, column=node.col_offset,
                metadata={"module": module, "full": full,
                           "asname": alias.asname or alias.name}))
        self.generic_visit(node)

    def _visit_def(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        params = [a.arg for a in node.args.args]
        self.facts.append(SourceFact(
            kind="function_definition", language="py", name=node.name,
            file=self.file, line=node.lineno, column=node.col_offset,
            arguments=tuple(params),
            metadata={"async": isinstance(node, ast.AsyncFunctionDef)}))
        for arg in node.args.args:
            if arg.annotation is not None:
                self.facts.append(SourceFact(
                    kind="type_reference", language="py",
                    name=_render(arg.annotation) or "",
                    file=self.file, line=node.lineno,
                    column=node.col_offset, function=node.name,
                    metadata={"param": arg.arg}))
        old, self.current_function = self.current_function, node.name
        self.generic_visit(node)
        self.current_function = old

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_def(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_def(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for base in node.bases:
            self.facts.append(SourceFact(
                kind="type_reference", language="py", name=_dotted(base),
                file=self.file, line=node.lineno, column=node.col_offset,
                metadata={"class": node.name}))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = ""
        if isinstance(node.func, (ast.Name, ast.Attribute)):
            name = _dotted(node.func)
        if name:
            arg_vals = [_render(a) for a in node.args]
            arg_vals += [_render(k.value) for k in node.keywords]
            args = tuple(arg_vals)
            self.facts.append(SourceFact(
                kind="function_call", language="py", name=name,
                file=self.file, line=node.lineno, column=node.col_offset,
                function=self.current_function, arguments=args))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        value = _render(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.facts.append(SourceFact(
                    kind="assignment", language="py", name=target.id,
                    file=self.file, line=node.lineno,
                    column=node.col_offset,
                    function=self.current_function, value=value))
                if isinstance(node.value, ast.Constant):
                    self.facts.append(SourceFact(
                        kind="constant", language="py", name=target.id,
                        file=self.file, line=node.lineno,
                        column=node.col_offset,
                        function=self.current_function, value=value))
                if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                    self.facts.append(SourceFact(
                        kind="array_constant", language="py", name=target.id,
                        file=self.file, line=node.lineno,
                        column=node.col_offset,
                        function=self.current_function, value=value,
                        metadata={"size": len(node.value.elts)}))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name):
            value = _render(node.value)
            ann = _render(node.annotation)
            self.facts.append(SourceFact(
                kind="assignment", language="py", name=node.target.id,
                file=self.file, line=node.lineno, column=node.col_offset,
                function=self.current_function, value=value,
                type_name=str(ann) if ann else None))
            self.facts.append(SourceFact(
                kind="type_reference", language="py", name=str(ann or ""),
                file=self.file, line=node.lineno, column=node.col_offset,
                function=self.current_function))
            if isinstance(node.value, ast.Constant):
                self.facts.append(SourceFact(
                    kind="constant", language="py", name=node.target.id,
                    file=self.file, line=node.lineno,
                    column=node.col_offset,
                    function=self.current_function, value=value))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            self.facts.append(SourceFact(
                kind="string_literal", language="py", name="",
                file=self.file, line=node.lineno, column=node.col_offset,
                function=self.current_function, value=node.value[:500]))
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        self.facts.append(SourceFact(
            kind="return", language="py", name="",
            file=self.file, line=node.lineno, column=node.col_offset,
            function=self.current_function, value=_render(node.value)))
        self.generic_visit(node)


def extract_facts_python(source: str, file: str = "<memory>") -> list[SourceFact]:
    """Extract Phase 2 facts from Python source (AST; empty on syntax error)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    visitor = _PythonFactVisitor(file)
    visitor.visit(tree)
    return visitor.facts


def extract_facts_brace(source: str, file: str = "<memory>",
                         lang: str = "c") -> list[SourceFact]:
    """Extract Phase 2 facts from a brace language via the masking tokenizer."""
    lang = (lang or "c").lower()
    if lang not in _BRACE_LANGS:
        lang = "c"
    facts: list[SourceFact] = []
    lines = source.splitlines()

    try:
        from ecdat.scanners.source import c_parser as _cp
        masked, _ = _cp.mask_source(source)
        sites = _cp.extract_calls(masked)
        consts = _cp.collect_constants(masked)
        try:
            spans = _cp._function_spans(masked)  # internal but stable
        except Exception:
            spans = []
    except Exception:
        masked, sites, consts, spans = source, [], {}, []

    for start, end, fname in spans:
        line = masked.count("\n", 0, start) + 1
        facts.append(SourceFact(
            kind="function_definition", language=lang, name=fname,
            file=file, line=line, metadata={"span": (start, end)}))
    seen_defs = {f.name for f in facts if f.kind == "function_definition"}
    # Fallback for single-line definitions (``int main() { ... }``) which the
    # brace-depth span tracker skips (candidate ends with ``}``, not ``{``).
    _SINGLE_LINE_DEF_RE = re.compile(
        r"^\s*(?:[\w:\<\>\*]+\s+)+[\*\&]?\s*([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{")
    _CTL_RE = re.compile(r"\b(?:if|for|while|switch|catch|return|sizeof)\b")
    for idx, line_text in enumerate(masked.splitlines(), 1):
        match = _SINGLE_LINE_DEF_RE.match(line_text)
        if match and not _CTL_RE.search(line_text.split("(")[0]):
            if match.group(1) not in seen_defs:
                facts.append(SourceFact(
                    kind="function_definition", language=lang,
                    name=match.group(1), file=file, line=idx,
                    metadata={"via": "single-line-fallback"}))
                seen_defs.add(match.group(1))

    for idx, line_text in enumerate(lines, 1):
        stripped = line_text.strip()
        if not stripped:
            continue
        proto = _PROTO_RE.match(stripped)
        if proto and "(" in stripped and stripped.endswith(";"):
            facts.append(SourceFact(
                kind="function_declaration", language=lang,
                name=proto.group(1), file=file, line=idx))
        for match in _INCLUDE_RE.finditer(line_text):
            inc = next((g for g in match.groups() if g), "")
            if inc:
                facts.append(SourceFact(
                    kind="include", language=lang, name=inc.strip(),
                    file=file, line=idx))
                facts.append(SourceFact(
                    kind="import", language=lang, name=inc.strip(),
                    file=file, line=idx,
                    metadata={"via": "include"}))
        for match in _DEFINE_RE.finditer(line_text + "\n"):
            macro, body = match.group(1), (match.group(2) or "").strip()
            facts.append(SourceFact(
                kind="macro", language=lang, name=macro, file=file,
                line=idx, value=body[:200] if body else None))
            if body:
                facts.append(SourceFact(
                    kind="constant", language=lang, name=macro, file=file,
                    line=idx, value=body[:200]))
        ret = _RETURN_RE.match(line_text)
        if ret:
            facts.append(SourceFact(
                kind="return", language=lang, name="", file=file, line=idx,
                value=ret.group(1).strip()[:200] or None))
        for match in _STRING_RE.finditer(line_text):
            literal = match.group(1) if match.group(1) is not None else match.group(2)
            facts.append(SourceFact(
                kind="string_literal", language=lang, name="", file=file,
                line=idx, column=match.start(), value=literal or ""))
        arr = _ARRAY_INIT_RE.search(line_text)
        if arr:
            facts.append(SourceFact(
                kind="array_constant", language=lang, name=arr.group(1),
                file=file, line=idx, value=arr.group(2)[:200]))
        for match in _TYPE_HINT_RE.finditer(line_text):
            facts.append(SourceFact(
                kind="type_reference", language=lang, name=match.group(1),
                file=file, line=idx, column=match.start()))

    for site in sites:
        facts.append(SourceFact(
            kind="function_call", language=lang, name=site.name,
            file=file, line=site.line, column=0, function=site.function,
            arguments=tuple(_split_top_level(site.args)),
            metadata={"call_text": site.call_text}))
    for cname, cval in consts.items():
        facts.append(SourceFact(
            kind="assignment", language=lang, name=cname, file=file, line=0,
            value=cval[:200] if isinstance(cval, str) else cval))
        facts.append(SourceFact(
            kind="constant", language=lang, name=cname, file=file, line=0,
            value=cval[:200] if isinstance(cval, str) else cval))
    return facts


def _split_top_level(args: str) -> list:
    try:
        from ecdat.scanners.source import c_parser as _cp
        return _cp.split_args(args)
    except Exception:
        return [p.strip() for p in args.split(",") if p.strip()]


def extract_facts(path: str | Path) -> list[SourceFact]:
    """Dispatch by suffix with graceful fallback (never raises on read)."""
    path = Path(path)
    lang = _SUFFIX_TO_LANG.get(path.suffix.lower(), "")
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    fname = str(path)
    if lang == "py":
        facts = extract_facts_python(source, fname)
        if not facts:  # syntax error fallback: brace-style call scan
            facts = extract_facts_brace(source, fname, "c")
        return facts
    if lang:
        return extract_facts_brace(source, fname, lang)
    # Unknown suffix: try Python, fall back to brace scan.
    facts = extract_facts_python(source, fname)
    return facts or extract_facts_brace(source, fname, "c")


_FACT_CACHE: dict[str, tuple[str, list[SourceFact]]] = {}


def get_cached_facts(path: str | Path) -> list[SourceFact]:
    """Content-hash fact cache: same bytes -> same fact list object."""
    key = str(path)
    try:
        raw = Path(path).read_bytes()
    except Exception:
        return []
    digest = hashlib.sha256(raw).hexdigest()
    hit = _FACT_CACHE.get(key)
    if hit is not None and hit[0] == digest:
        return hit[1]
    facts = extract_facts(path)
    _FACT_CACHE[key] = (digest, facts)
    return facts


def clear_fact_cache() -> None:
    """Test helper: drop all cached fact rows."""
    _FACT_CACHE.clear()
