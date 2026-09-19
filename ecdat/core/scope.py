"""Phase 6: scope + build-state classification (Person-1).

Stdlib-only, pure, deterministic. Path-based hints with stronger
evidence override (syntax facts > manifest info > build membership >
path). Never raises on odd input; unknown maps to UNKNOWN.
"""

from __future__ import annotations

from pathlib import PurePosixPath

__all__ = [
    "SCOPES",
    "BUILD_STATES",
    "classify_scope",
    "classify_build_state",
]

SCOPES = (
    "APPLICATION",
    "LIBRARY_IMPLEMENTATION",
    "TEST",
    "FIXTURE",
    "BENCHMARK",
    "DEMO",
    "EXAMPLE",
    "DOCUMENTATION",
    "GENERATED",
    "VENDOR",
    "BUILD",
    "CONFIG",
    "DEPENDENCY",
    "BINARY",
    "CERTIFICATE_ASSET",
    "UNKNOWN",
)

BUILD_STATES = (
    "DEFAULT_ENABLED",
    "ENABLED",
    "DISABLED",
    "CONDITIONAL",
    "SUPPORTED",
    "UNKNOWN",
)

_SCOPE_SET = frozenset(SCOPES)
_BUILD_SET = frozenset(BUILD_STATES)

# -- path vocab -----------------------------------------------------------

_TEST_DIRS = {"test", "tests", "testing", "testsuite", "__tests__", "spec", "specs"}
_FIXTURE_DIRS = {
    "fixture", "fixtures", "fakes", "fake", "mocks", "mock", "stubs", "stub",
    "testdata", "test-data", "test_data", "__fixtures__", "__mocks__",
    "snapshots", "__snapshots__",
}
_BENCH_DIRS = {"benchmark", "benchmarks", "bench", "perfs", "perf"}
_DEMO_DIRS = {"demo", "demos"}
_EXAMPLE_DIRS = {"example", "examples", "sample", "samples"}
_DOC_DIRS = {"doc", "docs", "documentation", "wiki", "manual", "man"}
_GENERATED_DIRS = {"generated", "gen", "__generated__", "codegen"}
_VENDOR_DIRS = {
    "vendor", "third_party", "thirdparty", "node_modules", ".venv", "venv",
    "env", ".tox", "site-packages", "dist-packages",
}
_BUILD_DIRS = {"build", "dist", "target", "out", "artifacts", "obj", "bin-obj"}
_CONFIG_DIRS = {"config", "configs", "conf", "settings", "etc"}
_LIB_DIRS = {"lib", "libs", "library", "libraries", "pkg", "packages"}

_BINARY_SUFFIXES = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".lib",
    ".class", ".pyc", ".pyo", ".wasm",
})
_CERT_SUFFIXES = frozenset({
    ".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".p8", ".pub",
})
_CERT_DIR_HINTS = {"certs", "cert", "certificates", "pki", "keys", "key", "tls", "ssl"}
_CONFIG_SUFFIXES = frozenset({
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".env",
})
_DOC_SUFFIXES = frozenset({".md", ".rst", ".adoc"})
_SOURCE_SUFFIXES = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs",
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".cs", ".rb",
    ".php", ".swift", ".kt", ".kts", ".scala", ".m", ".mm",
})
_BUILD_FILENAMES = frozenset({
    "makefile", "cmakelists.txt", "build.bazel", "workspace",
    "meson.build", "build.gradle", "build.xml", "makefile.am",
})
_CONFIG_FILENAMES = frozenset({
    "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".editorconfig", ".gitignore", ".gitattributes",
})
_MANIFEST_FILENAMES = frozenset({
    "package-lock.json", "poetry.lock", "gemfile.lock", "cargo.lock",
    "pnpm-lock.yaml", "composer.lock", "go.sum",
})

# Stronger-evidence flag -> scope, checked in this order (first hit wins).
# FIXTURE precedes TEST so fixtures living under tests/ stay fixtures.
_FLAG_SCOPE_ORDER: tuple[tuple[str, tuple[str, ...]], str] = (
    (("is_binary", "binary"), "BINARY"),
    (("is_certificate", "is_cert", "is_certificate_asset"), "CERTIFICATE_ASSET"),
    (("is_generated", "generated", "auto_generated"), "GENERATED"),
    (("is_vendor", "vendor", "vendored"), "VENDOR"),
    (("is_dependency", "dependency", "dependency_only"), "DEPENDENCY"),
    (("is_fixture", "fixture", "is_test_fixture", "test_fixture"), "FIXTURE"),
    (("is_benchmark", "benchmark"), "BENCHMARK"),
    (("is_demo", "demo"), "DEMO"),
    (("is_example", "example"), "EXAMPLE"),
    (("is_test", "test"), "TEST"),
    (("is_documentation", "documentation", "is_doc"), "DOCUMENTATION"),
    (("is_build", "build"), "BUILD"),
    (("is_config", "config"), "CONFIG"),
    (("is_library", "is_library_implementation", "library_implementation"), "LIBRARY_IMPLEMENTATION"),
    (("is_application", "application"), "APPLICATION"),
)


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _norm_scope(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip().upper().replace("-", "_").replace(" ", "_").replace("/", "_")
    return text if text in _SCOPE_SET else None


def _explicit_scope(*dicts: dict) -> str | None:
    """Explicit ``scope`` key in stronger-evidence dicts (first hit wins)."""
    for mapping in dicts:
        if not isinstance(mapping, dict):
            continue
        for key in ("scope", "role", "source_role", "evidence_scope"):
            hit = _norm_scope(mapping.get(key))
            if hit is not None:
                return hit
    return None


def _flag_scope(*dicts: dict) -> str | None:
    for mapping in dicts:
        if not isinstance(mapping, dict):
            continue
        lowered = {str(k).strip().lower(): v for k, v in mapping.items()}
        for aliases, scope in _FLAG_SCOPE_ORDER:
            for alias in aliases:
                if lowered.get(alias) is True:
                    return scope
    return None


def _path_parts(path) -> tuple[list[str], str, str]:
    """Return (dir parts lower, filename lower, suffix lower)."""
    if path is None:
        return [], "", ""
    text = str(path).replace("\\", "/").strip()
    if not text:
        return [], "", ""
    posix = PurePosixPath(text)
    parts = [p.lower() for p in posix.parts[:-1]]
    filename = posix.name.lower()
    suffix = posix.suffix.lower()
    # Strip drive-letter pseudo-part (``c:``) from windows paths.
    parts = [p for p in parts if p not in ("c:", "d:")]
    return parts, filename, suffix


def _path_hint(path, language=None) -> str | None:
    parts, filename, suffix = _path_parts(path)
    part_set = set(parts)
    stem = filename.rsplit(".", 1)[0] if "." in filename else filename
    lang = str(language or "").strip().lower()

    if lang in ("binary", "bytecode", "native", "executable"):
        return "BINARY"
    if lang in ("certificate", "cert", "x.509", "x509", "pem", "key-material"):
        return "CERTIFICATE_ASSET"

    # Extension-strong signals first (binary / cert assets).
    if suffix in _BINARY_SUFFIXES:
        return "BINARY"
    if suffix == ".key":
        # ``*.key`` is usually key material; ssh/config keys still assets.
        return "CERTIFICATE_ASSET"
    if suffix in _CERT_SUFFIXES:
        return "CERTIFICATE_ASSET"
    if part_set & _CERT_DIR_HINTS and suffix in _CERT_SUFFIXES | {".key", ".txt", ".json"}:
        return "CERTIFICATE_ASSET"

    if filename in _MANIFEST_FILENAMES or filename in (
        "package-lock.json", "yarn.lock",
    ):
        return "DEPENDENCY"
    if part_set & _VENDOR_DIRS:
        return "VENDOR"
    if part_set & _FIXTURE_DIRS:
        return "FIXTURE"
    if part_set & _BENCH_DIRS:
        return "BENCHMARK"
    if part_set & _DEMO_DIRS:
        return "DEMO"
    if part_set & _EXAMPLE_DIRS:
        return "EXAMPLE"
    if part_set & _TEST_DIRS:
        return "TEST"
    if part_set & _GENERATED_DIRS:
        return "GENERATED"
    generated_markers = (".generated.", "_generated", ".pb.", "_pb2",
                         "_grpc", ".designer.", ".g.")
    if any(m in filename for m in generated_markers):
        return "GENERATED"
    if part_set & _DOC_DIRS:
        return "DOCUMENTATION"
    if suffix in _DOC_SUFFIXES:
        return "DOCUMENTATION"
    if filename.startswith(("readme", "changelog", "changes", "license", "licence")):
        return "DOCUMENTATION"
    if filename in _BUILD_FILENAMES or filename.endswith((".mk", ".cmake")):
        return "BUILD"
    if part_set & _BUILD_DIRS:
        return "BUILD"
    if filename in _CONFIG_FILENAMES:
        return "CONFIG"
    # Manifest / lock-ish roots are config-ish only when not dependency pins.
    if filename in ("package.json", "pyproject.toml", "cargo.toml",
                    "go.mod", "pom.xml", "build.gradle.kts"):
        return "CONFIG"
    if suffix in _CONFIG_SUFFIXES:
        # Plain data blobs next to certs were handled above; rest is config.
        return "CONFIG"
    if part_set & _CONFIG_DIRS:
        return "CONFIG"

    # Test-ish filenames even outside test dirs.
    import re as _re

    if (stem.startswith("test_") or stem.endswith(("_test", "-test", ".test"))
            or bool(_re.search(r"(^|[_\-.])tests?([_\-.]|$)", stem))):
        return "TEST"
    if filename == "conftest.py":
        return "FIXTURE"
    if part_set & _LIB_DIRS:
        return "LIBRARY_IMPLEMENTATION"
    if suffix in _SOURCE_SUFFIXES:
        return "APPLICATION"
    if suffix:
        # Recognised-but-unlisted suffix with no other hint: unknown, not app.
        return None
    # Bare filename with no suffix inside source-ish tree -> application.
    if filename:
        return "APPLICATION"
    return None


def classify_scope(path=None, language=None, build_membership=None,
                   manifest_info=None, syntax_facts=None) -> str:
    """Classify evidence scope. Pure + deterministic.

    Args:
        path: file path (str/Path-like) or None.
        language: language/ecosystem label (e.g. ``"python"``,
            ``"binary"``, ``"certificate"``) or None.
        build_membership: mapping with optional ``scope``/flag keys.
        manifest_info: mapping with optional ``scope``/flag keys.
        syntax_facts: mapping with optional ``scope``/flag keys.

    Returns:
        One of :data:`SCOPES`. Path gives the base hint; explicit
        ``scope`` or boolean flags in ``syntax_facts`` >
        ``manifest_info`` > ``build_membership`` override it.
    """
    syntax = _as_dict(syntax_facts)
    manifest = _as_dict(manifest_info)
    membership = _as_dict(build_membership)

    override = _explicit_scope(syntax, manifest, membership)
    if override is not None:
        return override
    flagged = _flag_scope(syntax, manifest, membership)
    if flagged is not None:
        return flagged
    hint = _path_hint(path, language)
    if hint is not None:
        return hint
    # Language-only fallback: known source languages imply application.
    if str(language or "").strip().lower() in (
        "python", "javascript", "typescript", "java", "go", "rust",
        "c", "c++", "c#", "ruby", "php", "swift", "kotlin",
    ):
        return "APPLICATION"
    return "UNKNOWN"


def _norm_build(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip().upper().replace("-", "_").replace(" ", "_")
    return text if text in _BUILD_SET else None


def _explicit_build(*dicts: dict) -> str | None:
    for mapping in dicts:
        if not isinstance(mapping, dict):
            continue
        for key in ("build_state", "build", "membership", "inclusion"):
            hit = _norm_build(mapping.get(key))
            if hit is not None:
                return hit
    return None


def _evidence_build(syntax: dict, manifest: dict, membership: dict) -> str | None:
    """Stronger-evidence build-state signals (syntax > manifest > membership)."""
    for mapping in (syntax, manifest, membership):
        if not isinstance(mapping, dict):
            continue
        lowered = {str(k).strip().lower(): v for k, v in mapping.items()}
        if lowered.get("excluded") is True or lowered.get("in_build") is False:
            return "DISABLED"
        if lowered.get("enabled") is False or lowered.get("disabled") is True:
            return "DISABLED"
        if lowered.get("undef") or lowered.get("undefined_macro"):
            return "DISABLED"
        cond_keys = ("conditional", "condition", "ifdef", "ifndef",
                     "if_condition", "preprocessor_condition", "requires_flag",
                     "cmake_option", "makefile_flag", "compile_flag", "-d",
                     "feature_flag", "cfg_flag")
        for key in cond_keys:
            if lowered.get(key):
                return "CONDITIONAL"
        if lowered.get("supported") is True and lowered.get("enabled") is not True:
            return "SUPPORTED"
        if lowered.get("optional") is True and lowered.get("enabled") is not True:
            return "SUPPORTED"
        if lowered.get("enabled") is True:
            if lowered.get("default") is True or lowered.get("by_default") is True:
                return "DEFAULT_ENABLED"
            return "ENABLED"
        if lowered.get("in_build") is True:
            return "ENABLED"
    return None


def classify_build_state(path=None, build_membership=None, manifest_info=None,
                         syntax_facts=None, language=None) -> str:
    """Classify build inclusion state. Pure + deterministic.

    Explicit ``build_state`` or membership/flag evidence wins; otherwise
    deployment source defaults to ``DEFAULT_ENABLED``, non-deployment
    scopes (test/fixture/demo/docs/...) map to ``SUPPORTED``, and
    unresolvable input maps to ``UNKNOWN``.
    """
    syntax = _as_dict(syntax_facts)
    manifest = _as_dict(manifest_info)
    membership = _as_dict(build_membership)

    explicit = _explicit_build(syntax, manifest, membership)
    if explicit is not None:
        return explicit
    evidenced = _evidence_build(syntax, manifest, membership)
    if evidenced is not None:
        return evidenced
    scope = classify_scope(path, language, membership, manifest, syntax)
    if scope in ("APPLICATION", "LIBRARY_IMPLEMENTATION"):
        return "DEFAULT_ENABLED"
    if scope in ("BUILD", "CONFIG"):
        return "ENABLED"
    if scope in ("TEST", "FIXTURE", "BENCHMARK", "DEMO", "EXAMPLE",
                 "DOCUMENTATION", "GENERATED", "VENDOR", "DEPENDENCY",
                 "BINARY", "CERTIFICATE_ASSET"):
        return "SUPPORTED"
    return "UNKNOWN"
