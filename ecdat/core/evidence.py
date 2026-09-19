"""Phase 4 evidence taxonomy (stdlib only, no LLM).

Classifies every detector signal into an *evidence class* (what kind of
observation is this?) and derives a *semantic state* (how far along the
reference -> invocation lifecycle is this crypto use?) from the fused
``usage_state`` plus the observed evidence classes.

Unknown tool strings are never guessed at: they fall back to
:data:`EvidenceClass.REFERENCE`, the weakest claim.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

__all__ = [
    "EvidenceClass",
    "SemanticState",
    "Relationship",
    "classify_evidence",
    "semantic_state_for",
]


class EvidenceClass(str, Enum):
    """What kind of observation a detector signal represents."""

    REFERENCE = "reference"  # string/pattern mention, unknown tooling
    DECLARATION = "declaration"  # import/include/require of crypto API
    IMPLEMENTATION = "implementation"  # def-body / binary implementation
    REGISTRATION = "registration"  # cloud inventory / service registration
    CONFIGURATION = "configuration"  # config file / docker / env claim
    INVOCATION = "invocation"  # direct API call / live handshake observed
    ASSET = "asset"  # certificate / secret / key material on disk
    DEPENDENCY = "dependency"  # SBOM / package capability, no direct use
    BINARY_SIGNATURE = "binary-signature"  # lief/capa/yara/strings match


class SemanticState(str, Enum):
    """Lifecycle state of a crypto operation, weakest -> strongest."""

    REFERENCED = "referenced"
    DECLARED = "declared"
    SUPPORTED = "supported"
    IMPLEMENTED = "implemented"
    REGISTERED = "registered"
    ENABLED = "enabled"
    CONFIGURED = "configured"
    INVOKED = "invoked"
    PROBABLE = "probable"
    CONFIRMED = "confirmed"


class Relationship(str, Enum):
    """Semantic edge vocabulary between crypto entities."""

    IMPLEMENTS = "implements"
    PROVIDES = "provides"
    USES = "uses"
    CONFIGURES = "configures"
    REGISTERS = "registers"
    INVOKES = "invokes"
    CONTAINS = "contains"
    DEPENDS_ON = "depends_on"
    DERIVES = "derives"
    PROTECTS = "protects"


# Ordered (needle, EvidenceClass) rules evaluated against the lowercased
# tool string. Order matters: specific capability prefixes win over the
# generic container/cloud fallbacks; unknown strings fall to REFERENCE.
_INVOCATION_NEEDLES = (
    "api-call",
    "custom-invocation",
    "wrapper-call",
    "function_call",
    "function-call",
    "call_site",
    "callsite",
    "runtime-tls",
    "runtime-ssh",
    "runtime-probe",
    "runtime:",
    "sslyze",
    "semgrep",
    "source:ast",
    "source:api",
    "source:wrapper",
    "tree-sitter",
)

_BINARY_NEEDLES = (
    "binary-lief",
    "binary-capa",
    "binary-floss",
    "binary-signatures",
    "binary-strings",
    "yara",
    "capa",
    "floss",
    "lief",
)

_CONFIG_NEEDLES = (
    "config:",
    "config-",
    "config_",
    "dockerfile",
    "container-docker",
    "docker",
    "env:",
    "ini:",
    "yaml:",
    "toml:",
)

_DEPENDENCY_NEEDLES = (
    "dependency:",
    "dependency_",
    "container-syft",
    "container-trivy",
    "syft",
    "cdxgen",
    "bom-",
    "bom_",
    "bom:",
    "trivy",
    "vuln-match",
    "dependency-capability",
)

_REGISTRATION_NEEDLES = (
    "cloud-aws",
    "cloud:",
    "cloud_",
    "cloud-",
    "cloud-inventory",
    "container:",
    "service:",
    "registry:",
    "register",
)

_ASSET_NEEDLES = (
    "certificate-",
    "certificate_",
    "cert-parse",
    "cert:",
    "secret",
    "gitleaks",
    "pem",
    "private-key",
    "private_key",
    "key-material",
)

_IMPLEMENTATION_NEEDLES = (
    "function_definition",
    "function-definition",
    "source:def",
    "fingerprint",
    ":def ",
    "implement",
    "definition",
)

_DECLARATION_NEEDLES = (
    "source:import",
    ":import",
    "#include",
    "include:",
    "import:",
    "require(",
    "require:",
    "declare",
    "declaration",
)


def _norm_tool(tool: Any) -> str:
    try:
        return str(tool or "").strip().lower()
    except Exception:
        return ""


def classify_evidence(tool_string: Any) -> EvidenceClass:
    """Map a detector tool string to its :class:`EvidenceClass`.

    Never raises and never guesses: anything unrecognised (including
    ``None``/empty/non-string input) maps to
    :data:`EvidenceClass.REFERENCE`.
    """
    text = _norm_tool(tool_string)
    if not text:
        return EvidenceClass.REFERENCE
    # Bare fusion-detector names (build_operations evidence carries
    # ``detector`` rather than full tool strings).
    _bare_invocation = {"source", "semgrep", "tree-sitter", "runtime", "sslyze"}
    _bare_dependency = {"syft", "bom", "dependency", "container"}
    _bare_config = {"config", "dockerfile"}
    _bare_binary = {"lief", "capa", "strings", "yara-x", "binary", "yara"}
    _bare_asset = {"secret", "gitleaks", "certificate"}
    if text in _bare_invocation:
        return EvidenceClass.INVOCATION
    if text in _bare_dependency:
        return EvidenceClass.DEPENDENCY
    if text in _bare_config:
        return EvidenceClass.CONFIGURATION
    if text in _bare_binary:
        return EvidenceClass.BINARY_SIGNATURE
    if text in _bare_asset:
        return EvidenceClass.ASSET
    for needle in _ASSET_NEEDLES:
        if needle in text:
            return EvidenceClass.ASSET
    for needle in _DEPENDENCY_NEEDLES:
        if needle in text:
            return EvidenceClass.DEPENDENCY
    for needle in _INVOCATION_NEEDLES:
        if needle in text:
            return EvidenceClass.INVOCATION
    for needle in _BINARY_NEEDLES:
        if needle in text:
            return EvidenceClass.BINARY_SIGNATURE
    for needle in _CONFIG_NEEDLES:
        if needle in text:
            return EvidenceClass.CONFIGURATION
    for needle in _REGISTRATION_NEEDLES:
        if needle in text:
            return EvidenceClass.REGISTRATION
    for needle in _IMPLEMENTATION_NEEDLES:
        if needle in text:
            return EvidenceClass.IMPLEMENTATION
    for needle in _DECLARATION_NEEDLES:
        if needle in text:
            return EvidenceClass.DECLARATION
    return EvidenceClass.REFERENCE


# Lifecycle rank for evidence classes (higher = stronger lifecycle claim).
_LIFECYCLE_RANK: dict[EvidenceClass, int] = {
    EvidenceClass.REFERENCE: 0,
    EvidenceClass.DECLARATION: 1,
    EvidenceClass.DEPENDENCY: 2,
    EvidenceClass.ASSET: 2,
    EvidenceClass.IMPLEMENTATION: 3,
    EvidenceClass.BINARY_SIGNATURE: 3,
    EvidenceClass.REGISTRATION: 4,
    EvidenceClass.CONFIGURATION: 6,
    EvidenceClass.INVOCATION: 7,
}

_RANK_STATE: dict[int, SemanticState] = {
    0: SemanticState.REFERENCED,
    1: SemanticState.DECLARED,
    2: SemanticState.SUPPORTED,
    3: SemanticState.IMPLEMENTED,
    4: SemanticState.REGISTERED,
    6: SemanticState.CONFIGURED,
    7: SemanticState.INVOKED,
}


def _coerce_class(item: Any) -> EvidenceClass:
    if isinstance(item, EvidenceClass):
        return item
    if isinstance(item, dict):
        for key in ("class", "evidence_class", "evidenceClass"):
            if item.get(key) is not None:
                try:
                    return EvidenceClass(str(item[key]).lower())
                except Exception:
                    pass
        tool = item.get("tool", item.get("detector", ""))
        return classify_evidence(tool)
    if isinstance(item, str):
        try:
            return EvidenceClass(item.lower())
        except Exception:
            return classify_evidence(item)
    return EvidenceClass.REFERENCE


def _norm_usage(usage_state: Any) -> str:
    try:
        value = getattr(usage_state, "value", usage_state)
        return str(value or "").strip()
    except Exception:
        return ""


def semantic_state_for(usage_state: Any, evidence_list: Any) -> SemanticState:
    """Derive the :class:`SemanticState` for a fused usage + evidence set.

    Rules (deterministic, stdlib-only):

    * ``FalsePositiveSuppressed`` -> ``REFERENCED`` (weakest claim kept).
    * ``ProvidedOnly`` -> lifecycle state capped at ``SUPPORTED``: a
      dependency-only capability never claims invocation.
    * ``Probable`` -> ``PROBABLE``.
    * ``Confirmed`` -> ``INVOKED`` when invocation evidence is present,
      else ``CONFIRMED``.
    * anything else (``Possible``/unknown/empty) -> lifecycle state from
      evidence, defaulting to ``REFERENCED`` when there is no evidence.
    """
    usage = _norm_usage(usage_state)
    items = list(evidence_list) if isinstance(evidence_list, (list, tuple)) else []
    classes = [_coerce_class(i) for i in items]

    if usage == "FalsePositiveSuppressed":
        return SemanticState.REFERENCED

    def lifecycle() -> SemanticState:
        if not classes:
            return SemanticState.REFERENCED
        rank = max(_LIFECYCLE_RANK.get(c, 0) for c in classes)
        return _RANK_STATE.get(rank, SemanticState.REFERENCED)

    if usage == "ProvidedOnly":
        life = lifecycle()
        if life in (SemanticState.INVOKED, SemanticState.CONFIGURED,
                    SemanticState.REGISTERED, SemanticState.IMPLEMENTED,
                    SemanticState.ENABLED):
            return SemanticState.SUPPORTED
        return life
    if usage == "Probable":
        return SemanticState.PROBABLE
    if usage == "Confirmed":
        if EvidenceClass.INVOCATION in classes:
            return SemanticState.INVOKED
        return SemanticState.CONFIRMED
    return lifecycle()
