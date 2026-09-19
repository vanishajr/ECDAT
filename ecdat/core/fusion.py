"""Person-1 Agent B: evidence fusion, usage adjudication, dedup, redaction.

Stdlib-only, no LLM. Fuses heterogeneous detector signals into one
calibrated confidence, maps it to a usage state, collapses duplicate
operations by exact dedup_key, and redacts secrets from snippets.
"""

from __future__ import annotations

import re

__all__ = [
    "DETECTOR_RELIABILITY",
    "DIRECT_SIGNAL_TYPES",
    "weighted_fusion",
    "decide_usage",
    "deduplicate",
    "redact_snippet",
]

# Per-detector reliability weights (stable contract, see task spec).
# Phase 8 calibration: the original eight entries are untouched; the added
# keys register ECDAT's own detector families so production evidence
# fuses through this table instead of the 0.7 default. Values mirror the
# architecture evidence table (direct source API calls and live runtime
# probes rank highest; dependency-only capability ranks lowest).
DETECTOR_RELIABILITY: dict[str, float] = {
    "semgrep": 0.9,
    "tree-sitter": 0.88,
    "lief": 0.85,
    "yara-x": 0.75,
    "capa": 0.8,
    "syft": 0.6,
    "sslyze": 0.92,
    "gitleaks": 0.85,
    "source": 0.92,
    "config": 0.85,
    "certificate": 0.85,
    "binary": 0.8,
    "strings": 0.6,
    "dependency": 0.5,
    "container": 0.6,
    "runtime": 0.92,
    "cloud": 0.75,
    "secret": 0.85,
    "dockerfile": 0.5,
    "bom": 0.5,
}

_DEFAULT_RELIABILITY = 0.7

# Signal types that count as direct-use evidence for the +0.25 term.
# Normalised comparison: lowercase, '-'/'_' unified, substring fallback.
DIRECT_SIGNAL_TYPES: frozenset[str] = frozenset(
    {
        "direct_usage",
        "direct",
        "usage",
        "call",
        "call_site",
        "dataflow",
    }
)

_USAGE_ORDER = (
    "Confirmed",
    "Probable",
    "Possible",
    "ProvidedOnly",
    "FalsePositiveSuppressed",
)


def _reliability_for(detector: str | None, override: object = None) -> float:
    if override is not None:
        try:
            v = float(override)  # type: ignore[arg-type]
            return min(1.0, max(0.0, v))
        except (TypeError, ValueError):
            pass
    if not detector:
        return _DEFAULT_RELIABILITY
    norm = str(detector).strip().lower().replace("_", "-")
    if norm in DETECTOR_RELIABILITY:
        return DETECTOR_RELIABILITY[norm]
    # Tolerate common variants: tree_sitter, yara_x, yarax, LIEF caps, etc.
    compact = norm.replace("-", "")
    for key, val in DETECTOR_RELIABILITY.items():
        if key.replace("-", "") == compact:
            return val
    return _DEFAULT_RELIABILITY


def _is_direct(signal_type: str | None) -> bool:
    if not signal_type:
        return False
    norm = str(signal_type).strip().lower().replace("-", "_")
    if norm in {s.replace("-", "_") for s in DIRECT_SIGNAL_TYPES}:
        return True
    # Substring fallback covers encrypt_call/decrypt_call/dataflow_trace, etc.
    return "direct" in norm or norm in {"usage", "call", "dataflow"}


def weighted_fusion(
    evidence: list[dict] | tuple[dict, ...] | None,
    param_resolved: bool = False,
    binary_support: bool = False,
    config_runtime_agreement: bool = False,
    dependency_only: bool = False,
) -> tuple[float, dict]:
    """Fuse detector evidence into a calibrated confidence.

    Formula (stable contract)::

        raw = 0.5 + 0.25*direct_usage + 0.10*param + 0.08*binary
              + 0.07*agreement - 0.35*dependency_penalty
        confidence = clamp(raw * reliability_mean, 0, 1)

    where ``direct_usage`` is 1.0 when any evidence entry has a direct
    signal type (else 0.0), ``param``/``binary``/``agreement`` are the
    boolean flags as 0/1, ``dependency_penalty`` is 1.0 when
    ``dependency_only`` else 0.0, and ``reliability_mean`` is the mean
    of per-evidence reliabilities (explicit ``detector_reliability``
    override else :data:`DETECTOR_RELIABILITY`, default 0.7; empty
    evidence -> 1.0 so the prior stands).

    Returns ``(confidence, breakdown)`` with the additive components,
    reliability mean, evidence/detector census for auditability.
    """
    evs: list[dict] = list(evidence) if evidence else []
    has_direct = any(_is_direct(e.get("signal_type")) for e in evs) if evs else False
    direct = 1.0 if has_direct else 0.0
    param = 1.0 if param_resolved else 0.0
    binary = 1.0 if binary_support else 0.0
    agreement = 1.0 if config_runtime_agreement else 0.0
    penalty = 1.0 if dependency_only else 0.0

    raw = 0.5 + 0.25 * direct + 0.10 * param + 0.08 * binary + 0.07 * agreement - 0.35 * penalty

    if evs:
        rels = [
            _reliability_for(e.get("detector"), e.get("detector_reliability"))
            for e in evs
        ]
        reliability_mean = sum(rels) / len(rels)
        detectors = sorted({str(e.get("detector", "unknown")) for e in evs})
        try:
            conf_mean = sum(float(e.get("confidence", 0.0)) for e in evs) / len(evs)
        except (TypeError, ValueError):
            conf_mean = 0.0
    else:
        reliability_mean = 1.0
        detectors = []
        conf_mean = 0.0

    fused = raw * reliability_mean
    confidence = min(1.0, max(0.0, fused))
    breakdown = {
        "base": 0.5,
        "direct_usage": 0.25 * direct,
        "param": 0.10 * param,
        "binary": 0.08 * binary,
        "agreement": 0.07 * agreement,
        "dependency_penalty": -0.35 * penalty,
        "raw": raw,
        "reliability_mean": reliability_mean,
        "confidence": confidence,
        "has_direct_usage": has_direct,
        "evidence_count": len(evs),
        "detectors": detectors,
        "evidence_confidence_mean": conf_mean,
    }
    return confidence, breakdown


def decide_usage(
    confidence: float,
    dependency_only: bool = False,
    is_test_fixture: bool = False,
    is_checksum_only: bool = False,
    has_direct_evidence: bool | None = None,
) -> str:
    """Adjudicate a fused confidence into a usage state.

    Priority (deterministic):
      1. ``FalsePositiveSuppressed`` when ``is_test_fixture`` or
         ``is_checksum_only`` (fixture/checksum never confirms).
      2. ``ProvidedOnly`` when ``dependency_only`` (no direct use, so it
         can never reach Confirmed/Probable/Possible).
      3. ``Confirmed`` when confidence >= 0.85 (requires direct evidence;
         without direct the fusion ceiling is 0.75*0.92 < 0.85, and an
         explicit ``has_direct_evidence=False`` also blocks it).
      4. ``Probable`` when confidence >= 0.65.
      5. ``Possible`` when confidence >= 0.40, else weak-``Possible``
         (kept Possible rather than invented negatives to avoid false
         negatives; suppression is explicit via (1)).

    The optional ``has_direct_evidence`` preserves the "Confirmed w/
    direct" clause when callers track it; ``None`` (default) infers it
    from the score ceiling per above.
    """
    try:
        conf = float(confidence)
    except (TypeError, ValueError):
        conf = 0.0
    if is_test_fixture or is_checksum_only:
        return "FalsePositiveSuppressed"
    if dependency_only:
        return "ProvidedOnly"
    if conf >= 0.85:
        if has_direct_evidence is False:
            return "Probable"
        return "Confirmed"
    if conf >= 0.65:
        return "Probable"
    return "Possible"


def deduplicate(
    operations: list[dict] | tuple[dict, ...] | None,
) -> tuple[list[dict], int]:
    """Collapse operations by exact ``dedup_key`` match.

    Keeps the highest-confidence entry per key (deterministic tie-break
    by smallest ``id``, then first-seen order) and returns
    ``(kept, suppressed_count)``. Entries without a ``dedup_key`` are
    never merged (each kept as-is).
    """
    ops: list[dict] = list(operations) if operations else []
    if not ops:
        return [], 0
    best: dict[str, dict] = {}
    best_conf: dict[str, float] = {}
    best_id: dict[str, str] = {}
    keyless: list[dict] = []
    for op in ops:
        key = op.get("dedup_key")
        if not key:
            keyless.append(op)
            continue
        try:
            conf = float(op.get("confidence", 0.0))
        except (TypeError, ValueError):
            conf = 0.0
        oid = str(op.get("id", ""))
        if key not in best:
            best[key] = op
            best_conf[key] = conf
            best_id[key] = oid
        else:
            if conf > best_conf[key] or (
                conf == best_conf[key] and oid < best_id[key]
            ):
                best[key] = op
                best_conf[key] = conf
                best_id[key] = oid
    kept = list(best.values()) + keyless
    kept.sort(
        key=lambda o: (
            -(float(o.get("confidence", 0.0)) if _is_num(o.get("confidence")) else 0.0),
            str(o.get("dedup_key", "")),
            str(o.get("id", "")),
        )
    )
    return kept, len(ops) - len(kept)


def _is_num(v: object) -> bool:
    try:
        float(v)  # type: ignore[arg-type]
        return True
    except (TypeError, ValueError):
        return False


_KEY_RE = re.compile(
    r"(?i)\b([a-z0-9_\-\.]*key\s*[:=]\s*)([^\s;,\n'\"`]+)"
)
_SECRET_RE = re.compile(
    r"(?i)\b([a-z0-9_\-\.]*secret\s*[:=]\s*)([^\s;,\n'\"`]+)"
)
_PEM_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE[^-]*-----[\s\S]*?-----END [^-]*PRIVATE[^-]*-----",
    re.IGNORECASE,
)
_BEGIN_PRIVATE_RE = re.compile(r"(?i)BEGIN PRIVATE[^\n]*")


def redact_snippet(snippet: str | None) -> str:
    """Redact secret material from a code snippet (deterministic).

    Replaces ``key= <value>`` / ``secret= <value>`` values and PEM
    ``BEGIN PRIVATE`` blocks with ``[REDACTED]``. Non-string/empty
    input -> ``""``. No LLM, pure regex.
    """
    if not snippet or not isinstance(snippet, str):
        return ""
    out = _PEM_RE.sub("[REDACTED]", snippet)
    out = _KEY_RE.sub(r"\1[REDACTED]", out)
    out = _SECRET_RE.sub(r"\1[REDACTED]", out)
    # Fallback: bare "BEGIN PRIVATE" line without PEM armour.
    if "BEGIN PRIVATE" in out.upper():
        out = _BEGIN_PRIVATE_RE.sub("[REDACTED]", out)
    return out
