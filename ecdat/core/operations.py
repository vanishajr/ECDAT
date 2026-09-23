"""Person-1 Agent B: raw-hit -> CryptoOperation collapse (stdlib only).

Groups many low-level detector hits into few ``CryptoOperation`` plain
dicts shaped like ``cir.schema.json`` (kept as dicts — not Agent A's
``cir_models`` — to avoid a circular import). Each group fuses its
combined evidence via :mod:`ecdat.core.fusion`, mints a deterministic
``dedup_key``/``id``, and sorts by ``(confidence desc, id)``.

``ProvidedOnly`` (dependency-only, no direct use) groups are never
merged with direct-use groups sharing the same crypto/location key and
are capped to confidence <= 0.35 per contract.
"""

from __future__ import annotations

import hashlib
import os
import re

from ecdat.core.fusion import decide_usage, redact_snippet, weighted_fusion

__all__ = ["build_operations", "build_semantic_operations",
           "group_key_for", "dedup_key_for", "reconstruct_cir"]

_TEST_DIR_NAMES = frozenset({"test", "tests", "testing", "testsuite",
                             "demos", "examples", "doc"})

# Evidence tool prefix -> (fusion detector, fusion signal type).
# Signal "call" counts as direct-use evidence in weighted_fusion;
# everything else contributes through flags/reliability instead.
_TOOL_SIGNALS: tuple[tuple[str, str, str], ...] = (
    ("source:api-call", "source", "call"),
    ("source:ast", "source", "call"),
    ("source:semgrep", "semgrep", "call"),
    ("source:wrapper-call", "source", "call"),
    ("source:custom-invocation", "source", "call"),
    ("source:fingerprint", "source", "definition"),
    ("binary-lief", "lief", "binary-import"),
    ("binary-capa", "capa", "behavior"),
    ("binary-floss", "strings", "decoded-match"),
    ("binary-signatures", "yara-x", "constant-match"),
    ("binary-strings", "strings", "pattern-match"),
    ("binary:", "binary", "pattern-match"),
    ("config:dockerfile", "dockerfile", "definition"),
    ("config-", "config", "config-match"),
    ("dependency:syft", "syft", "dependency-capability"),
    ("dependency:cdxgen", "syft", "dependency-capability"),
    ("dependency:bom-", "bom", "dependency-capability"),
    ("dependency:", "dependency", "dependency-capability"),
    ("container-syft", "syft", "dependency-capability"),
    ("container-trivy", "container", "vuln-match"),
    ("container-docker", "container", "definition"),
    ("container:", "container", "pattern-match"),
    ("certificate-", "certificate", "cert-parse"),
    ("runtime-tls", "runtime", "runtime-probe"),
    ("runtime-ssh", "runtime", "runtime-probe"),
    ("runtime:", "runtime", "runtime-probe"),
    ("cloud-aws", "cloud", "cloud-inventory"),
    ("cloud:", "cloud", "cloud-inventory"),
    ("secret", "secret", "secret-match"),
    ("gitleaks", "gitleaks", "secret-match"),
)

_DEPENDENCY_TOOLS: tuple[str, ...] = (
    "dependency:", "container-syft", "container-trivy",
    "config:dockerfile", "dependency:syft", "dependency:cdxgen",
    "dependency:bom-",
)

_SERVICE_RE = re.compile(r"service=([^;]+)")

_PROVIDED_ONLY_CAP = 0.35
_PROVIDED_SUFFIX = "provided-only"


def _s(v: object) -> str:
    if v is None:
        return ""
    return str(v)


def _nested(hit: dict, *names: str, default: object = None) -> object:
    """Look up ``names[0]`` top-level, then inside asset/location/implementation/context."""
    if not isinstance(hit, dict):
        return default
    if names[0] in hit and hit[names[0]] is not None:
        return hit[names[0]]
    for container in ("asset", "location", "implementation", "context"):
        sub = hit.get(container)
        if isinstance(sub, dict):
            for n in names:
                if n in sub and sub[n] is not None:
                    return sub[n]
    # Alias fallbacks across naming styles.
    return default


def _as_bool(hit: dict, *names: str) -> bool:
    for container in (hit, hit.get("implementation", {}), hit.get("context", {}),
                      hit.get("asset", {}), hit.get("location", {})):
        if isinstance(container, dict):
            for n in names:
                if n in container and container[n] is not None:
                    return bool(container[n])
    return False


def _as_evidence(hit: dict) -> list[dict]:
    ev = hit.get("evidence")
    if isinstance(ev, list):
        return [e for e in ev if isinstance(e, dict)]
    for container in ("implementation", "context", "asset"):
        sub = hit.get(container)
        if isinstance(sub, dict) and isinstance(sub.get("evidence"), list):
            return [e for e in sub["evidence"] if isinstance(e, dict)]
    # Single-evidence shorthand: detector/signal_type at top level.
    if isinstance(hit.get("detector"), str) or isinstance(hit.get("signal_type"), str):
        return [
            {
                "detector": hit.get("detector", "unknown"),
                "signal_type": hit.get("signal_type", ""),
                "confidence": hit.get("confidence", 0.0),
            }
        ]
    return []


def _asset_ids_of(hit: dict) -> list[str]:
    ids: list[str] = []
    for key in ("asset_ids", "assetIds"):
        v = hit.get(key)
        if isinstance(v, list):
            ids.extend(_s(x) for x in v if _s(x))
    for key in ("asset_id", "assetId", "id"):
        v = hit.get(key)
        if isinstance(v, str) and v and key != "id":
            ids.append(v)
        elif isinstance(v, str) and v and key == "id" and v.startswith("asset"):
            ids.append(v)
    for container in ("asset", "context", "implementation"):
        sub = hit.get(container)
        if isinstance(sub, dict):
            for key in ("asset_id", "asset_ids", "id"):
                v = sub.get(key)
                if isinstance(v, str) and v:
                    ids.append(v)
                elif isinstance(v, list):
                    ids.extend(_s(x) for x in v if _s(x))
    # De-dup preserving first-seen order.
    seen: dict[str, None] = {}
    for i in ids:
        seen.setdefault(i)
    return list(seen)


def _snippet_of(hit: dict) -> str:
    for container in (hit, hit.get("context", {}), hit.get("location", {}),
                      hit.get("implementation", {})):
        if isinstance(container, dict):
            for key in ("snippet", "code", "additionalContext", "additional_context"):
                v = container.get(key)
                if isinstance(v, str) and v:
                    return v
    evs = _as_evidence(hit)
    for e in evs:
        if isinstance(e.get("snippet"), str) and e["snippet"]:
            return e["snippet"]  # type: ignore[index]
    return ""


def _stable_file(value: object, root: object) -> str:
    """Repository-relative path when ``value`` sits under ``root``.

    Identity inputs (group keys, ID seeds, tie-breaks) must not depend
    on absolute temporary acquisition paths: ``/tmp/A/repo/crypto/x.py``
    and ``/tmp/B/repo/crypto/x.py`` normalize to the same ``crypto/x.py``.
    Anything outside ``root`` (cloud labels, image refs, empty values)
    passes through unchanged, preserving prior behavior there.
    """
    text = str(value or "")
    if not text or root is None:
        return text
    try:
        relative = os.path.relpath(text, str(root))
    except Exception:
        return text
    if not relative or relative == "." or relative.startswith(".."):
        return text
    return relative


def _stable_base(base: tuple, root: object) -> tuple:
    """Group-key tuple with the file slot (index 5) stabilized."""
    if root is None or len(base) <= 5:
        return base
    items = list(base)
    items[5] = _stable_file(items[5], root)
    return tuple(items)


def _stable_sort_key(location: object = None, function: object = None,
                     canonical: object = "", root: object = None) -> tuple:
    """Deterministic, path-independent representative ordering key.

    Tie-break rule (documented): repository-relative file, then line,
    then function, then canonical name. Uses only stable
    repository/content information — never absolute paths, temp dirs,
    PIDs, timestamps, scan IDs, or randomness.
    """
    try:
        line = getattr(location, "line", None)
        line_no = int(line) if isinstance(line, int) or (
            isinstance(line, str) and line.lstrip("-").isdigit()) else -1
    except Exception:
        line_no = -1
    try:
        path = str(getattr(location, "file", "") or "") if location else ""
    except Exception:
        path = ""
    return (_stable_file(path, root), line_no,
            str(function or ""), str(canonical or ""))


def _scan_root(target: object) -> object:
    """Scan-root directory for stable identity, or None.

    Directory targets relativize to themselves; file targets to their
    parent. Anything else (cloud labels, image refs, missing paths)
    yields None, preserving historical absolute-path behavior there.
    """
    text = str(target or "").strip()
    if not text:
        return None
    try:
        candidate = os.path.realpath(text)
        if os.path.isdir(candidate):
            return candidate
        parent = os.path.dirname(candidate)
        if parent and os.path.isdir(parent):
            return parent
    except Exception:
        pass
    return None


def group_key_for(hit: dict) -> tuple[str, ...]:
    """Return the 9-part grouping key for one raw hit.

    ``(operation_type|canonical_name|key_size|mode|curve|file|function|
    service|endpoint)`` with ``None`` -> ``""`` and everything stringified.
    """
    op_type = _s(
        _nested(hit, "operation_type", "operationType", default="")
        or hit.get("type", "")
    )
    canonical = _s(
        _nested(hit, "canonical_name", "canonicalName", "algorithm", "name",
                default="")
    )
    key_size = _s(_nested(hit, "key_size", "keySize", "bits", default=""))
    mode = _s(_nested(hit, "mode", default=""))
    curve = _s(_nested(hit, "curve", "ec_curve", "named_curve", default=""))
    # Location-ish fields may live top-level or nested.
    file = _s(_nested(hit, "file", "path", "filename", default=""))
    function = _s(_nested(hit, "function", "function_name", "symbol", default=""))
    service = _s(_nested(hit, "service", default=""))
    endpoint = _s(
        _nested(hit, "endpoint", "url", "host", default="")
    )
    return (op_type, canonical, key_size, mode, curve, file, function, service, endpoint)


def dedup_key_for(group_key: tuple[str, ...], dependency_only: bool = False) -> str:
    """Render a deterministic dedup string for a group key.

    ``ProvidedOnly`` groups get a ``|provided-only`` suffix so they never
    collapse with direct-use groups on the same crypto/location tuple.
    """
    base = "|".join(group_key)
    if dependency_only:
        return base + "|" + _PROVIDED_SUFFIX
    return base


def _evidence_classes_for(detectors: list) -> list[str]:
    """Classify fusion detector names via the Phase 4 evidence taxonomy.

    Additive annotation only: never raises, unknown detectors map to
    ``reference`` (see :mod:`ecdat.core.evidence`). Import is local so
    this module keeps its stdlib-only import surface at load time.
    """
    try:
        from ecdat.core.evidence import classify_evidence as _classify
    except Exception:
        return []
    classes: list[str] = []
    for detector in (detectors or []):
        try:
            name = _classify(detector).value
        except Exception:
            name = "reference"
        if name not in classes:
            classes.append(name)
    return sorted(classes)


def _semantic_state_for(usage_state: str, classes: list[str]) -> str:
    """Derive the Phase 4 semantic state string (additive annotation)."""
    try:
        from ecdat.core.evidence import semantic_state_for as _state_for
        return _state_for(usage_state, classes).value
    except Exception:
        return "referenced"


def build_operations(raw_hits: list[dict] | tuple[dict, ...] | None,
                     use_semantic: bool = False,
                     root: object = None) -> list[dict]:
    """Collapse raw hits into sorted CryptoOperation dicts.

    Args:
        raw_hits: each hit may carry asset fields, location
            (file/function/service/endpoint), implementation flags
            (param_resolved/binary_support/config_runtime_agreement),
            ``evidence`` (list of detector/signal_type/confidence), and
            context (dependency_only/is_test_fixture/is_checksum_only/
            snippet/asset_id). Missing keys default sensibly.
        use_semantic: when True, fused groups sharing one Phase 7
            semantic identity (primitive/variant/mode/key/curve/
            protocol/op-type/scope/provider) are additionally correlated
            into a single operation with merged provenance. Defaults to
            False so the legacy 9-tuple grouping is unchanged.
    root: optional scan-root directory. When given, the file slot of
        group keys is repository-relative, so identical trees scanned
        from different locations fuse identically. ``None`` preserves
        the historical absolute-path behavior (unit-test default).

    Returns:
        List of plain ``CryptoOperation`` dicts with fused
        ``confidence``, ``usage_state``, ``dedup_key``, ``asset_ids``,
        sorted by ``(confidence desc, id)``. ``id`` is
        ``op-<blake2s12(dedup_key)>``.
    """
    hits: list[dict] = [h for h in (raw_hits or []) if isinstance(h, dict)]
    if not hits:
        return []

    # Accumulate per (base_key, dependency_flag) so ProvidedOnly groups
    # never merge with direct-use groups on the same tuple.
    groups: dict[tuple[tuple[str, ...], bool], dict] = {}
    for hit in hits:
        base = _stable_base(group_key_for(hit), root)
        dep = _as_bool(hit, "dependency_only", "dependencyOnly")
        gk = (base, dep)
        g = groups.get(gk)
        if g is None:
            g = {
                "base": base,
                "dependency_only": dep,
                "evidence": [],
                "asset_ids": [],
                "param_resolved": False,
                "binary_support": False,
                "config_runtime_agreement": False,
                "is_test_fixture": False,
                "is_checksum_only": False,
                "snippets": [],
                "hit_count": 0,
            }
            groups[gk] = g
        g["evidence"].extend(_as_evidence(hit))
        for aid in _asset_ids_of(hit):
            if aid not in g["asset_ids"]:
                g["asset_ids"].append(aid)
        if _as_bool(hit, "param_resolved", "paramResolved"):
            g["param_resolved"] = True
        if _as_bool(hit, "binary_support", "binarySupport"):
            g["binary_support"] = True
        if _as_bool(hit, "config_runtime_agreement", "configRuntimeAgreement",
                    "runtime_agreement"):
            g["config_runtime_agreement"] = True
        if _as_bool(hit, "is_test_fixture", "isTestFixture", "test_fixture"):
            g["is_test_fixture"] = True
        if _as_bool(hit, "is_checksum_only", "isChecksumOnly", "checksum_only"):
            g["is_checksum_only"] = True
        snip = _snippet_of(hit)
        if snip:
            g["snippets"].append(snip)
        g["hit_count"] += 1

    ops: list[dict] = []
    for (base, dep), g in groups.items():
        confidence, breakdown = weighted_fusion(
            g["evidence"],
            param_resolved=bool(g["param_resolved"]),
            binary_support=bool(g["binary_support"]),
            config_runtime_agreement=bool(g["config_runtime_agreement"]),
            dependency_only=bool(dep),
        )
        if dep and confidence > _PROVIDED_ONLY_CAP:
            confidence = _PROVIDED_ONLY_CAP
        if not dep and not g["is_test_fixture"] and not g["is_checksum_only"] \
                and breakdown.get("has_direct_usage"):
            # Direct observation is a floor, not a target: fusion can
            # corroborate upward and penalties still apply, but a direct
            # API call is never fused below what was observed.
            try:
                confidence = max(confidence, max(
                    float(e.get("confidence", 0.0) or 0.0)
                    for e in g["evidence"]))
            except Exception:
                pass
        usage_state = decide_usage(
            confidence,
            dependency_only=bool(dep),
            is_test_fixture=bool(g["is_test_fixture"]),
            is_checksum_only=bool(g["is_checksum_only"]),
        )
        dedup_key = dedup_key_for(base, bool(dep))
        op_id = "op-" + hashlib.blake2s(
            dedup_key.encode("utf-8")).hexdigest()[:12]
        asset_ids = sorted(g["asset_ids"])
        first_snippet = g["snippets"][0] if g["snippets"] else ""
        detectors = breakdown.get("detectors", [])
        evidence_classes = _evidence_classes_for(detectors)
        op = {
            "id": op_id,
            "operation_type": base[0],
            "canonical_name": base[1],
            "key_size": int(base[2]) if base[2].isdigit() else (
                base[2] if base[2] else None),
            "mode": base[3] or None,
            "curve": base[4] or None,
            "file": base[5] or None,
            "function": base[6] or None,
            "service": base[7] or None,
            "endpoint": base[8] or None,
            "confidence": confidence,
            "usage_state": usage_state,
            "dedup_key": dedup_key,
            "asset_ids": asset_ids,
            "evidence_count": len(g["evidence"]),
            "hit_count": g["hit_count"],
            "detectors": detectors,
            "breakdown": breakdown,
            "redacted_snippet": redact_snippet(first_snippet),
            # Phase 4 additive annotations (taxonomy-derived, never fused).
            "evidence_classes": evidence_classes,
            "semantic_state": _semantic_state_for(
                usage_state, evidence_classes),
        }
        ops.append(op)

    ops.sort(key=lambda o: (-float(o.get("confidence", 0.0)), str(o.get("id", ""))))
    if use_semantic:
        ops = _correlate_semantic(ops)
    return ops


def _correlate_semantic(ops: list[dict]) -> list[dict]:
    """Merge fused ops sharing one Phase 7 semantic identity (opt-in).

    Identity ignores the syntactic ``function``/``id`` split so a direct
    API call and its wrapper collapse to one logical operation; all
    provenance (asset_ids/detectors/evidence & hit counts) is preserved
    via union/sum and confidence is the member max.
    """
    try:
        from ecdat.core.semantic_ops import semantic_identity_key as _sem_key
    except Exception:
        return ops
    groups: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    for op in ops:
        key_size = op.get("key_size")
        pseudo = {
            "primitive": None,
            "variant": op.get("canonical_name"),
            "algorithm": op.get("canonical_name"),
            "mode": op.get("mode"),
            "key": {"size": key_size, "curve": op.get("curve")},
            "protocol": None,
            "operation": op.get("operation_type"),
            "scope": {"file": op.get("file"), "service": op.get("service"),
                      "endpoint": op.get("endpoint")},
            "build_state": ("provided-only"
                            if str(op.get("dedup_key", "")).endswith(
                                "provided-only") else ""),
            "call_sequence": [],
            "provider": None,
        }
        try:
            key = _sem_key(pseudo)
        except Exception:
            key = (str(op.get("dedup_key", "")),)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(op)
    merged: list[dict] = []
    for key in order:
        members = groups[key]
        if len(members) == 1:
            merged.append(members[0])
            continue
        first = dict(members[0])
        asset_ids: list = []
        detectors: list = []
        evidence_count = 0
        hit_count = 0
        confidence = 0.0
        for member in members:
            for aid in (member.get("asset_ids") or []):
                if aid not in asset_ids:
                    asset_ids.append(aid)
            for detector in (member.get("detectors") or []):
                if detector not in detectors:
                    detectors.append(detector)
            try:
                evidence_count += int(member.get("evidence_count", 0) or 0)
                hit_count += int(member.get("hit_count", 0) or 0)
            except (TypeError, ValueError):
                pass
            try:
                confidence = max(
                    confidence, float(member.get("confidence", 0.0) or 0.0))
            except (TypeError, ValueError):
                pass
        first["asset_ids"] = sorted(asset_ids)
        first["detectors"] = sorted(detectors)
        first["evidence_count"] = evidence_count
        first["hit_count"] = hit_count
        first["confidence"] = confidence
        first["evidence_classes"] = _evidence_classes_for(sorted(detectors))
        first["semantic_state"] = _semantic_state_for(
            str(first.get("usage_state", "")), first["evidence_classes"])
        try:
            breakdown = dict(first.get("breakdown", {}) or {})
            breakdown["detectors"] = sorted(detectors)
            first["breakdown"] = breakdown
        except Exception:
            pass
        merged.append(first)
    merged.sort(key=lambda o: (-float(o.get("confidence", 0.0)),
                               str(o.get("id", ""))))
    return merged


def build_semantic_operations(
        raw_hits: list[dict] | tuple[dict, ...] | None) -> list[dict]:
    """Reconstruct Phase 4 semantic operations for raw hits (additive).

    Groups hits with :func:`group_key_for`, rebuilds one semantic
    operation per group via
    :func:`ecdat.core.semantic_ops.build_semantic_operation`, then
    correlates by semantic identity. Returns semantic-op dicts
    (primitive/algorithm/variant/mode/... shape), *not* the fused
    :func:`build_operations` shape.
    """
    from ecdat.core.semantic_ops import (
        build_semantic_operation, correlate_operations)
    hits = [h for h in (raw_hits or []) if isinstance(h, dict)]
    if not hits:
        return []
    groups: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    for hit in hits:
        try:
            base = group_key_for(hit)
        except Exception:
            continue
        if base not in groups:
            groups[base] = []
            order.append(base)
        groups[base].append(hit)
    semantic = [build_semantic_operation(groups[base]) for base in order]
    return correlate_operations(semantic)


def _usage_is_provided_only(state: object) -> bool:
    """True for ProvidedOnly in Enum, value, or string form.

    In-memory CIR carries ``UsageState`` enum members whose ``str()``
    is ``"UsageState.PROVIDED_ONLY"`` (never endswith ``"ProvidedOnly"``);
    serialized CIR carries the plain value. Both must count, otherwise
    re-fusion silently upgrades ProvidedOnly assets to Possible/Probable.
    """
    try:
        value = getattr(state, "value", state)
        text = str(value if value is not None else "")
    except Exception:
        return False
    return text == "ProvidedOnly" or text.endswith("ProvidedOnly")


def _dethash(value: str, prefix: str, length: int = 16) -> str:
    """Deterministic ``prefix:hash`` (same seed as discovery's helper)."""
    hash_val = hashlib.sha256(value.encode()).hexdigest()[:length]
    return f"{prefix}:{hash_val}"


def _tool_signal(tool: str, detail: str = "") -> tuple[str, str]:
    """Map an evidence tool string to (fusion detector, signal type).

    Phase 6 refinement: an explicitly *enabled* protocol version in
    deployment configuration (``ssl_protocols TLSv1;``,
    ``min_tls_version = "1.0"``) is a directly observed configured
    fact — invocation-equivalent for protocol posture — not a mere
    keyword mention. Only exact-directive details qualify; generic
    config keyword hits stay ``config-match``.
    """
    text = str(tool or "")
    lowered = str(detail or "").lower()
    if text.startswith("config-") and (
        "protocol enabled" in lowered or "tls version:" in lowered
    ):
        return "config", "call"
    for prefix, detector, signal in _TOOL_SIGNALS:
        if text.startswith(prefix):
            return detector, signal
    return "unknown", "pattern-match"


def _is_dependency_tool(tool: str) -> bool:
    text = str(tool or "")
    return any(text.startswith(prefix) for prefix in _DEPENDENCY_TOOLS)


def _is_test_path(path: str | None) -> bool:
    if not path:
        return False
    try:
        from pathlib import Path as _Path
        parts = [p.lower() for p in _Path(str(path)).parts]
        if any(p in _TEST_DIR_NAMES for p in parts):
            return True
        stem = _Path(str(path)).stem.lower()
        return bool(re.search(r"(^|[_\-.])tests?([_\-.]|$)", stem))
    except Exception:
        return False


def _direct_best(evidence: list) -> float:
    """Strongest direct-call confidence in raw CIR evidence items."""
    best = 0.0
    try:
        for item in evidence or []:
            tool = str(getattr(item, "tool", "") or "")
            detail = str(getattr(item, "detail", "") or "")
            _, signal = _tool_signal(tool, detail)
            if signal == "call":
                try:
                    best = max(best, float(
                        getattr(item, "confidence", 0.0) or 0.0))
                except (TypeError, ValueError):
                    continue
    except Exception:
        pass
    return best


def _test_suppressed(path: str | None, evidence: list) -> bool:
    """Test-vector suppression needs BOTH a test path AND weak evidence.

    A direct high-confidence observation (floor 0.8, the Confirmed band
    edge) is application use no matter the filename — e.g. a fixture
    file literally named ``test.py`` scanned at a scan root. Weak
    test-path evidence suppresses per the fusion contract.
    """
    return _is_test_path(path) and _direct_best(evidence) < 0.8


def _service_of(context_notes: str | None) -> str:
    if not context_notes:
        return ""
    match = _SERVICE_RE.search(str(context_notes))
    return match.group(1).strip() if match else ""


def _endpoint_of(location) -> str:
    try:
        uri = str(getattr(location, "uri", "") or "")
    except Exception:
        return ""
    return uri if "://" in uri else ""


def _merge_evidence(lists: list[list]) -> list:
    """Concatenate signals, dropping exact duplicates (provenance kept)."""
    merged: list = []
    seen: set = set()
    for items in lists:
        for item in items or []:
            try:
                key = (str(getattr(item, "tool", "")),
                       str(getattr(item, "detail", "")),
                       str(getattr(item, "snippet", "") or ""),
                       str(getattr(item, "confidence", "")))
            except Exception:
                continue
            if key not in seen:
                seen.add(key)
                merged.append(item)
    return merged


def _notes_append(notes: str | None, addition: str) -> str | None:
    if not addition:
        return notes
    if not notes:
        return addition
    keys = {p.split("=")[0] + "=" for p in str(notes).split("; ")}
    additions = [p for p in addition.split("; ")
                 if p.split("=")[0] + "=" not in keys]
    if not additions:
        return notes
    return str(notes) + "; " + "; ".join(additions)


def _hit_for_operation(op, asset) -> dict:
    """Adapt one CIR operation (+asset) to the build_operations contract."""
    evidence: list[dict] = []
    for item in (getattr(op, "evidence", None) or []):
        try:
            tool = str(getattr(item, "tool", "") or "unknown")
            detector, signal = _tool_signal(
                tool, str(getattr(item, "detail", "") or ""))
            evidence.append({
                "detector": detector,
                "signal_type": signal,
                "confidence": getattr(item, "confidence", 0.0),
            })
        except Exception:
            continue
    location = getattr(op, "location", None)
    context = getattr(op, "context", None)
    implementation = getattr(op, "implementation", None)
    try:
        file = str(getattr(location, "file", "") or "") if location else ""
    except Exception:
        file = ""
    try:
        function = str(getattr(op, "function", "") or "") or None
    except Exception:
        function = None
    notes = ""
    try:
        notes = str(getattr(context, "notes", "") or "") if context else ""
    except Exception:
        notes = ""
    asset_dict = {
        "canonical_name": getattr(asset, "canonical", "") if asset else "",
        "key_size": getattr(asset, "key_size", None) if asset else None,
        "mode": getattr(asset, "mode", None) if asset else None,
        "curve": getattr(asset, "curve", None) if asset else None,
    }
    try:
        op_type = getattr(getattr(op, "operation_type", None), "value", "")
    except Exception:
        op_type = ""
    try:
        lib = str(getattr(implementation, "library", "") or "") \
            if implementation else ""
    except Exception:
        lib = ""
    try:
        usage_state = str(getattr(getattr(op, "risk_inputs", None),
                                  "usage_state", "") or "")
    except Exception:
        usage_state = ""
    try:
        tools = [str(getattr(e, "tool", ""))
                 for e in (getattr(op, "evidence", None) or [])]
    except Exception:
        tools = []
    dependency_only = _usage_is_provided_only(usage_state) or (
        bool(tools) and all(_is_dependency_tool(t) for t in tools))
    try:
        raw_evidence = list(getattr(op, "evidence", None) or [])
    except Exception:
        raw_evidence = []
    return {
        "operation_type": op_type or "",
        "canonical_name": asset_dict["canonical_name"],
        "key_size": asset_dict["key_size"],
        "mode": asset_dict["mode"],
        "curve": asset_dict["curve"],
        "file": file,
        "function": function,
        "service": _service_of(notes),
        "endpoint": _endpoint_of(location),
        "library": lib,
        "evidence": evidence,
        "asset_ids": [getattr(op, "asset_id", "")] if getattr(
            op, "asset_id", "") else [],
        "param_resolved": bool(
            (asset_dict["key_size"] or asset_dict["mode"]
             or asset_dict["curve"])
            and any(e["signal_type"] == "call" for e in evidence)),
        "binary_support": any(
            str(getattr(i, "tool", "")).startswith("binary-")
            for i in (getattr(op, "evidence", None) or [])),
        "config_runtime_agreement": any(
            str(getattr(i, "tool", "")).startswith("config-")
            for i in (getattr(op, "evidence", None) or [])) and any(
            str(getattr(i, "tool", "")).startswith("runtime-")
            for i in (getattr(op, "evidence", None) or [])),
        "dependency_only": dependency_only,
        "is_test_fixture": _test_suppressed(file, raw_evidence),
        "_op": op,
        "_asset": asset,
    }


def _hit_dependency_only(hit: dict) -> bool:
    """Group-level dependency separation (mirrors build_operations)."""
    return bool(hit.get("dependency_only", False))


def reconstruct_cir(cir):
    """Fuse evidence and reconstruct operations over a CIR document.

    The authoritative Phase 8 production stage (called by
    ``DiscoveryEngine.scan_and_emit_cir`` for every CLI/GUI/CI scan):

    1. adapts CIR operations (+assets) to raw hits carrying detector,
       signal type, location, parameters, confidence, usage implication
       and context per evidence item;
    2. collapses hits with :func:`build_operations` (weighted fusion
       confidence, usage adjudication, ProvidedOnly separation,
       deterministic dedup keys) — never one operation per raw finding;
    3. rewrites operations (merged provenance evidence, fused
       confidence/usage, stable semantic IDs) and regroups assets by
       (canonical, parameters, file) with fused confidence/usage;
    4. preserves asset-only evidence (assets no operation references);
    5. rebuilds the knowledge-graph nodes/edges from the merged sets;
    6. returns a validated ``CIRDocument`` (pydantic construction).

    Direct-observation confidence is a floor, not a target: fusion can
    corroborate upward and penalties (dependency/test) still apply via
    :func:`decide_usage`, but a direct API call is never fused below
    what the detector observed.
    """
    # Path-independent identity: identical trees scanned from different
    # locations must fuse, select, and identify identically.
    root = _scan_root(getattr(cir, "target", ""))
    from ecdat.core.cir_models import (
        CIRDocument, CryptoAsset, CryptoOperation, Graph, GraphEdge,
        GraphNode, GraphNodeKind, GraphRelationship, RiskInputs,
        new_asset_id, new_operation_id,
    )

    assets_by_id = {a.asset_id: a for a in (cir.assets or [])}
    hits: list[dict] = []
    for op in (cir.operations or []):
        try:
            hits.append(_hit_for_operation(
                op, assets_by_id.get(getattr(op, "asset_id", ""))))
        except Exception:
            continue
    if not hits:
        return cir

    # Scan-level static/runtime agreement (task 4): a config claim for
    # an algorithm ALSO observed live (runtime probe, same canonical)
    # corroborates it. Computed here from scan context — the
    # build_operations contract itself is untouched.
    live_canonicals = set()
    for hit in hits:
        try:
            tools = [str(getattr(e, "tool", ""))
                     for e in (hit["_op"].evidence or [])]
        except Exception:
            tools = []
        if any(t.startswith("runtime-") for t in tools):
            live_canonicals.add(str(hit.get("canonical_name", "")))
    if live_canonicals:
        for hit in hits:
            try:
                tools = [str(getattr(e, "tool", ""))
                         for e in (hit["_op"].evidence or [])]
            except Exception:
                tools = []
            if any(t.startswith("config-") for t in tools) and \
                    str(hit.get("canonical_name", "")) in live_canonicals:
                hit["config_runtime_agreement"] = True

    fused = build_operations(hits, root=root)

    # Recover membership per fused group via the same deterministic
    # dedup_key contract (insertion order = CIR order = deterministic).
    # Keys use the same stabilized file slot as build_operations above.
    groups: dict[str, list] = {}
    for hit in hits:
        key = dedup_key_for(
            _stable_base(group_key_for(hit), root),
            bool(hit.get("dependency_only", False)))
        groups.setdefault(key, []).append(hit["_op"])

    new_operations: list = []
    for group in fused:
        key = group["dedup_key"]
        ops = groups.get(key, [])
        if not ops:
            continue
        # Survivor: richest provenance, then strongest signal, then the
        # documented stable tie-break (relative path, line, function,
        # canonical) — never absolute temp paths or random order.
        ops = sorted(ops, key=lambda o: (
            -len(getattr(o, "evidence", None) or []),
            -(float(getattr(o, "confidence", 0.0) or 0.0)),
            _stable_sort_key(getattr(o, "location", None),
                             getattr(o, "function", None),
                             getattr(getattr(o, "operation_type", None),
                                     "value", ""),
                             root)))
        survivor = ops[0]
        merged_evidence = _merge_evidence(
            [list(getattr(o, "evidence", None) or []) for o in ops])
        confidence = float(group.get("confidence", 0.0) or 0.0)
        if group.get("breakdown", {}).get("has_direct_usage"):
            try:
                direct_best = max(
                    float(getattr(e, "confidence", 0.0) or 0.0)
                    for o in ops for e in (getattr(o, "evidence", None) or []))
                confidence = max(confidence, direct_best)
            except Exception:
                pass
        confidence = min(1.0, max(0.0, round(confidence, 3)))
        usage = str(group.get("usage_state", "Possible"))
        breakdown = group.get("breakdown", {}) or {}
        if usage not in ("ProvidedOnly", "FalsePositiveSuppressed"):
            # Adjudicate on the floored score: build_operations decides
            # on the formula value, but direct observation floors the
            # confidence above it (a 0.92 direct call is Confirmed, not
            # Probable). Flags still dominate via decide_usage.
            usage = decide_usage(
                confidence,
                has_direct_evidence=bool(
                    breakdown.get("has_direct_usage", False)))
        detectors = ",".join(breakdown.get("detectors", []) or [])
        fusion_note = (f"fusion=conf:{confidence}/usage:{usage}/"
                       f"detectors:{detectors}/"
                       f"evidence:{len(merged_evidence)}/"
                       f"hits:{group.get('hit_count', len(ops))}")
        # Phase 4 additive provenance: evidence taxonomy classes for the
        # merged detectors (classify_evidence never guesses; unknown ->
        # reference). Keeps the stable "fusion=" prefix intact.
        try:
            from ecdat.core.evidence import classify_evidence as _classify
            _classes = sorted({
                _classify(getattr(e, "tool", "")).value
                for e in (merged_evidence or [])})
            if _classes:
                fusion_note += f"/classes:{','.join(_classes)}"
        except Exception:
            pass
        try:
            notes = _notes_append(
                str(getattr(getattr(survivor, "context", None),
                            "notes", "") or "") or None, fusion_note)
        except Exception:
            notes = fusion_note
        try:
            context = getattr(survivor, "context", None)
            if context is not None:
                context.notes = notes
        except Exception:
            pass
        risk_inputs = getattr(survivor, "risk_inputs", None)
        try:
            from ecdat.core.cir_models import UsageState as _UsageState
            usage_state = _UsageState(usage)
        except Exception:
            from ecdat.core.cir_models import UsageState as _UsageState
            usage_state = _UsageState.POSSIBLE
        if risk_inputs is not None:
            try:
                risk_inputs.usage_state = usage_state
            except Exception:
                pass
        else:
            try:
                from ecdat.core.cir_models import Exposure as _Exposure
                exposure = getattr(getattr(survivor, "context", None),
                                   "exposure", _Exposure.INTERNAL)
                risk_inputs = RiskInputs(
                    usage_state=usage_state, exposure=exposure,
                    sensitive_data=False,
                    external_dependency=bool(
                        getattr(getattr(survivor, "implementation", None),
                                "library", None)))
            except Exception:
                risk_inputs = None
        # Stable semantic identity (task 10): asset link may have been
        # regrouped below; recompute deterministically at the end.
        new_operations.append({
            "survivor": survivor,
            "evidence": merged_evidence,
            "confidence": confidence,
            "usage_state": usage_state,
            "risk_inputs": risk_inputs,
            "detectors": detectors,
        })

    # Regroup assets by (canonical, params, file): same-file duplicates
    # collapse, cross-file assets stay distinct (stable, test-pinned).
    asset_groups: dict[tuple, list] = {}
    for asset in (cir.assets or []):
        try:
            loc = getattr(asset, "location", None)
            file = str(getattr(loc, "file", "") or "") if loc else ""
            # Identity-grade path: repository-relative so regrouping and
            # regenerated IDs match across acquisition locations.
            file = _stable_file(file, root)
        except Exception:
            file = ""
        key = (str(getattr(asset, "canonical", "")),
               getattr(asset, "key_size", None),
               getattr(asset, "mode", None),
               getattr(asset, "curve", None),
               getattr(asset, "protocol", None), file)
        asset_groups.setdefault(key, []).append(asset)

    new_assets: list = []
    asset_id_map: dict[str, str] = {}
    for key, members_ in asset_groups.items():
        canonical, key_size, mode, curve, protocol, file = key
        merged_evidence = _merge_evidence(
            [list(getattr(a, "evidence", None) or []) for a in members_])
        probe = [{"detector": _tool_signal(
            str(getattr(e, "tool", "")), str(getattr(e, "detail", "") or ""))[0],
            "signal_type": _tool_signal(
                str(getattr(e, "tool", "")), str(getattr(e, "detail", "") or ""))[1],
            "confidence": getattr(e, "confidence", 0.0)}
            for e in merged_evidence]
        dep_only = all(
            _usage_is_provided_only(getattr(a, "usage_state", ""))
            or (bool(getattr(a, "evidence", None)) and all(
                _is_dependency_tool(str(getattr(e, "tool", "")))
                for e in (getattr(a, "evidence", None) or [])))
            for a in members_)
        test_suppress = _test_suppressed(file, merged_evidence)
        param = bool(key_size or mode or curve) and any(
            p["signal_type"] == "call" for p in probe)
        confidence, breakdown = weighted_fusion(
            probe, param_resolved=param, dependency_only=dep_only)
        if breakdown.get("has_direct_usage"):
            try:
                confidence = max(confidence, max(
                    float(getattr(e, "confidence", 0.0) or 0.0)
                    for e in merged_evidence))
            except Exception:
                pass
        if dep_only and not breakdown.get("has_direct_usage"):
            # Implementation identification (structural fingerprint,
            # container/docker definition) is high-confidence knowledge
            # about what is PROVIDED. The dependency penalty targets weak
            # capability hints; it must not crush a 0.95 identification
            # into noise. Floor at the strongest definition evidence.
            try:
                impl_best = max(
                    float(getattr(e, "confidence", 0.0) or 0.0)
                    for e, p in zip(merged_evidence, probe)
                    if p.get("signal_type") == "definition")
                confidence = max(confidence, impl_best)
            except (TypeError, ValueError):
                pass
            except Exception:
                pass
        confidence = min(1.0, max(0.0, round(confidence, 3)))
        usage = decide_usage(
            confidence, dependency_only=dep_only,
            is_test_fixture=test_suppress,
            has_direct_evidence=breakdown.get("has_direct_usage"))
        survivor = sorted(
            members_, key=lambda a: (
                -len(getattr(a, "evidence", None) or []),
                -(float(getattr(a, "confidence", 0.0) or 0.0)),
                _stable_sort_key(getattr(a, "location", None), None,
                                 getattr(a, "canonical", ""), root)))[0]
        try:
            from ecdat.core.cir_models import UsageState as _UsageState
            usage_state = _UsageState(usage)
        except Exception:
            from ecdat.core.cir_models import UsageState as _UsageState
            usage_state = _UsageState.POSSIBLE
        new_id = new_asset_id(canonical, key_size, mode, curve, protocol,
                              file or None, None)
        for member in members_:
            asset_id_map[getattr(member, "asset_id", "")] = new_id
        try:
            arisk = getattr(survivor, "risk_inputs", None)
            if arisk is not None:
                arisk.usage_state = usage_state
        except Exception:
            pass
        try:
            acontext = getattr(survivor, "context", None)
            if acontext is not None:
                acontext.notes = _notes_append(
                    str(getattr(acontext, "notes", "") or "") or None,
                    f"fusion=conf:{confidence}/usage:{usage}/"
                    f"evidence:{len(merged_evidence)}")
        except Exception:
            pass
        try:
            new_assets.append(CryptoAsset(
                asset_id=new_id,
                canonical=getattr(survivor, "canonical", canonical),
                original=getattr(survivor, "original", None),
                key_size=key_size, mode=mode, curve=curve, protocol=protocol,
                library=getattr(survivor, "library", None),
                usage_state=usage_state, confidence=confidence,
                evidence=merged_evidence,
                location=getattr(survivor, "location", None),
                implementation=getattr(survivor, "implementation", None),
                context=getattr(survivor, "context", None),
                risk_inputs=getattr(survivor, "risk_inputs", None),
            ))
        except Exception:
            new_assets.append(survivor)

    # Finalize operations with regrouped asset links + stable IDs.
    final_operations: list = []
    for entry in new_operations:
        survivor = entry["survivor"]
        old_asset_id = getattr(survivor, "asset_id", "")
        new_asset = asset_id_map.get(old_asset_id, old_asset_id)
        try:
            from ecdat.core.cir_models import OperationType as _OpType
            op_type = getattr(survivor, "operation_type", None)
            if not isinstance(op_type, _OpType):
                continue
            # ID seed uses the repository-relative location: identical
            # content scanned elsewhere must yield identical IDs. The
            # stored operation keeps its absolute location (evidence).
            _loc = getattr(survivor, "location", None)
            try:
                _stable = _stable_file(
                    getattr(_loc, "file", ""), root) if _loc else ""
                _seed_loc = _loc.model_copy(update={"file": _stable}) \
                    if _stable and hasattr(_loc, "model_copy") else _loc
            except Exception:
                _seed_loc = _loc
            op_id = new_operation_id(
                op_type, new_asset,
                getattr(survivor, "function", None),
                _seed_loc)
            final_operations.append(CryptoOperation(
                operation_id=op_id,
                operation_type=op_type,
                asset_id=new_asset,
                confidence=entry["confidence"],
                evidence=entry["evidence"],
                function=getattr(survivor, "function", None),
                location=getattr(survivor, "location", None),
                implementation=getattr(survivor, "implementation", None),
                context=getattr(survivor, "context", None),
                risk_inputs=entry["risk_inputs"],
            ))
        except Exception:
            continue

    # Rebuild the graph from the merged sets (same vocabulary/IDs).
    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []
    for asset in new_assets:
        try:
            nodes[asset.asset_id] = GraphNode(
                id=asset.asset_id, kind=GraphNodeKind.ASSET,
                label=asset.canonical, ref=asset.asset_id)
            loc = getattr(asset, "location", None)
            file = str(getattr(loc, "file", "") or "") if loc else ""
            if file:
                # Node identity uses the repository-relative path so the
                # graph matches across acquisition locations; the label
                # keeps the absolute path for traceability.
                file_id = _dethash(_stable_file(file, root) or file, "file")
                if file_id not in nodes:
                    nodes[file_id] = GraphNode(
                        id=file_id, kind=GraphNodeKind.FILE,
                        label=file, ref=file)
                edges.append(GraphEdge(**{
                    "from": file_id, "to": asset.asset_id,
                    "relationship": GraphRelationship.CONTAINS}))
            impl = getattr(asset, "implementation", None)
            lib = str(getattr(impl, "library", "") or "") if impl else ""
            if lib:
                lib_id = _dethash(lib, "library")
                if lib_id not in nodes:
                    nodes[lib_id] = GraphNode(
                        id=lib_id, kind=GraphNodeKind.LIBRARY,
                        label=lib, ref=lib)
                edges.append(GraphEdge(**{
                    "from": asset.asset_id, "to": lib_id,
                    "relationship": GraphRelationship.USES}))
        except Exception:
            continue
    for operation in final_operations:
        try:
            nodes[operation.operation_id] = GraphNode(
                id=operation.operation_id, kind=GraphNodeKind.OPERATION,
                label=operation.operation_type.value,
                ref=operation.operation_id)
            edges.append(GraphEdge(**{
                "from": operation.operation_id, "to": operation.asset_id,
                "relationship": GraphRelationship.USES}))
            loc = getattr(operation, "location", None)
            file = str(getattr(loc, "file", "") or "") if loc else ""
            if file:
                # Node identity uses the repository-relative path so the
                # graph matches across acquisition locations; the label
                # keeps the absolute path for traceability.
                file_id = _dethash(_stable_file(file, root) or file, "file")
                if file_id not in nodes:
                    nodes[file_id] = GraphNode(
                        id=file_id, kind=GraphNodeKind.FILE,
                        label=file, ref=file)
                edges.append(GraphEdge(**{
                    "from": file_id, "to": operation.operation_id,
                    "relationship": GraphRelationship.CONTAINS}))
        except Exception:
            continue

    # Phase 9: authoritative cross-surface system links. The minimal
    # file/asset/operation/library nodes above stay (tested base); the
    # rich builder contributes service/host/key/cert/config/cloud/owner
    # nodes plus depends_on/derives/calls/terminates edges, all in the
    # same CIR v0.1 vocabulary. Library entities are consolidated so one
    # library is one node (rich ``lib:`` ids merge into the minimal
    # ``library:`` ids on matching base names). Failures degrade to the
    # minimal graph, never a failed scan.
    try:
        from ecdat.core.graph import wire_system_links as _wire_links
        extra = _wire_links(new_assets, final_operations) or {}
        lib_base_to_id: dict[str, str] = {}
        for node in nodes.values():
            try:
                if node.kind == GraphNodeKind.LIBRARY:
                    base = str(node.label or "").split("@")[0].strip().lower()
                    if base:
                        lib_base_to_id.setdefault(base, node.id)
            except Exception:
                continue
        seen_edges = {(e.from_node, e.to, e.relationship) for e in edges}
        for node in (extra.get("nodes", []) or []):
            try:
                nid = str(node.get("id", "") or "")
                kind = str(node.get("kind", "") or "")
                if not nid or not kind:
                    continue
                if nid in nodes:
                    continue
                if nid.startswith("lib:"):
                    base = str(node.get("label", "") or "").split("@")[0]
                    base = base.strip().lower().split(" (inferred)")[0]
                    target = lib_base_to_id.get(base)
                    if target:
                        continue  # consolidated below via edge rewrite
                nodes[nid] = GraphNode(
                    id=nid, kind=GraphNodeKind(kind),
                    label=node.get("label"), ref=node.get("ref"))
            except Exception:
                continue
        for edge in (extra.get("edges", []) or []):
            try:
                src, dst = str(edge.get("from", "")), str(edge.get("to", ""))
                rel = GraphRelationship(str(edge.get("relationship", "")))
                if not src or not dst:
                    continue
                if src.startswith("lib:"):
                    base = ""
                    for node in (extra.get("nodes", []) or []):
                        if str(node.get("id", "")) == src:
                            base = str(node.get("label", "") or "")
                            break
                    base = base.split("@")[0].strip().lower()
                    base = base.split(" (inferred)")[0]
                    if base and base in lib_base_to_id:
                        src = lib_base_to_id[base]
                if dst.startswith("lib:"):
                    base = ""
                    for node in (extra.get("nodes", []) or []):
                        if str(node.get("id", "")) == dst:
                            base = str(node.get("label", "") or "")
                            break
                    base = base.split("@")[0].strip().lower()
                    base = base.split(" (inferred)")[0]
                    if base and base in lib_base_to_id:
                        dst = lib_base_to_id[base]
                if src not in nodes or dst not in nodes:
                    continue
                key = (src, dst, rel)
                if key not in seen_edges:
                    seen_edges.add(key)
                    edges.append(GraphEdge(**{
                        "from": src, "to": dst, "relationship": rel}))
            except Exception:
                continue
    except Exception:
        pass

    try:
        return CIRDocument(
            cir_version=getattr(cir, "cir_version", "0.1"),
            scan_id=getattr(cir, "scan_id"),
            target=getattr(cir, "target"),
            started_at=getattr(cir, "started_at"),
            finished_at=getattr(cir, "finished_at"),
            tool_versions=dict(getattr(cir, "tool_versions", {}) or {}),
            registry_version=getattr(cir, "registry_version"),
            assets=new_assets,
            operations=final_operations,
            graph=Graph(nodes=list(nodes.values()), edges=edges),
            risks=list(getattr(cir, "risks", []) or []),
            recommendations=list(
                getattr(cir, "recommendations", []) or []),
        )
    except Exception:
        return cir
