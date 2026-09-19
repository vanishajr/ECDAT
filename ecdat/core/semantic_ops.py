"""Phase 4 semantic operation reconstruction + Phase 7 correlation/dedup.

Where :mod:`ecdat.core.operations` collapses raw hits by an exact
9-tuple group key, this module reconstructs *semantic* operations: one
``CryptoOperation`` dict per real-world crypto use, with a resolved
lifecycle (primitive/algorithm/variant/mode/operation/key/provider...),
full evidence provenance, and correlation by semantic identity.

Core contract: **unknown stays ``None``/``"unresolved"`` -- never
guessed.** Every resolver returns ``None`` when the hits carry no
signal, and every merge preserves all evidence locations.
"""

from __future__ import annotations

from typing import Any

from ecdat.core.evidence import EvidenceClass, classify_evidence

__all__ = [
    "UNRESOLVED",
    "build_semantic_operation",
    "semantic_identity_key",
    "correlate_operations",
    "dedup_metrics",
]

UNRESOLVED = "unresolved"

# Canonical-name substring -> primitive family. Only matched families are
# reported; anything else stays None (never guessed).
_PRIMITIVE_TABLE: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("symmetric-encryption", ("AES", "DES", "3DES", "CHACHA", "CAMELLIA",
                              "ARIA", "SM4", "BLOWFISH", "TWOFISH")),
    ("asymmetric-encryption", ("RSA",)),
    ("signature", ("ECDSA", "EDDSA", "ED25519", "DSA", "ECGDSA", "SM2")),
    ("key-exchange", ("DH", "ECDH", "X25519", "X448", "KYBER", "ML-KEM")),
    ("hash", ("SHA", "MD5", "BLAKE", "SHAKE", "SM3", "WHIRLPOOL")),
    ("mac", ("HMAC", "POLY1305", "CMAC", "GMAC", "SIPHash".upper())),
    ("kdf", ("HKDF", "PBKDF", "SCRYPT", "ARGON", "BCRYPT", "KDF")),
    ("protocol", ("TLS", "SSL", "SSH", "IPSEC", "QUIC", "DTLS")),
    ("random", ("DRBG", "CSPRNG", "RDRAND", "GETRANDOM", "URANDOM")),
)


def _s(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _nested(hit: dict, *names: str, default: Any = None) -> Any:
    if not isinstance(hit, dict):
        return default
    if names[0] in hit and hit[names[0]] is not None:
        return hit[names[0]]
    for container in ("asset", "location", "implementation", "context"):
        sub = hit.get(container)
        if isinstance(sub, dict):
            for name in names:
                if name in sub and sub[name] is not None:
                    return sub[name]
    return default


def _norm_str(value: Any) -> str | None:
    text = _s(value).strip()
    return text or None


def _infer_primitive(canonical: str | None) -> str | None:
    upper = (canonical or "").upper()
    if not upper:
        return None
    for primitive, needles in _PRIMITIVE_TABLE:
        for needle in needles:
            if needle and needle in upper:
                return primitive
    return None


def _tool_of(evidence_item: Any) -> str:
    if isinstance(evidence_item, dict):
        for key in ("tool", "detector"):
            value = evidence_item.get(key)
            if value:
                return _s(value)
        return ""
    try:
        return _s(getattr(evidence_item, "tool", "") or "")
    except Exception:
        return ""


def _confidence_of(item: Any) -> float:
    if isinstance(item, dict):
        try:
            return float(item.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            return 0.0
    try:
        return float(getattr(item, "confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _hit_confidence(hit: dict) -> float:
    direct = hit.get("confidence")
    try:
        if direct is not None:
            return float(direct)
    except (TypeError, ValueError):
        pass
    best = 0.0
    evidence = hit.get("evidence")
    if isinstance(evidence, list):
        for item in evidence:
            best = max(best, _confidence_of(item))
    return best


def build_semantic_operation(grouped_hits: list[dict] | tuple[dict, ...] | None) -> dict:
    """Reconstruct one semantic ``CryptoOperation`` dict from grouped hits.

    Args:
        grouped_hits: raw detector hits believed to describe the same
            real-world crypto use (e.g. one :func:`group_key_for` group).

    Returns:
        Dict with ``primitive, algorithm, variant, mode, operation, key,
        nonce_iv, random_source, provider, call_sequence, locations,
        scope, evidence, confidence``. Anything the hits do not establish
        stays ``None`` (scalars) or ``[]``/``{}`` -- never guessed.
    """
    hits = [h for h in (grouped_hits or []) if isinstance(h, dict)]

    algorithm: str | None = None
    variant: str | None = None
    mode: str | None = None
    operation: str | None = None
    key_size: int | str | None = None
    curve: str | None = None
    protocol: str | None = None
    nonce_iv: Any = None
    random_source: str | None = None
    provider: str | None = None
    call_sequence: list[str] = []
    locations: list[dict] = []
    evidence: list[dict] = []
    scope_file: str | None = None
    scope_service: str | None = None
    scope_endpoint: str | None = None
    confidence = 0.0

    seen_calls: set[str] = set()
    seen_locations: set[tuple] = set()

    for hit in hits:
        canonical = _norm_str(_nested(
            hit, "canonical_name", "canonicalName", "algorithm", "name"))
        if canonical and algorithm is None:
            algorithm = canonical
        op_type = _norm_str(_nested(
            hit, "operation_type", "operationType", "type"))
        if op_type and operation is None:
            operation = op_type
        mode_v = _norm_str(_nested(hit, "mode"))
        if mode_v and mode is None:
            mode = mode_v
        curve_v = _norm_str(_nested(hit, "curve", "ec_curve", "named_curve"))
        if curve_v and curve is None:
            curve = curve_v
        proto_v = _norm_str(_nested(hit, "protocol"))
        if proto_v and protocol is None:
            protocol = proto_v
        ks = _nested(hit, "key_size", "keySize", "bits")
        if ks is not None and key_size is None:
            try:
                key_size = int(ks)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                key_size = _norm_str(ks)
        for key in ("nonce_iv", "nonce", "iv"):
            value = _nested(hit, key)
            if value not in (None, "") and nonce_iv is None:
                nonce_iv = value
        rs = _norm_str(_nested(
            hit, "random_source", "randomSource", "rng", "drbg"))
        if rs and random_source is None:
            random_source = rs
        prov = _norm_str(_nested(
            hit, "provider", "library", "implementation"))
        if prov is None:
            impl = hit.get("implementation")
            if isinstance(impl, dict):
                prov = _norm_str(impl.get("provider", impl.get("library")))
        if prov and provider is None:
            provider = prov

        symbol = _norm_str(_nested(
            hit, "function", "function_name", "symbol", "api", "call"))
        if symbol and symbol not in seen_calls:
            seen_calls.add(symbol)
            call_sequence.append(symbol)

        loc = {
            "file": _norm_str(_nested(hit, "file", "path", "filename")),
            "function": symbol,
            "line": _nested(hit, "line", "line_number", "lineno"),
            "service": _norm_str(_nested(hit, "service")),
            "endpoint": _norm_str(_nested(
                hit, "endpoint", "url", "host", "uri")),
        }
        loc_key = tuple(sorted((k, _s(v)) for k, v in loc.items()))
        if loc_key not in seen_locations:
            seen_locations.add(loc_key)
            locations.append(loc)

        if scope_file is None and loc["file"]:
            scope_file = loc["file"]
        if scope_service is None and loc["service"]:
            scope_service = loc["service"]
        if scope_endpoint is None and loc["endpoint"]:
            scope_endpoint = loc["endpoint"]

        raw_evidence = hit.get("evidence")
        items = raw_evidence if isinstance(raw_evidence, list) else []
        if not items and (hit.get("detector") or hit.get("tool")):
            items = [hit]
        for item in items:
            tool = _tool_of(item) or _s(hit.get("tool", ""))
            try:
                klass = classify_evidence(tool).value
            except Exception:
                klass = EvidenceClass.REFERENCE.value
            detail = ""
            if isinstance(item, dict):
                detail = _s(item.get("detail", item.get("signal_type", "")))
            evidence.append({
                "tool": tool or "unknown",
                "class": klass,
                "detail": detail,
                "confidence": _confidence_of(item),
            })

        confidence = max(confidence, _hit_confidence(hit))

    # Variant: the most specific algorithm spelling observed (e.g. the
    # longest canonical name such as "AES-256-GCM" over "AES"); stays
    # None when nothing was observed -- never synthesised.
    if algorithm:
        variant = algorithm
    key: dict | None = None
    if key_size is not None or curve is not None:
        key = {"size": key_size, "curve": curve}

    return {
        "primitive": _infer_primitive(algorithm),
        "algorithm": algorithm,
        "variant": variant,
        "mode": mode,
        "operation": operation,
        "key": key,
        "nonce_iv": nonce_iv,
        "random_source": random_source,
        "provider": provider,
        "call_sequence": call_sequence,
        "locations": locations,
        "scope": {
            "file": scope_file,
            "service": scope_service,
            "endpoint": scope_endpoint,
        },
        "evidence": evidence,
        "confidence": round(min(1.0, max(0.0, confidence)), 3),
    }


def semantic_identity_key(semantic_op: dict) -> tuple:
    """Return the Phase 7 semantic identity tuple for one operation.

    Identity = ``(primitive, variant, mode, key_size, curve, protocol,
    op_type, scope, build_state, symbol lineage, provider)`` with
    ``None`` normalised to ``""`` so the key is hashable and stable.
    """
    if not isinstance(semantic_op, dict):
        return ("",) * 11
    key = semantic_op.get("key") or {}
    scope = semantic_op.get("scope") or {}
    if isinstance(scope, dict):
        scope_key = (_s(scope.get("file")), _s(scope.get("service")),
                     _s(scope.get("endpoint")))
    else:
        scope_key = (_s(scope), "", "")
    lineage = semantic_op.get("call_sequence") or []
    try:
        lineage_key = tuple(sorted(_s(c) for c in lineage))
    except Exception:
        lineage_key = ()
    key_size = key.get("size") if isinstance(key, dict) else semantic_op.get("key_size")
    curve = (key.get("curve") if isinstance(key, dict)
             else semantic_op.get("curve"))
    return (
        _s(semantic_op.get("primitive")),
        _s(semantic_op.get("variant", semantic_op.get("algorithm"))),
        _s(semantic_op.get("mode")),
        _s(key_size),
        _s(curve),
        _s(semantic_op.get("protocol")),
        _s(semantic_op.get("operation", semantic_op.get("operation_type"))),
        scope_key,
        _s(semantic_op.get("build_state", semantic_op.get("usage_state"))),
        lineage_key,
        _s(semantic_op.get("provider")),
    )


def _as_semantic_op(item: Any) -> dict:
    if isinstance(item, dict) and (
            "algorithm" in item or "primitive" in item or "variant" in item):
        return item
    if isinstance(item, dict):
        return build_semantic_operation([item])
    return build_semantic_operation([])


def _merge_semantic_ops(members: list[dict]) -> dict:
    first = members[0]
    evidence: list[dict] = []
    locations: list[dict] = []
    calls: list[str] = []
    seen_evidence: set[tuple] = set()
    seen_locations: set[tuple] = set()
    seen_calls: set[str] = set()
    confidence = 0.0
    for member in members:
        for item in (member.get("evidence") or []):
            if not isinstance(item, dict):
                continue
            key = (_s(item.get("tool")), _s(item.get("class")),
                   _s(item.get("detail")), _s(item.get("confidence")))
            if key not in seen_evidence:
                seen_evidence.add(key)
                evidence.append(item)
        for loc in (member.get("locations") or []):
            if not isinstance(loc, dict):
                continue
            key = tuple(sorted((k, _s(v)) for k, v in loc.items()))
            if key not in seen_locations:
                seen_locations.add(key)
                locations.append(loc)
        for symbol in (member.get("call_sequence") or []):
            if symbol not in seen_calls:
                seen_calls.add(symbol)
                calls.append(symbol)
        try:
            confidence = max(confidence, float(member.get("confidence", 0.0)))
        except (TypeError, ValueError):
            pass
    merged = dict(first)
    merged["evidence"] = evidence
    merged["locations"] = locations
    merged["call_sequence"] = sorted(calls)
    merged["confidence"] = round(min(1.0, max(0.0, confidence)), 3)
    merged["evidence_count"] = len(evidence)
    merged["merged_from"] = len(members)
    return merged


def correlate_operations(semantic_ops: list[dict] | tuple | None) -> list[dict]:
    """Collapse semantic operations by semantic identity (Phase 7).

    Accepts semantic-op dicts (as returned by
    :func:`build_semantic_operation`) or raw hits / hit-groups (each
    item is first reconstructed via :func:`build_semantic_operation`).
    Members sharing :func:`semantic_identity_key` modulo symbol lineage
    merge into one op: a direct API call and its wrapper share crypto,
    scope and provider but differ in call symbol, and must not explode
    into duplicates. The lineage union is preserved in the merged
    ``call_sequence``, **all** evidence and locations are preserved
    (deduped, never dropped), and confidence is the member max. Output
    is sorted by ``(confidence desc, variant, operation)`` for
    determinism.
    """
    items = list(semantic_ops or [])
    if not items:
        return []
    groups: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    for item in items:
        if isinstance(item, (list, tuple)):
            sem = build_semantic_operation(list(item))
        else:
            sem = _as_semantic_op(item)
        full = semantic_identity_key(sem)
        try:
            key = full[:9] + full[10:]  # identity modulo symbol lineage
        except Exception:
            key = full
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(sem)
    merged = [_merge_semantic_ops(groups[key]) for key in order]
    merged.sort(key=lambda o: (
        -float(o.get("confidence", 0.0) or 0.0),
        _s(o.get("variant", o.get("algorithm"))),
        _s(o.get("operation"))))
    return merged


def dedup_metrics(raw: Any, logical: Any) -> dict:
    """Summarise a raw-hit -> logical-operation collapse (Phase 7).

    Args:
        raw: raw hit count, or the raw-hit list itself.
        logical: logical operation count, or the operation list itself.

    Returns:
        ``{raw_hits, logical_ops, duplicates_removed, dedup_ratio,
        reduction_factor}`` where ``dedup_ratio = 1 - logical/raw``
        (0.0 when ``raw`` is 0) and ``reduction_factor = raw/logical``
        (0.0 when ``logical`` is 0).
    """
    raw_hits = len(raw) if isinstance(raw, (list, tuple)) else int(raw or 0)
    logical_ops = (len(logical) if isinstance(logical, (list, tuple))
                   else int(logical or 0))
    raw_hits = max(0, raw_hits)
    logical_ops = max(0, logical_ops)
    removed = max(0, raw_hits - logical_ops)
    ratio = (1.0 - logical_ops / raw_hits) if raw_hits else 0.0
    factor = (raw_hits / logical_ops) if logical_ops else 0.0
    return {
        "raw_hits": raw_hits,
        "logical_ops": logical_ops,
        "duplicates_removed": removed,
        "dedup_ratio": round(ratio, 3),
        "reduction_factor": round(factor, 3),
    }
