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

from ecdat.core.fusion import decide_usage, redact_snippet, weighted_fusion

__all__ = ["build_operations", "group_key_for", "dedup_key_for"]

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


def build_operations(raw_hits: list[dict] | tuple[dict, ...] | None) -> list[dict]:
    """Collapse raw hits into sorted CryptoOperation dicts.

    Args:
        raw_hits: each hit may carry asset fields, location
            (file/function/service/endpoint), implementation flags
            (param_resolved/binary_support/config_runtime_agreement),
            ``evidence`` (list of detector/signal_type/confidence), and
            context (dependency_only/is_test_fixture/is_checksum_only/
            snippet/asset_id). Missing keys default sensibly.

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
        base = group_key_for(hit)
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
        }
        ops.append(op)

    ops.sort(key=lambda o: (-float(o.get("confidence", 0.0)), str(o.get("id", ""))))
    return ops
