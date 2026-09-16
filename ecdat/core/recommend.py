"""PQC / modern-crypto recommendation engine (Person-1 Agent C).

Stdlib-only, rule-based, deterministic — no LLM. The replacement choice
always comes from the ``RECOMMENDATIONS`` policy registry (detection
catalogue → migration path); risk scores only set priority/sorting.
An LLM may rephrase ``reason`` downstream, never change the target.

Each registry entry carries the six ``replacement_score`` factors::

    replacement_score = (.35*risk_reduction + .20*standards + .15*compat
                         + .10*latency + .10*effort + .10*cost)

``recommend_for_operation(op, risk=None)`` → Recommendation dict::

    {finding_id, operation_id, target_algorithms, migration_pattern,
     compatibility, effort, latency_cost_class, priority, reason, refs,
     replacement_score, rule_key}

``recommend_cir(cir, risks=None)`` → list sorted by priority
(Critical→Informational) then replacement_score desc, then operation_id.

CIR v0.1 interop: asset crypto facts are merged under each operation
before matching (same split as the risk engine), and
``to_cir_recommendation`` projects onto the wire Recommendation
(registry pqc_map preferred for ``pqc_target`` when importable).
"""

from __future__ import annotations

__all__ = [
    "RECOMMENDATIONS",
    "PRIORITY_ORDER",
    "replacement_score",
    "recommend_for_operation",
    "recommend_cir",
    "to_cir_recommendation",
]

PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3,
                  "Informational": 4}

_FIPS203 = "https://csrc.nist.gov/pubs/fips/203/final"          # ML-KEM
_FIPS204 = "https://csrc.nist.gov/pubs/fips/204/final"          # ML-DSA
_FIPS205 = "https://csrc.nist.gov/pubs/fips/205/final"          # SLH-DSA
_NCCOE = "https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc"
_SP1800 = ("https://www.nccoe.nist.gov/publications/practice-guide/"
           "migration-post-quantum-cryptography-nist-sp-1800-38-practice-guide")
_OQS = "https://openquantumsafe.org/liboqs/"


def _rec(targets, pattern, compat, effort, latency, priority_hint, reason,
         refs, factors):
    """Registry row builder. ``factors`` = (risk_reduction, standards,
    compat, latency, effort, cost) each 0..1 from the policy author's view."""
    return {
        "target_algorithms": list(targets),
        "migration_pattern": pattern,
        "compatibility": compat,
        "effort": effort,
        "latency_cost_class": latency,
        "priority_hint": priority_hint,
        "reason": reason,
        "refs": list(refs),
        "factors": {
            "risk_reduction": factors[0], "standards": factors[1],
            "compat": factors[2], "latency": factors[3],
            "effort": factors[4], "cost": factors[5],
        },
    }


# -- policy registry: catalogue detection -> migration path ----------------
RECOMMENDATIONS: dict[str, dict] = {
    "RSA-ENC": _rec(
        ["ML-KEM-768 (hybrid X25519+ML-KEM during transition)"],
        "hybrid-kem", "medium", "M", "medium", "High",
        "RSA key exchange/encryption is quantum-vulnerable; move KEM use to "
        "ML-KEM, hybrid with X25519 while peers lack PQC support.",
        [_FIPS203, _NCCOE, _OQS], (0.95, 1.0, 0.6, 0.7, 0.6, 0.6)),
    "RSA-SIG": _rec(
        ["ML-DSA-65 (alt: SLH-DSA-128s conservative profile)"],
        "sig-replace", "low", "L", "medium", "High",
        "RSA signatures are quantum-vulnerable; plan ML-DSA migration "
        "(SLH-DSA where hash-based conservatism is required). PKI/tooling "
        "compatibility is the main blocker.",
        [_FIPS204, _FIPS205, _NCCOE], (0.95, 1.0, 0.4, 0.6, 0.4, 0.5)),
    "DH": _rec(
        ["hybrid X25519+ML-KEM-768 (TLS 1.3 KEM)"],
        "hybrid-kex", "medium", "M", "low", "High",
        "Finite-field DH is quantum-vulnerable; move to TLS 1.3 and a "
        "ML-KEM hybrid group where available.",
        [_FIPS203, _NCCOE, _OQS], (0.9, 0.9, 0.6, 0.8, 0.6, 0.7)),
    "ECDH": _rec(
        ["hybrid X25519+ML-KEM-768"],
        "hybrid-kex", "medium", "M", "low", "High",
        "ECDH/X25519 key agreement is quantum-vulnerable despite classical "
        "strength; augment with ML-KEM hybrid.",
        [_FIPS203, _NCCOE, _OQS], (0.9, 0.9, 0.7, 0.8, 0.6, 0.7)),
    "ECDSA": _rec(
        ["ML-DSA-65 (alt: SLH-DSA-128s conservative profile)"],
        "sig-replace", "low", "L", "medium", "High",
        "ECDSA is quantum-vulnerable; migrate signing to ML-DSA (primary) "
        "or SLH-DSA (conservative/hash-based). Track signature size and "
        "verification cost.",
        [_FIPS204, _FIPS205, _NCCOE], (0.95, 1.0, 0.4, 0.6, 0.4, 0.5)),
    "EDDSA": _rec(
        ["ML-DSA-65 (alt: SLH-DSA-128s conservative profile)"],
        "sig-replace", "low", "M", "medium", "High",
        "Ed25519/Ed448 signatures are quantum-vulnerable; move to ML-DSA "
        "when the ecosystem supports it.",
        [_FIPS204, _FIPS205, _OQS], (0.95, 1.0, 0.4, 0.6, 0.5, 0.5)),
    "TLS-OLD": _rec(
        ["TLS 1.3 (AEAD ciphers, modern groups, PQ-hybrid-ready stack)"],
        "protocol-upgrade", "high", "S", "low", "High",
        "SSL/TLS 1.0/1.1 and weak ciphers are classically broken; upgrade to "
        "TLS 1.3 first, then pilot PQ-hybrid groups. Fix classical risk "
        "before claiming PQ readiness.",
        [_NCCOE, _SP1800], (0.8, 1.0, 0.9, 0.9, 0.8, 0.9)),
    "AES-ECB": _rec(
        ["AES-256-GCM (alt: ChaCha20-Poly1305)"],
        "aead-upgrade", "high", "S", "low", "High",
        "AES-ECB leaks plaintext structure; replace with an AEAD (AES-GCM "
        "or ChaCha20-Poly1305). Never acceptable for structured data.",
        [_NCCOE], (0.85, 0.9, 0.9, 0.9, 0.8, 0.9)),
    "CBC-NO-AUTH": _rec(
        ["AES-256-GCM (alt: ChaCha20-Poly1305)"],
        "aead-upgrade", "high", "S", "low", "Medium",
        "Unauthenticated CBC/CTR needs random IV plus a MAC; an AEAD "
        "simplifies the design -- prefer AES-GCM or ChaCha20-Poly1305.",
        [_NCCOE], (0.7, 0.9, 0.9, 0.9, 0.8, 0.9)),
    "DES-3DES-RC4": _rec(
        ["AES-256-GCM (alt: ChaCha20-Poly1305)"],
        "aead-upgrade", "high", "S", "low", "High",
        "DES/3DES/RC4 are broken or legacy-slow; modernize to AES-GCM or "
        "ChaCha20-Poly1305 immediately.",
        [_NCCOE], (0.9, 1.0, 0.9, 0.9, 0.8, 0.9)),
    "MD5-SHA1": _rec(
        ["SHA-256 / SHA-384 / SHA-3-256"],
        "hash-upgrade", "high", "S", "low", "Medium",
        "MD5/SHA-1 are broken for collision resistance; use SHA-256/384 or "
        "SHA-3 (checksum-only uses should be labelled, not scored).",
        [_NCCOE], (0.75, 1.0, 0.9, 0.9, 0.9, 0.9)),
    "PBKDF2-WEAK": _rec(
        ["Argon2id (alt: scrypt, bcrypt, or stronger PBKDF2 policy)"],
        "kdf-upgrade", "medium", "S", "low", "Medium",
        "Weak PBKDF2 iteration/salt policy risks passwords; prefer Argon2id "
        "(scrypt/bcrypt where stack-constrained) or a stronger PBKDF2 policy.",
        [_NCCOE], (0.7, 0.8, 0.7, 0.8, 0.8, 0.8)),
    "AES128-LONG": _rec(
        ["AES-256-GCM (alt: ChaCha20-Poly1305 by platform)"],
        "symmetric-margin", "high", "S", "low", "Medium",
        "AES-128 has reduced quantum margin for long-lived data; move "
        "long-lived sensitive records to AES-256-GCM.",
        [_NCCOE], (0.5, 0.8, 0.9, 0.9, 0.9, 0.9)),
    "PQC-OK": _rec(
        ["keep ML-KEM / ML-DSA / SLH-DSA (verify params + maturity)"],
        "verify-only", "high", "S", "low", "Low",
        "PQC already present; verify parameter level, implementation "
        "maturity and hybrid fallback instead of re-migrating.",
        [_FIPS203, _FIPS204, _FIPS205, _OQS], (0.2, 1.0, 0.9, 0.9, 0.9, 0.9)),
    "HYBRID-OK": _rec(
        ["keep hybrid (verify interop + cert strategy)"],
        "verify-only", "high", "S", "low", "Low",
        "Hybrid classical+PQC already deployed; verify peer interop, "
        "certificate size and fallback behaviour.",
        [_NCCOE, _OQS], (0.2, 0.9, 0.9, 0.9, 0.9, 0.9)),
    "CLASSICAL-OK": _rec(
        ["keep AES-256-GCM / ChaCha20-Poly1305 / SHA-256+ (monitor)"],
        "verify-only", "high", "S", "low", "Low",
        "Strong classical primitive with correct parameters; monitor "
        "inventory, no migration required.",
        [_NCCOE], (0.15, 0.9, 1.0, 1.0, 1.0, 1.0)),
    "REVIEW": _rec(
        ["confirm usage, then map to catalogue path"],
        "verify-only", "medium", "S", "low", "Informational",
        "Unmapped or ProvidedOnly finding; confirm real use before planning "
        "migration to avoid noisy roadmaps.",
        [_NCCOE], (0.1, 0.5, 0.7, 0.9, 0.9, 0.9)),
}


def _norm(text) -> str:
    return "".join(str(text or "").upper().split()).replace("_", "-").replace("/", "-")


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _first(mapping: dict, *keys, default=None):
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return default


def _rule_key(op: dict) -> str:
    """Map an operation dict to a RECOMMENDATIONS key (deterministic)."""
    canon_raw = str(_first(op, "canonical_name", "canonical", "algorithm",
                             "name", default="") or "")
    canonical = _norm(canon_raw)
    mode = _norm(_first(op, "mode", default=""))
    proto = _norm(_first(op, "protocol_version", "protocol", default=""))
    usage = _norm(_first(op, "usage", "operation-type", "operation_type", default=""))
    key_size = _first(op, "key_size", "keySize", default=None)
    context = _as_dict(op.get("context"))
    lifetime = _first(context, "data_lifetime_years", "data_lifetime", default=0) or 0
    text = " ".join([canonical, mode, proto, usage,
                     str(_first(op, "variant", "hash", default=""))])

    def has(*needles):
        return any(n in text for n in needles)

    if has("HYBRID") or ("+" in canon_raw
                         and has("ML-KEM", "MLKEM", "KYBER")):
        return "HYBRID-OK"
    if has("ML-KEM", "MLKEM", "KYBER", "ML-DSA", "MLDSA", "DILITHIUM",
           "SLH-DSA", "SLHDSA", "SPHINCS", "FN-DSA", "FALCON", "HQC"):
        return "PQC-OK"
    if has("X25519", "X448") and has("ML-KEM", "KYBER", "HYBRID"):
        return "HYBRID-OK"
    if "RSA" in canonical or "RSA" in text:
        if has("SIGN", "VERIFY", "CERT", "X.509", "CERTIFICATE", "WITH"):
            return "RSA-SIG"
        return "RSA-ENC"
    if has("X.509", "CERTIFICATE", "CERT-"):
        # X.509 / certificate inventory uses public-key auth -> signature path.
        if has("ECDSA", "EC-"):
            return "ECDSA"
        return "RSA-SIG"
    if has("ED25519", "ED448", "EDDSA"):
        return "EDDSA"
    if has("ECDSA"):
        return "ECDSA"
    if has("ECDH", "X25519", "X448"):
        return "ECDH"
    if has("FFDHE") or canonical in ("DH",) or has("DIFFIE"):
        return "DH"
    if has("DSA") and not has("ML-DSA", "SLH-DSA"):
        return "RSA-SIG"  # legacy DSA sig path mirrors RSA-SIG migration
    if has("SSL", "TLS1.0", "TLS1.1", "TLSV1", "TLSV1.0", "TLSV1.1"):
        return "TLS-OLD"
    if has("TLS") and ("CBC" in text or "RC4" in text or "DES" in text):
        return "TLS-OLD"
    if has("TLS"):
        return "CLASSICAL-OK"  # TLS 1.2/1.3 with modern suites: monitor
    if has("ECB"):
        return "AES-ECB"
    if has("DES", "RC4", "ARC4"):
        return "DES-3DES-RC4"
    if has("MD5", "SHA1", "SHA-1"):
        return "MD5-SHA1"
    if has("PBKDF2"):
        return "PBKDF2-WEAK"
    if has("CBC", "CTR", "OFB", "CFB") and not has("GCM", "POLY1305", "CCM", "EAX", "OCB"):
        return "CBC-NO-AUTH"
    if has("AES-128", "AES128"):
        try:
            life = float(lifetime)
        except (TypeError, ValueError):
            life = 0.0
        if life >= 7 or "LONG" in text:
            return "AES128-LONG"
        return "CLASSICAL-OK"
    if has("AES-256", "AES256", "AES-192", "CHACHA", "GCM", "POLY1305",
           "SHA256", "SHA384", "SHA512", "SHA-256", "SHA-2", "SHA-3",
           "KECCAK", "BLAKE", "HMAC", "BCRYPT", "SCRYPT", "ARGON2", "HKDF"):
        return "CLASSICAL-OK"
    state = _norm(_first(_as_dict(op.get("risk_inputs")), "usage_state",
                          default=None)
                  or _first(op, "usage_state", "state", default=""))
    if state in ("PROVIDEDONLY", "PROVIDED-ONLY", "SUPPRESSED",
                 "FALSEPOSITIVESUPPRESSED"):
        return "REVIEW"
    return "REVIEW"


def replacement_score(risk_reduction: float, standards: float, compat: float,
                      latency: float, effort: float, cost: float) -> float:
    """Policy replacement score 0..1 (spec weights), rounded to 3 decimals."""
    score = (0.35 * float(risk_reduction) + 0.20 * float(standards)
             + 0.15 * float(compat) + 0.10 * float(latency)
             + 0.10 * float(effort) + 0.10 * float(cost))
    return round(min(1.0, max(0.0, score)), 3)


def _priority_for(rule_key: str, risk: dict | None) -> str:
    if isinstance(risk, dict) and risk.get("class") in PRIORITY_ORDER:
        # PQC/classical-healthy findings never page above Low via risk alone.
        if rule_key in ("PQC-OK", "HYBRID-OK", "CLASSICAL-OK"):
            return "Low" if risk.get("class") in ("Critical", "High") else risk["class"]
        if rule_key == "REVIEW" and risk.get("class") in ("Critical", "High"):
            return "Medium"  # unmapped items do not inherit Critical
        return risk["class"]
    return RECOMMENDATIONS[rule_key]["priority_hint"]


def recommend_for_operation(op: dict, risk: dict | None = None) -> dict:
    """Build one Recommendation dict for an operation (+ optional RiskRecord)."""
    if not isinstance(op, dict):
        raise TypeError("recommend_for_operation expects an operation dict")
    if risk is not None and not isinstance(risk, dict):
        raise TypeError("risk must be a RiskRecord dict or None")
    op_id = str(_first(op, "operation_id", "id", "op_id", default="op-unknown"))
    rule_key = _rule_key(op)
    template = RECOMMENDATIONS[rule_key]
    priority = _priority_for(rule_key, risk)

    risk_reduction = template["factors"]["risk_reduction"]
    if isinstance(risk, dict) and isinstance(risk.get("score"), (int, float)):
        # Scale author's risk_reduction by the measured risk so the score
        # reflects this instance, not just the catalogue row.
        risk_reduction = round(template["factors"]["risk_reduction"]
                               * min(1.0, max(0.0, float(risk["score"]))) * 2.0, 3)
        risk_reduction = min(1.0, risk_reduction)
    score = replacement_score(risk_reduction, template["factors"]["standards"],
                              template["factors"]["compat"], template["factors"]["latency"],
                              template["factors"]["effort"], template["factors"]["cost"])
    canonical = str(_first(op, "canonical_name", "canonical", "algorithm",
                             default="UNKNOWN"))
    asset_ids = _asset_ids_of(op)
    reason = (f"{canonical} [{op_id}] -> {', '.join(template['target_algorithms'])}. "
              f"{template['reason']} Priority {priority} "
              f"(replacement_score {score:.3f}).")
    return {
        "finding_id": op_id,
        "operation_id": op_id,
        "rule_key": rule_key,
        "asset_ids": asset_ids,
        "target_algorithms": list(template["target_algorithms"]),
        "migration_pattern": template["migration_pattern"],
        "compatibility": template["compatibility"],
        "effort": template["effort"],
        "latency_cost_class": template["latency_cost_class"],
        "priority": priority,
        "reason": reason,
        "refs": list(template["refs"]),
        "replacement_score": score,
    }


def _asset_ids_of(op: dict) -> list[str]:
    single = op.get("asset_id")
    ids = [single] if isinstance(single, str) and single else []
    multi = op.get("asset_ids")
    if isinstance(multi, list):
        ids.extend(x for x in multi if isinstance(x, str) and x)
    seen: dict[str, None] = {}
    for ident in ids:
        seen.setdefault(ident)
    return list(seen)


def _merge_asset_view(op: dict, assets_by_id: dict) -> dict:
    """Overlay the linked CryptoAsset's fields under a CIR operation."""
    if not assets_by_id or not isinstance(op, dict):
        return op
    aid = op.get("asset_id")
    if not isinstance(aid, str):
        ids = op.get("asset_ids")
        aid = ids[0] if isinstance(ids, list) and ids else None
    asset = assets_by_id.get(aid) if isinstance(aid, str) else None
    if not isinstance(asset, dict):
        return op
    merged = dict(asset)
    for key, value in op.items():
        if value is not None and value != "":
            merged[key] = value
    return merged


def recommend_cir(cir, risks: list[dict] | dict | None = None) -> list[dict]:
    """Recommend for every operation in a CIR dict (or bare op list).

    Accepts CIR v0.1 documents (operations reference assets by asset_id;
    asset crypto facts are merged under each operation before matching),
    rich Agent C operation dicts, or a bare operation list. ``risks`` may
    be a ``score_cir`` list or an ``{op_id: RiskRecord}`` map; when
    omitted, priorities fall back to registry hints. Sorted by priority,
    then replacement_score desc, then operation_id.
    """
    if isinstance(cir, dict):
        ops = cir.get("operations", []) or []
        assets_by_id = {a.get("asset_id"): a for a in (cir.get("assets", []) or [])
                        if isinstance(a, dict) and a.get("asset_id")}
    else:
        ops = cir or []
        assets_by_id = {}
    by_id: dict[str, dict] = {}
    if isinstance(risks, dict):
        by_id = {str(k): v for k, v in risks.items() if isinstance(v, dict)}
    elif isinstance(risks, list):
        for record in risks:
            if isinstance(record, dict) and record.get("operation_id"):
                by_id[str(record["operation_id"])] = record
    recs = [recommend_for_operation(_merge_asset_view(op, assets_by_id), by_id.get(
        str(_first(op, "operation_id", "id", "op_id", default=""))))
        for op in ops if isinstance(op, dict)]
    recs.sort(key=lambda r: (PRIORITY_ORDER.get(r["priority"], 9),
                             -r["replacement_score"], r["operation_id"]))
    return recs


def _pqc_target_for(rec: dict, canonical: str) -> str:
    """Best PQC target name: registry pqc_map first, else cleaned template."""
    try:
        from ecdat.core.registry import pqc_targets_for
        targets = pqc_targets_for({"canonical": canonical,
                                   "mode": "", "operation_type": ""})
        if targets:
            return str(targets[0])
    except ImportError:
        pass
    first = (rec.get("target_algorithms") or ["review"])[0]
    return str(first).split(" (")[0].strip() or "review"


def to_cir_recommendation(rec: dict, asset_ids: list[str] | None = None,
                          canonical: str = "UNKNOWN") -> dict:
    """Project an internal Recommendation onto the CIR v0.1 wire shape.

    Returns ``{recommendation_id, title, description, priority, asset_ids,
    pqc_target}`` validating against cir.schema.json Recommendation
    (additionalProperties-safe).
    """
    import hashlib

    if not isinstance(rec, dict):
        raise TypeError("to_cir_recommendation expects a recommendation dict")
    op_id = str(rec.get("operation_id", rec.get("finding_id", "op-unknown")))
    seed = f"{op_id}|{rec.get('rule_key', '')}"
    digest = hashlib.blake2s(seed.encode("utf-8")).hexdigest()[:16]
    aids = list(asset_ids) if asset_ids else list(rec.get("asset_ids", []) or [])
    priority = rec.get("priority", "Informational")
    if priority not in PRIORITY_ORDER:
        priority = "Informational"
    targets = list(rec.get("target_algorithms", []) or [])
    title = f"Migrate {canonical} [{op_id}] to {targets[0] if targets else 'reviewed primitive'}"
    return {
        "recommendation_id": f"rec:{digest}",
        "title": title[:300],
        "description": str(rec.get("reason", "")),
        "priority": priority,
        "asset_ids": aids,
        "pqc_target": _pqc_target_for(rec, canonical),
    }
