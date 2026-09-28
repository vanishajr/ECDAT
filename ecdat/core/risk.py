"""Quantum risk engine (Person-1 Agent C).

Stdlib-only, pure, deterministic. Scores CIR-shaped operation dicts with a
Mosca-style model plus exposure / criticality / confidence. No DB, no
network, no LLM. Single linear pass per operation; O(n) per CIR.

Inputs per reference architecture:
  X = data confidentiality lifetime (years)
  Y = migration / replacement lead time (years)
  Z = expected years to a cryptographically relevant quantum computer
  Q = quantum vulnerability of the algorithm family (0..1)
  E = exposure weight (0..1)
  B = business criticality weight (0..1)
  C = confidence the artefact is actually used (0..1)

Mosca trigger: ``X + Y > Z`` → urgent quantum migration risk.

Score (spec, clamped to 0..1, rounded to 3 decimals)::

    score = clamp(.35*Q + .20*E + .15*B + .15*C + .15*mosca_boost)

where ``mosca_boost`` is 1.0 when the Mosca trigger fires, else 0.0.

Classes: >=.8 Critical, >=.6 High, >=.4 Medium, >=.2 Low, else
Informational. ``ProvidedOnly`` caps at Low; any Suppressed state forces
Informational with score 0.0 (dependency-only noise must not page owners).

CIR v0.1 interop: ``score_cir`` merges each operation's linked asset
(canonical/key_size/mode live on the asset per cir.schema.json) under the
operation before scoring, and reads usage/exposure from ``risk_inputs``
plus ``data_classification``/``notes`` gap-fillers when rich context is
absent. ``to_cir_risk`` projects the internal record onto the wire
RiskRecord (score scaled 0..1 -> 0..10).

NOTE on QUANTUM_VULN: the table folds a *classical-weakness floor* into Q
for broken symmetric/hash primitives (MD5, SHA-1, DES, RC4, AES-ECB,
TLS 1.0, ...) so they still prioritize under the single-formula
constraint. The floor is documented per entry in ``_CLASSICAL_FLOOR`` and
surfaced in the explanation string.
"""

from __future__ import annotations

import hashlib
import re

__all__ = [
    "QUANTUM_VULN",
    "EXPOSURE_W",
    "CRIT_W",
    "USAGE_CONFIDENCE",
    "mosca_trigger",
    "quantum_vuln",
    "score_operation",
    "score_cir",
    "to_cir_risk",
    "assess_classical_posture",
    "assess_misuse_severity",
    "assess_protocol_posture",
    "assess_quantum_exposure",
    "score_operation_v2",
]

# -- algorithm -> quantum vulnerability (0.0 safe .. 1.0 broken by CRQC) ----
QUANTUM_VULN: dict[str, float] = {
    # Public-key crypto: broken by a cryptographically relevant QC.
    "RSA": 1.0,
    "DSA": 1.0,
    "DH": 1.0,
    "ECDH": 1.0,
    "ECDSA": 1.0,
    "X25519": 1.0,
    "X448": 1.0,
    "ED25519": 1.0,
    "ED448": 1.0,
    "ELGAMAL": 1.0,
    # Hybrid classical+PQC: residual classical risk only.
    "HYBRID": 0.35,
    # NIST PQC families.
    "ML-KEM": 0.0,
    "ML-DSA": 0.0,
    "SLH-DSA": 0.0,
    "FN-DSA": 0.0,
    "HQC": 0.0,
    # Symmetric: Grover-style margin reduction only (AES-256 acceptable).
    "AES": 0.15,          # 0.30 when key_size < 256 (see quantum_vuln)
    "CHACHA20": 0.10,
    "POLY1305": 0.05,
    "HMAC": 0.05,
    "SHA-2": 0.05,
    "SHA-3": 0.03,
    "BLAKE": 0.03,
    "HKDF": 0.05,
    # Classical-weakness floor (broken/legacy even ignoring quantum).
    "MD5": 0.60,
    "SHA-1": 0.50,
    "DES": 0.70,
    "3DES": 0.50,
    "RC4": 0.70,
    "BLOWFISH": 0.35,
    "AES-ECB": 0.45,
    "TLS-OLD": 0.60,      # SSLv2/v3, TLS 1.0/1.1
    "TLS12": 0.30,
    "TLS13": 0.10,
    "PBKDF2-WEAK": 0.30,
    "PBKDF2": 0.10,
    "BCRYPT": 0.05,
    "SCRYPT": 0.05,
    "ARGON2": 0.05,
    "X.509": 0.90,        # cert inherits public-key risk; refined by key algo
    "UNKNOWN": 0.50,      # conservative default for unmapped names
}

# Entries whose Q is (partly) a classical floor rather than pure quantum risk.
_CLASSICAL_FLOOR = {
    "MD5", "SHA-1", "DES", "3DES", "RC4", "BLOWFISH", "AES-ECB",
    "TLS-OLD", "TLS12", "PBKDF2-WEAK", "X.509",
}

EXPOSURE_W: dict[str, float] = {
    "internet-facing": 1.0,
    "cloud": 0.85,
    "third-party": 0.80,
    "internal": 0.50,
    "offline": 0.20,
}

CRIT_W: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.50,
    "low": 0.25,
}

USAGE_CONFIDENCE: dict[str, float] = {
    "confirmed": 1.0,
    "probable": 0.75,
    "possible": 0.50,
    "providedonly": 0.25,
    "provided-only": 0.25,
    "suppressed": 0.0,
    "falsepositivesuppressed": 0.0,
}

_SUPPRESSED = {"SUPPRESSED", "FALSEPOSITIVESUPPRESSED", "FALSE-POSITIVE-SUPPRESSED",
               "SUPPRESSED-FP"}

_EXPOSURE_ALIASES = {
    "internet": "internet-facing", "public": "internet-facing",
    "external": "internet-facing", "dmz": "internet-facing",
    "aws": "cloud", "azure": "cloud", "gcp": "cloud",
    "thirdparty": "third-party", "partner": "third-party", "vendor": "third-party",
    "intranet": "internal", "corp": "internal",
    "airgapped": "offline", "air-gapped": "offline", "test": "offline",
}

_DEFAULT_X = 5.0   # data lifetime years assumed when undeclared
_DEFAULT_Y = 3.0   # migration lead time years assumed when undeclared

# CIR v0.1 data_classification -> (criticality label, lifetime hint years).
# Only fills gaps: explicit criticality / X inputs always win.
_CLASSIFICATION_HINTS = {
    "restricted": ("critical", 10.0),
    "confidential": ("high", 7.0),
    "internal": ("medium", 5.0),
    "public": ("low", 2.0),
}

_NOTES_X_RE = re.compile(r"data_lifetime_years\s*=\s*([\d.]+)")
_NOTES_Y_RE = re.compile(r"migration_years\s*=\s*([\d.]+)")

# Phase 10: user-supplied scan context rides in operation context notes as
# ``user:<key>=<value>`` pairs (see ScanContext in core/orchestrator.py).
# User values win over every observed/inferred signal and are tagged
# ``user-supplied`` in the record provenance. Provenance vocabulary:
# observed (detector/context evidence), inferred (hints, gap-fillers,
# caller defaults recorded as explicit assumptions), user-supplied
# (Phase 10 ScanContext), unknown (no basis; scored conservatively).
_USER_RE_TMPL = r"user:%s\s*=\s*([^;]+)"
_USER_EXPOSURE_RE = re.compile(_USER_RE_TMPL % "exposure")
_USER_CRIT_RE = re.compile(_USER_RE_TMPL % "(?:criticality|business_criticality)")
_USER_X_RE = re.compile(_USER_RE_TMPL % "(?:data_lifetime_years|data_lifetime)")
_USER_Y_RE = re.compile(_USER_RE_TMPL % "(?:migration_years|migration_time)")


def _user_note(context: dict, pattern) -> str | None:
    """First ``user:<key>=`` value in context notes, if any."""
    try:
        notes = str(context.get("notes", "") or "")
    except Exception:
        return None
    if not notes:
        return None
    match = pattern.search(notes)
    if not match:
        return None
    value = " ".join(match.group(1).split())
    return value or None


def _norm(text) -> str:
    return "".join(str(text or "").upper().split()).replace("_", "-").replace("/", "-")


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _first(mapping: dict, *keys, default=None):
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return default


def mosca_trigger(X, Y, Z) -> bool:
    """Mosca inequality: data lifetime + migration time exceeds QC timeline."""
    return (float(X) + float(Y)) > float(Z)


def quantum_vuln(canonical_name, key_size=None, mode=None,
                 protocol_version=None) -> float:
    """Look up Q for an algorithm name (+ params). Deterministic.

    AES with ``key_size < 256`` scores 0.30 (reduced Grover margin);
    AES-ECB scores the 0.45 misuse floor regardless of key size.
    Unknown names fall back to 0.50 (conservative, documented).
    """
    norm = _norm(canonical_name)
    mod = _norm(mode)
    proto = _norm(protocol_version)

    def has(*needles):
        return any(n in norm or n in mod or n in proto for n in needles)

    if has("HYBRID") or ("+" in str(canonical_name or "") and has("ML-KEM", "KYBER")):
        return QUANTUM_VULN["HYBRID"]
    if has("ML-KEM", "MLKEM", "KYBER"):
        return QUANTUM_VULN["ML-KEM"]
    if has("ML-DSA", "MLDSA", "DILITHIUM"):
        return QUANTUM_VULN["ML-DSA"]
    if has("SLH-DSA", "SLHDSA", "SPHINCS"):
        return QUANTUM_VULN["SLH-DSA"]
    if has("FN-DSA", "FNDSA", "FALCON"):
        return QUANTUM_VULN["FN-DSA"]
    if has("HQC"):
        return QUANTUM_VULN["HQC"]
    if has("X25519"):
        return QUANTUM_VULN["X25519"]
    if has("X448"):
        return QUANTUM_VULN["X448"]
    if has("ED25519"):
        return QUANTUM_VULN["ED25519"]
    if has("ED448"):
        return QUANTUM_VULN["ED448"]
    if has("ECDSA"):
        return QUANTUM_VULN["ECDSA"]
    if has("ECDH"):
        return QUANTUM_VULN["ECDH"]
    if has("ELGAMAL"):
        return QUANTUM_VULN["ELGAMAL"]
    if has("3DES", "DESEDE", "TRIPLEDES", "TDEA"):
        return QUANTUM_VULN["3DES"]
    if has("DES") and not has("DESCRIBE"):
        return QUANTUM_VULN["DES"]
    if has("RC4", "ARC4"):
        return QUANTUM_VULN["RC4"]
    if has("BLOWFISH", "TWOFISH"):
        return QUANTUM_VULN["BLOWFISH"]
    if has("RSA"):
        return QUANTUM_VULN["RSA"]
    if has("DSA") and not has("ML-DSA", "SLH-DSA", "FN-DSA"):
        return QUANTUM_VULN["DSA"]
    if has("DIFFIE", "D-H") or norm in ("DH", "FFDHE") or has("FFDHE"):
        return QUANTUM_VULN["DH"]
    if has("X.509", "CERT"):
        return QUANTUM_VULN["X.509"]
    if has("TLS1.3", "TLSV1.3"):
        return QUANTUM_VULN["TLS13"]
    if has("TLS1.2", "TLSV1.2"):
        return QUANTUM_VULN["TLS12"]
    if has("SSL", "TLS1.0", "TLS1.1", "TLSV1", "TLSV1.0", "TLSV1.1"):
        return QUANTUM_VULN["TLS-OLD"]
    if has("ECB"):
        return QUANTUM_VULN["AES-ECB"]
    if has("AES"):
        try:
            if key_size is not None and int(key_size) < 256:
                return 0.30
        except (TypeError, ValueError):
            pass
        return QUANTUM_VULN["AES"]
    if has("CHACHA"):
        return QUANTUM_VULN["CHACHA20"]
    if has("POLY1305"):
        return QUANTUM_VULN["POLY1305"]
    if has("HMAC", "CMAC", "GMAC"):
        return QUANTUM_VULN["HMAC"]
    if has("MD5"):
        return QUANTUM_VULN["MD5"]
    if has("SHA1", "SHA-1"):
        return QUANTUM_VULN["SHA-1"]
    if has("SHA3", "KECCAK"):
        return QUANTUM_VULN["SHA-3"]
    if has("SHA224", "SHA256", "SHA384", "SHA512", "SHA-2", "SHA2"):
        return QUANTUM_VULN["SHA-2"]
    if has("BLAKE"):
        return QUANTUM_VULN["BLAKE"]
    if has("RIPEMD"):
        return 0.40
    if has("PBKDF2"):
        return QUANTUM_VULN["PBKDF2"]
    if has("ARGON2"):
        return QUANTUM_VULN["ARGON2"]
    if has("SCRYPT"):
        return QUANTUM_VULN["SCRYPT"]
    if has("BCRYPT"):
        return QUANTUM_VULN["BCRYPT"]
    if has("HKDF"):
        return QUANTUM_VULN["HKDF"]
    if has("OPENSSL", "LIBRARY", "PROVIDER"):
        return QUANTUM_VULN["UNKNOWN"]
    return QUANTUM_VULN["UNKNOWN"]


def _risk_inputs(op: dict) -> dict:
    """CIR v0.1 risk_inputs block (top-level or nested), else {}."""
    block = _as_dict(op.get("risk_inputs"))
    if block:
        return block
    for container in ("context", "location", "implementation"):
        sub = _as_dict(op.get(container))
        if isinstance(sub.get("risk_inputs"), dict):
            return sub["risk_inputs"]
    return {}


def _exposure_weight(context: dict, location: dict, risk_inputs: dict):
    user = _user_note(context, _USER_EXPOSURE_RE)
    if user is not None:
        key = _EXPOSURE_ALIASES.get(user.strip().lower(),
                                    user.strip().lower())
        if key in EXPOSURE_W:
            return EXPOSURE_W[key], key, False, "user-supplied"
        return EXPOSURE_W["internal"], "internal", True, "user-supplied"
    raw = _first(context, "exposure", "environment_exposure",
                 default=_first(location, "exposure",
                                default=_first(risk_inputs, "exposure", default=None)))
    if raw is None:
        # Lowest-precedence hint: an external dependency is at least
        # third-party exposed even when exposure is otherwise undeclared.
        if risk_inputs.get("external_dependency") is True:
            return EXPOSURE_W["third-party"], "third-party", True, "inferred"
        return EXPOSURE_W["internal"], "internal", True, "inferred"
    key = str(raw).strip().lower()
    key = _EXPOSURE_ALIASES.get(key, key)
    if key in EXPOSURE_W:
        return EXPOSURE_W[key], key, False, "observed"
    return EXPOSURE_W["internal"], "internal", True, "inferred"


def _criticality_weight(context: dict, risk_inputs: dict):
    user = _user_note(context, _USER_CRIT_RE)
    if user is not None:
        key = user.strip().lower()
        if key in CRIT_W:
            return CRIT_W[key], key, False, "user-supplied"
        return CRIT_W["medium"], "medium", True, "user-supplied"
    raw = _first(context, "criticality", "business_criticality", "crit",
                 default=None)
    assumed = False
    provenance = "observed"
    if raw is None:
        # CIR v0.1 gap-fillers: data_classification, then sensitive_data.
        classification = str(_first(context, "data_classification", default="") or "")
        hint = _CLASSIFICATION_HINTS.get(classification.strip().lower())
        if hint is not None:
            raw = hint[0]
            assumed = True
        elif risk_inputs.get("sensitive_data") is True:
            raw = "high"
            assumed = True
        else:
            raw = "medium"
            assumed = True
        provenance = "inferred"
    key = str(raw or "medium").strip().lower()
    if key in CRIT_W:
        return CRIT_W[key], key, assumed, provenance
    return CRIT_W["medium"], "medium", True, "inferred"


def _usage_state(op: dict) -> str:
    # risk_inputs first: on asset-merged views the top-level state is the
    # asset's, while the operation's own state lives in risk_inputs.
    state = _first(_risk_inputs(op), "usage_state", default=None)
    if state is None:
        state = _first(op, "usage_state", "usageState", "state",
                       default="Possible")
    return str(state or "Possible")


def _confidence(op: dict, state: str):
    base = USAGE_CONFIDENCE.get(_norm(state), 0.50)
    num = _first(op, "confidence", default=None)
    if isinstance(num, bool) or not isinstance(num, (int, float)):
        return base, False
    clamped = min(1.0, max(0.0, float(num)))
    return round((base + clamped) / 2.0, 3), True


def _mosca_inputs(op: dict, context: dict, Z_default: float):
    X = _first(context, "data_lifetime_years", "data_lifetime",
               "lifetime_years", "shelflife", "X",
               default=_first(op, "data_lifetime_years", "X", default=None))
    Y = _first(context, "migration_years", "migration_time_years",
               "migration_time", "replacement_lead_years", "Y",
               default=_first(op, "migration_years", "Y", default=None))
    Z = _first(context, "crqc_years", "collapse_years", "Z",
               default=_first(op, "crqc_years", "Z", default=None))
    assumptions = []
    prov_x = "observed" if X is not None else ""
    prov_y = "observed" if Y is not None else ""
    prov_z = "observed" if Z is not None else ""
    user_x = _user_note(context, _USER_X_RE)
    user_y = _user_note(context, _USER_Y_RE)
    if user_x is not None:
        X = user_x
        prov_x = "user-supplied"
        assumptions.append("data lifetime X user-supplied via scan context")
    if user_y is not None:
        Y = user_y
        prov_y = "user-supplied"
        assumptions.append("migration lead time Y user-supplied via scan context")
    if X is None:
        # CIR v0.1 carries X/Y inside free-text notes
        # ("data_lifetime_years=8; migration_years=3; ...") when set.
        notes = str(_first(context, "notes", default="") or "")
        match = _NOTES_X_RE.search(notes)
        if match:
            X = match.group(1)
            prov_x = "observed"
            assumptions.append("data lifetime X parsed from context notes")
        else:
            classification = str(_first(context, "data_classification", default="") or "")
            hint = _CLASSIFICATION_HINTS.get(classification.strip().lower())
            if hint is not None:
                X = hint[1]
                prov_x = "inferred"
                assumptions.append(
                    f"data lifetime X hinted {hint[1]:g}y by data_classification")
    if Y is None:
        notes = str(_first(context, "notes", default="") or "")
        match = _NOTES_Y_RE.search(notes)
        if match:
            Y = match.group(1)
            prov_y = "observed"
            assumptions.append("migration lead time Y parsed from context notes")
    if X is None:
        X, assumptions = _DEFAULT_X, assumptions + [
            f"data lifetime X assumed {_DEFAULT_X:g}y (undeclared)"]
        prov_x = "inferred"
    if Y is None:
        Y = _DEFAULT_Y
        assumptions.append(f"migration lead time Y assumed {_DEFAULT_Y:g}y (undeclared)")
        prov_y = "inferred"
    if Z is None:
        Z = Z_default
        prov_z = "inferred"
        assumptions.append(f"QC timeline Z assumed {Z_default:g}y (caller default)")
    try:
        X, Y, Z = float(X), float(Y), float(Z)
    except (TypeError, ValueError):
        X, Y, Z = _DEFAULT_X, _DEFAULT_Y, float(Z_default)
        prov_x, prov_y, prov_z = "inferred", "inferred", "inferred"
        assumptions.append("non-numeric Mosca input replaced by defaults")
    provenance = {"data_lifetime_years": prov_x or "inferred",
                  "migration_years": prov_y or "inferred",
                  "crqc_years": prov_z or "inferred"}
    return X, Y, Z, assumptions, provenance


def _class_for(score: float) -> str:
    if score >= 0.8:
        return "Critical"
    if score >= 0.6:
        return "High"
    if score >= 0.4:
        return "Medium"
    if score >= 0.2:
        return "Low"
    return "Informational"


def score_operation(op: dict, Z_default: float = 10) -> dict:
    """Score one CIR operation dict → RiskRecord dict.

    Returns ``{operation_id, canonical_name, mosca_trigger, mosca,
    score, class, explanation, assumptions}`` — the spec keys plus
    ``canonical_name``/``mosca`` detail (harmless extras for downstream
    stages). Pure and deterministic.
    """
    if not isinstance(op, dict):
        raise TypeError("score_operation expects a CIR operation dict")
    op_id = str(_first(op, "operation_id", "id", "op_id", default="op-unknown"))
    canonical = str(_first(op, "canonical_name", "canonical", "algorithm",
                           "name", default="UNKNOWN") or "UNKNOWN")
    context = _as_dict(op.get("context"))
    location = _as_dict(op.get("location"))
    risk_inputs = _risk_inputs(op)

    state = _usage_state(op)
    if _norm(state) in _SUPPRESSED:
        return {
            "operation_id": op_id,
            "canonical_name": canonical,
            "mosca_trigger": False,
            "mosca": {"X": 0.0, "Y": 0.0, "Z": float(Z_default)},
            "score": 0.0,
            "class": "Informational",
            "explanation": (f"{canonical} [{op_id}] is marked {state}: suppressed "
                            "noise, no risk carried."),
            "assumptions": ["suppressed findings carry no risk by policy"],
            "provenance": {
                "exposure": "unknown",
                "criticality": "unknown",
                "data_lifetime_years": "unknown",
                "migration_years": "unknown",
                "crqc_years": "unknown",
                "quantum_vuln": "unknown",
            },
        }

    Q = quantum_vuln(canonical, _first(op, "key_size", "keySize", default=None),
                     _first(op, "mode", default=None),
                     _first(op, "protocol_version", "protocol", default=None))
    # PBKDF2 iteration/salt weakness folds into Q via the weak floor.
    if _norm(canonical) in ("PBKDF2", "PBKDF") and _looks_weak_pbkdf2(op):
        Q = max(Q, QUANTUM_VULN["PBKDF2-WEAK"])
    E, exposure, exposure_assumed, exposure_prov = _exposure_weight(
        context, location, risk_inputs)
    B, criticality, crit_assumed, crit_prov = _criticality_weight(
        context, risk_inputs)
    C, blended = _confidence(op, state)
    X, Y, Z, mosca_assumptions, mosca_prov = _mosca_inputs(
        op, context, float(Z_default))
    triggered = bool(mosca_trigger(X, Y, Z))
    boost = 1.0 if triggered else 0.0

    score = 0.35 * Q + 0.20 * E + 0.15 * B + 0.15 * C + 0.15 * boost
    score = round(min(1.0, max(0.0, score)), 3)
    klass = _class_for(score)

    assumptions = list(mosca_assumptions)
    q_prov = "observed"
    if Q == QUANTUM_VULN["UNKNOWN"]:
        assumptions.append(f"algorithm {canonical!r} unmapped -> Q=0.5 conservative")
        q_prov = "unknown"
    if exposure_assumed:
        assumptions.append("exposure unmapped -> internal (0.5)")
    if crit_assumed:
        assumptions.append("criticality unmapped -> medium (0.5)")
    if blended:
        assumptions.append("confidence blended 50/50 usage_state x declared confidence")
    key_size = _first(op, "key_size", "keySize", default=None)
    try:
        if (key_size is not None and _norm(canonical) in ("RSA",)
                and int(key_size) < 2048):
            assumptions.append(
                f"RSA-{key_size} below 2048-bit policy floor (classical weakness noted)")
    except (TypeError, ValueError):
        pass

    # ProvidedOnly caps at Low: dependency capability, not demonstrated use.
    if _norm(state) in ("PROVIDEDONLY", "PROVIDED-ONLY"):
        if score > 0.39 or klass not in ("Low", "Informational"):
            assumptions.append("ProvidedOnly caps at Low (capability without use evidence)")
            score = min(score, 0.39)
            klass = "Low" if score >= 0.2 else "Informational"

    floor_note = ""
    if _norm(canonical) in _CLASSICAL_FLOOR or Q in (0.60, 0.70, 0.50, 0.45):
        floor_note = " Q includes the classical-weakness floor."
    explanation = (
        f"{canonical} [{op_id}] ({state}): Q={Q:.2f} quantum vuln,"
        f" E={E:.2f} ({exposure}), B={B:.2f} ({criticality}),"
        f" C={C:.2f} ({state}), Mosca X+Y={X:g}+{Y:g} {'>' if triggered else '<='} Z={Z:g}"
        f" -> boost={boost:.0f}.{floor_note} Score {score:.3f} -> {klass}."
    )
    provenance = {
        "exposure": exposure_prov,
        "criticality": crit_prov,
        "data_lifetime_years": mosca_prov.get("data_lifetime_years",
                                              "inferred"),
        "migration_years": mosca_prov.get("migration_years", "inferred"),
        "crqc_years": mosca_prov.get("crqc_years", "inferred"),
        "quantum_vuln": q_prov,
    }
    return {
        "operation_id": op_id,
        "canonical_name": canonical,
        "mosca_trigger": triggered,
        "mosca": {"X": X, "Y": Y, "Z": Z},
        "score": score,
        "class": klass,
        "explanation": explanation,
        "assumptions": assumptions,
        "provenance": provenance,
    }


def _looks_weak_pbkdf2(op: dict) -> bool:
    iterations = _first(op, "iterations", "iteration_count", default=None)
    if iterations is None:
        iterations = _first(_as_dict(op.get("parameters")), "iterations", default=None)
    try:
        if iterations is not None and int(iterations) < 100_000:
            return True
    except (TypeError, ValueError):
        pass
    texts = [str(op.get("variant", "")), str(op.get("hash", ""))]
    for key in ("notes",):
        texts.append(str(_as_dict(op.get("context")).get(key, "")))
    for ent in (op.get("evidence", []) or []):
        if isinstance(ent, dict):
            texts.append(str(ent.get("detail", "")))
            texts.append(str(ent.get("snippet", "")))
    blob = _norm(" ".join(texts))
    if "WEAK" in blob or "SHA1" in blob or "MD5" in blob:
        return True
    match = re.search(r"ITERATIONS?\D{0,12}(\d+)", blob)
    if match:
        try:
            return int(match.group(1)) < 100_000
        except ValueError:
            pass
    return False


def _merge_asset_view(op: dict, assets_by_id: dict) -> dict:
    """Overlay the linked CryptoAsset's fields under a CIR operation.

    CIR v0.1 splits crypto facts (canonical/key_size/mode/usage_state live
    on the asset) from use facts (operation). Scoring needs both, so asset
    fields fill operation gaps (explicit operation keys always win).
    """
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


def score_cir(cir, Z_default: float = 10) -> list[dict]:
    """Score every operation in a CIR dict (or bare op list), desc by score.

    Accepts CIR v0.1 documents (operations reference assets by asset_id),
    rich Agent C operation dicts, or a bare operation list. Asset fields
    are merged under each operation before scoring. Pure, deterministic;
    ties break by operation_id ascending.
    """
    if isinstance(cir, dict):
        ops = cir.get("operations", []) or []
        assets_by_id = {a.get("asset_id"): a for a in (cir.get("assets", []) or [])
                        if isinstance(a, dict) and a.get("asset_id")}
    else:
        ops = cir or []
        assets_by_id = {}
    risks = [score_operation(_merge_asset_view(op, assets_by_id), Z_default)
             for op in ops if isinstance(op, dict)]
    risks.sort(key=lambda r: (-r["score"], r["operation_id"]))
    return risks


def to_cir_risk(record: dict, asset_id: str | None = None,
                confidence: float | None = None) -> dict:
    """Project an internal RiskRecord onto the CIR v0.1 wire shape.

    Returns ``{risk_id, class, title, confidence, operation_id, asset_id?,
    score 0..10, description, rationale}`` validating against
    cir.schema.json RiskRecord (additionalProperties-safe). The internal
    0..1 score maps linearly onto the wire 0..10 scale.
    """
    if not isinstance(record, dict):
        raise TypeError("to_cir_risk expects a score_operation record dict")
    op_id = str(record.get("operation_id", "op-unknown"))
    digest = hashlib.blake2s(op_id.encode("utf-8")).hexdigest()[:16]
    try:
        conf = min(1.0, max(0.0, float(confidence if confidence is not None else 0.5)))
    except (TypeError, ValueError):
        conf = 0.5
    try:
        wire_score = round(min(1.0, max(0.0, float(record.get("score", 0.0)))) * 10.0, 2)
    except (TypeError, ValueError):
        wire_score = 0.0
    out: dict = {
        "risk_id": f"risk:{digest}",
        "class": record.get("class", "Informational"),
        "title": f"{record.get('canonical_name', 'UNKNOWN')} [{op_id}]",
        "confidence": conf,
        "operation_id": op_id,
        "score": wire_score,
        "description": str(record.get("explanation", "")),
        "rationale": "; ".join(str(a) for a in (record.get("assumptions", []) or [])),
    }
    if asset_id:
        out["asset_id"] = str(asset_id)
    if out["class"] not in ("Critical", "High", "Medium", "Low", "Informational"):
        out["class"] = "Informational"
    return out


# -- Phase 10: explainable risk dimensions (additive; v1 untouched) ---------

_CLASSICAL_POLICY = "NIST SP 800-131A Rev.2"
_PROTOCOL_POLICY = "RFC 9325 (TLS posture)"
_NON_DEPLOYMENT_SCOPES = frozenset({
    "TEST", "FIXTURE", "BENCHMARK", "DEMO", "EXAMPLE",
    "DOCUMENTATION", "GENERATED",
})


def _op_canonical(op: dict) -> str:
    return str(_first(op, "canonical_name", "canonical", "algorithm",
                      "name", default="UNKNOWN") or "UNKNOWN")


def _op_key_size(op: dict):
    return _first(op, "key_size", "keySize", "bits", default=None)


def _op_text(op: dict) -> str:
    bits: list[str] = [
        str(_first(op, "canonical_name", "canonical", "algorithm", default="")),
        str(_first(op, "mode", default="") or ""),
        str(_first(op, "protocol_version", "protocol", default="") or ""),
        str(_first(op, "variant", "hash", default="") or ""),
        str(_first(op, "operation", "operation_type", default="") or ""),
    ]
    params = op.get("parameters")
    if isinstance(params, dict):
        for key in ("mode", "hash", "digest", "protocol", "protocol_version"):
            if params.get(key):
                bits.append(str(params[key]))
    return _norm(" ".join(bits))


def assess_classical_posture(operation: dict) -> dict:
    """Standards-based classical posture for one operation dict. Pure.

    Returns ``{level, score 0..1, reason, policy}`` where level is one of
    ``secure/legacy/deprecated/broken/unknown``. Follows NIST SP 800-131A
    Rev.2 key-length/mode guidance (classical floor only; quantum and
    misuse are separate dimensions).
    """
    if not isinstance(operation, dict):
        raise TypeError("assess_classical_posture expects an operation dict")
    canonical = _op_canonical(operation)
    text = _op_text(operation)
    key_size = _op_key_size(operation)
    size = None
    try:
        size = int(key_size) if key_size is not None else None
    except (TypeError, ValueError):
        size = None

    def out(level, score, reason):
        return {"level": level, "score": round(float(score), 3),
                "reason": reason, "policy": _CLASSICAL_POLICY}

    if "ECB" in text:
        return out("broken", 1.0, f"{canonical}: ECB mode leaks structure (classical-broken)")
    if any(k in text for k in ("MD5",)):
        return out("broken", 1.0, f"{canonical}: MD5 collision-broken")
    if any(k in text for k in ("RC4", "ARC4")):
        return out("broken", 1.0, f"{canonical}: RC4 key-recovery broken")
    if "DES" in text and "DESCRIBE" not in text and "3DES" not in text \
            and "DESEDE" not in text and "AES" not in text:
        return out("broken", 1.0, f"{canonical}: single-DES brute-force broken")
    if any(k in text for k in ("SHA1", "SHA-1")):
        return out("deprecated", 0.7, f"{canonical}: SHA-1 collision-deprecated")
    if any(k in text for k in ("3DES", "DESEDE", "TRIPLEDES")):
        return out("deprecated", 0.7, f"{canonical}: 3DES disallowed for new use")
    if any(k in text for k in ("BLOWFISH", "RIPEMD")):
        return out("deprecated", 0.6, f"{canonical}: legacy primitive, migrate")
    if "RSA" in text or "DSA" in text or "DIFFIE" in text or text.strip() in ("DH",):
        if size is not None and size < 2048:
            return out("broken", 0.9, f"{canonical}-{size}: below 2048-bit floor")
        return out("secure", 0.15, f"{canonical}: classical strength ok (quantum handled separately)")
    if any(k in text for k in ("ECDSA", "ECDH", "X25519", "X448", "ED25519",
                               "ED448", "ELGAMAL")):
        if size is not None and size < 224:
            return out("broken", 0.9, f"{canonical}-{size}: below 224-bit EC floor")
        return out("secure", 0.15, f"{canonical}: classical strength ok (quantum handled separately)")
    if any(k in text for k in ("AES", "CHACHA", "POLY1305", "HMAC", "SHA256",
                               "SHA384", "SHA512", "SHA-2", "SHA-3", "SHA3",
                               "KECCAK", "BLAKE", "HKDF", "BCRYPT", "SCRYPT",
                               "ARGON2", "PBKDF2", "ML-KEM", "ML-DSA",
                               "SLH-DSA", "FN-DSA", "HQC", "KYBER", "HYBRID")):
        if "AES" in text and size is not None and size < 128:
            return out("broken", 0.9, f"AES-{size}: below 128-bit floor")
        return out("secure", 0.1, f"{canonical}: approved primitive/parameters")
    if text.strip() in ("UNKNOWN", "", "OPENSSL", "LIBRARY", "PROVIDER"):
        return out("unknown", 0.5, f"{canonical}: unmapped, conservative")
    return out("unknown", 0.5, f"{canonical}: unmapped, conservative")


def assess_misuse_severity(operation: dict) -> dict:
    """Misuse dimension: structured rule hits outrank algorithm presence.

    Returns ``{level, score 0..1, findings, reason}`` with level one of
    ``none/low/medium/high``. A strong primitive used incorrectly scores
    high here even when its classical posture is ``secure``.
    """
    if not isinstance(operation, dict):
        raise TypeError("assess_misuse_severity expects an operation dict")
    try:
        from ecdat.core.misuse import check_operation as _check
        findings = _check(operation)
    except Exception:
        findings = []
    if not findings:
        return {"level": "none", "score": 0.0, "findings": [],
                "reason": "no misuse rule fired"}
    severities = {str(f.get("severity", "")).lower() for f in findings
                  if isinstance(f, dict)}
    if "high" in severities or "critical" in severities:
        level, score = "high", 0.9
    elif "medium" in severities:
        level, score = "medium", 0.5
    else:
        level, score = "low", 0.25
    ids = sorted(str(f.get("rule_id", "?")) for f in findings
                 if isinstance(f, dict))
    return {"level": level, "score": score, "findings": findings,
            "reason": f"misuse rules fired: {', '.join(ids)}"}


def assess_protocol_posture(operation: dict) -> dict:
    """Protocol/configuration posture for one operation dict. Pure.

    Returns ``{level, score 0..1, reason, policy}`` with level one of
    ``secure/acceptable/legacy/broken/not-applicable``.
    """
    if not isinstance(operation, dict):
        raise TypeError("assess_protocol_posture expects an operation dict")
    text = _op_text(operation)
    params = operation.get("parameters") if isinstance(
        operation.get("parameters"), dict) else {}

    def out(level, score, reason):
        return {"level": level, "score": round(float(score), 3),
                "reason": reason, "policy": _PROTOCOL_POLICY}

    if any(k in text for k in ("TLS1.3", "TLSV1.3")):
        return out("secure", 0.05, "TLS 1.3 negotiated/configured")
    if any(k in text for k in ("TLS1.2", "TLSV1.2")):
        # Weak ciphers inside TLS 1.2 still downgrade via classical/misuse.
        return out("acceptable", 0.3, "TLS 1.2: acceptable only with strong suites")
    if "TLS" in text or "SSL" in text:
        return out("broken", 0.95, "legacy/broken TLS/SSL (1.0/1.1/SSLv2/v3 family)")
    if text and ("CBC" in text or "RC4" in text or "DES" in text) and "TLS" in text:
        return out("broken", 0.9, "TLS with legacy cipher")
    if params.get("protocol_version") or params.get("protocol") \
            or operation.get("protocol_version") or operation.get("protocol"):
        return out("acceptable", 0.3, "protocol present, no insecure version signal")
    return out("not-applicable", 0.0, "no protocol semantics in operation")


def assess_quantum_exposure(operation: dict, Z_default: float = 10) -> dict:
    """Quantum exposure dimension: Q plus Mosca urgency. Pure.

    Returns ``{q, mosca_trigger, level, score, reason}`` with level one of
    ``critical/high/medium/low/minimal``. Score blends Q (70%) with the
    Mosca boost (30%) so long-lived data migrates first.
    """
    if not isinstance(operation, dict):
        raise TypeError("assess_quantum_exposure expects an operation dict")
    canonical = _op_canonical(operation)
    q = quantum_vuln(canonical, _op_key_size(operation),
                     _first(operation, "mode", default=None),
                     _first(operation, "protocol_version", "protocol", default=None))
    if _norm(canonical) in ("PBKDF2", "PBKDF") and _looks_weak_pbkdf2(operation):
        q = max(q, QUANTUM_VULN["PBKDF2-WEAK"])
    context = _as_dict(operation.get("context"))
    try:
        X, Y, Z, _assumptions, _prov = _mosca_inputs(
            operation, context, float(Z_default))
    except Exception:
        X, Y, Z = 5.0, 3.0, float(Z_default)
    triggered = bool(mosca_trigger(X, Y, Z))
    score = round(min(1.0, max(0.0, 0.7 * q + 0.3 * (1.0 if triggered else 0.0))), 3)
    if q >= 0.8:
        level = "critical"
    elif q >= 0.6:
        level = "high"
    elif q >= 0.4:
        level = "medium"
    elif q >= 0.2:
        level = "low"
    else:
        level = "minimal"
    return {"q": round(float(q), 3), "mosca_trigger": triggered,
            "mosca": {"X": X, "Y": Y, "Z": Z},
            "level": level, "score": score,
            "reason": (f"{canonical}: Q={q:.2f}, Mosca X+Y={X:g}+{Y:g} "
                       f"{'>' if triggered else '<='} Z={Z:g}")}


def _deployment_impact(operation: dict, context: dict, location: dict,
                       risk_inputs: dict) -> dict:
    E, exposure, _ea, _ep = _exposure_weight(context, location, risk_inputs)
    B, criticality, _ca, _cp = _criticality_weight(context, risk_inputs)
    score = round((E + B) / 2.0, 3)
    scope = None
    try:
        scope = operation.get("scope")
        if scope is None:
            scope = _as_dict(operation.get("context")).get("scope")
        if scope is None:
            from ecdat.core.scope import classify_scope as _scope
            loc = _as_dict(operation.get("location"))
            scope = _scope(loc.get("file", loc.get("path")),
                           _as_dict(operation.get("implementation")).get("language"))
    except Exception:
        scope = scope or "UNKNOWN"
    scope = str(scope or "UNKNOWN").upper()
    capped = False
    if scope in _NON_DEPLOYMENT_SCOPES:
        score = round(score * 0.4, 3)
        capped = True
    reason = f"E={E:.2f} ({exposure}), B={B:.2f} ({criticality})"
    if capped:
        reason += f"; non-deployment scope {scope} reduces deployment impact"
    return {"score": score, "exposure": exposure, "criticality": criticality,
            "scope": scope, "capped": capped, "reason": reason}


def score_operation_v2(op: dict, Z_default: float = 10) -> dict:
    """Score one operation with named, inspectable dimensions. Pure.

    Additive Phase 10 API: :func:`score_operation` is untouched. Returns
    ``{operation_id, canonical_name, dimensions, score, score_10, class,
    explanation, assumptions, provenance}`` where ``dimensions`` holds
    ``classical_posture/misuse_severity/protocol_posture/quantum_exposure/
    deployment_impact/migration_urgency``. Detection confidence stays
    outside the risk value (reported separately in ``provenance`` notes).
    """
    if not isinstance(op, dict):
        raise TypeError("score_operation_v2 expects a CIR operation dict")
    base = score_operation(op, Z_default)
    classical = assess_classical_posture(op)
    misuse = assess_misuse_severity(op)
    protocol = assess_protocol_posture(op)
    quantum = assess_quantum_exposure(op, Z_default)
    context = _as_dict(op.get("context"))
    location = _as_dict(op.get("location"))
    deployment = _deployment_impact(op, context, location, _risk_inputs(op))
    urgency_score = round(min(1.0, (quantum["score"] + (0.5 if quantum["mosca_trigger"]
                                                       else 0.0)) / 1.5), 3)
    migration = {"score": urgency_score,
                 "mosca_trigger": quantum["mosca_trigger"],
                 "mosca": dict(quantum.get("mosca", {})),
                 "reason": ("urgent: Mosca fired on quantum-exposed primitive"
                            if quantum["mosca_trigger"] and quantum["q"] >= 0.4
                            else "routine migration timing")}
    score = round(min(1.0, max(0.0,
                               0.30 * quantum["score"] + 0.25 * classical["score"]
                               + 0.25 * misuse["score"] + 0.10 * protocol["score"]
                               + 0.10 * deployment["score"])), 3)
    klass = _class_for(score)
    state = _usage_state(op)
    if _norm(state) in _SUPPRESSED:
        score, klass = 0.0, "Informational"
    if _norm(state) in ("PROVIDEDONLY", "PROVIDED-ONLY") and score > 0.39:
        score = min(score, 0.39)
        klass = "Low" if score >= 0.2 else "Informational"
    assumptions = list(base.get("assumptions", []))
    if deployment.get("capped"):
        assumptions.append(
            f"scope {deployment.get('scope')} is non-deployment: deployment "
            "impact shown reduced, evidence retained")
    if misuse["findings"]:
        assumptions.append(
            "misuse takes precedence: strong primitive used incorrectly "
            "still scores via the misuse dimension")
    explanation = (
        f"{base.get('canonical_name')} [{base.get('operation_id')}] v2: "
        f"classical={classical['level']}({classical['score']:.2f}), "
        f"misuse={misuse['level']}({misuse['score']:.2f}), "
        f"protocol={protocol['level']}({protocol['score']:.2f}), "
        f"quantum={quantum['level']}({quantum['score']:.2f}), "
        f"deployment={deployment['score']:.2f}, "
        f"migration={migration['score']:.2f} -> {score:.3f} {klass}.")
    return {
        "operation_id": base.get("operation_id"),
        "canonical_name": base.get("canonical_name"),
        "dimensions": {
            "classical_posture": classical,
            "misuse_severity": misuse,
            "protocol_posture": protocol,
            "quantum_exposure": quantum,
            "deployment_impact": deployment,
            "migration_urgency": migration,
        },
        "score": score,
        "score_10": round(score * 10.0, 2),
        "class": klass,
        "explanation": explanation,
        "assumptions": assumptions,
        "provenance": base.get("provenance", {}),
    }
