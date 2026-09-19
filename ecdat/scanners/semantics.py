"""Phase 12: scanner-family semantic alignment (additive, stdlib-only).

Pure helpers that give every scanner family the same vocabulary:

- dependency presence is a *provided capability*, never an operation;
- binary findings gate on cheap -> expensive escalation;
- certificate findings are *assets/material*, not operations;
- config findings are classified by deployment state
  (mentioned / supported / configured / enabled-default).

No scanner is modified here; these helpers are imported by (or applied
to the output of) the family scanners. All functions are pure,
total (never raise on odd input), and operate on either dicts or
``ScannerFinding``-shaped objects.
"""

from __future__ import annotations

__all__ = [
    "dependency_capability_only",
    "binary_escalation_policy",
    "cert_asset_vs_operation",
    "config_state_classify",
    "DEPENDENCY_SCANNERS",
    "CERT_SCANNERS",
    "CONFIG_STATES",
]

DEPENDENCY_SCANNERS = frozenset({"dependency", "syft", "cdxgen"})
CERT_SCANNERS = frozenset({
    "certificate", "pem", "der", "jks", "pkcs12", "ssh", "jwk",
})
CONFIG_STATES = ("mentioned", "supported", "configured", "enabled-default")

_CONFIRMED_USAGE = frozenset({"Confirmed", "Probable"})


def _as_dict(finding: object) -> dict:
    if isinstance(finding, dict):
        return finding
    data: dict = {}
    for attr in ("dependency_only", "usage_state", "operation_type",
                 "library", "canonical", "scanner", "function",
                 "confidence", "metadata", "context", "location"):
        try:
            value = getattr(finding, attr, None)
        except Exception:
            continue
        if value is not None:
            data[attr] = value
    try:
        meta = getattr(finding, "metadata", None)
        if isinstance(meta, dict):
            data["metadata"] = meta
    except Exception:
        pass
    return data


def _finding_text(finding: object) -> str:
    data = finding if isinstance(finding, dict) else _as_dict(finding)
    parts: list[str] = []
    try:
        if isinstance(data, dict):
            for key in ("title", "rule_id", "snippet", "canonical",
                        "library", "scanner", "operation_type"):
                value = data.get(key)
                if value:
                    parts.append(str(value))
            meta = data.get("metadata")
            if isinstance(meta, dict):
                for key in ("scanner", "canonical_name", "rule_id",
                            "config_state", "usage_state", "title"):
                    value = meta.get(key)
                    if value:
                        parts.append(str(value))
    except Exception:
        pass
    return " ".join(parts).lower()


def dependency_capability_only(finding: object) -> bool:
    """Return True when ``finding`` is a provided capability, not an operation.

    Dependency presence (a package being installed / declared) never
    proves a cryptographic operation ran. Returns True when any of:

    - explicit ``dependency_only`` flag is set;
    - the finding carries no ``operation_type`` (no demonstrated call);
    - the producing scanner is a dependency scanner (syft/cdxgen/dependency);
    - usage state is anything other than Confirmed/Probable.
    """
    try:
        data = finding if isinstance(finding, dict) else _as_dict(finding)
        if not isinstance(data, dict):
            return True
        if bool(data.get("dependency_only")):
            return True
        meta = data.get("metadata")
        scanner = ""
        try:
            if isinstance(meta, dict):
                scanner = str(meta.get("scanner", "") or "").lower()
            scanner = scanner or str(data.get("scanner", "") or "").lower()
            library = data.get("library", None)
        except Exception:
            library = None
        if scanner in DEPENDENCY_SCANNERS:
            return True
        if data.get("operation_type") is None and library is not None:
            return True
        # Usage-state gate: only demonstrated use escapes capability-only.
        usage = ""
        try:
            if isinstance(meta, dict) and meta.get("usage_state"):
                usage = str(meta.get("usage_state"))
            usage = usage or str(data.get("usage_state", "") or "")
        except Exception:
            usage = ""
        if usage and usage not in _CONFIRMED_USAGE:
            # No operation id + unconfirmed use -> capability.
            if data.get("operation_type") is None:
                return True
            # Dependency-flavoured rule ids stay capabilities even with an
            # inferred operation type.
            text = _finding_text(data)
            if "dependenc" in text or "sbom" in text or "package" in text:
                return True
            return False
        if data.get("operation_type") is None:
            return True
        return False
    except Exception:
        return True


def binary_escalation_policy(signals: dict | None) -> dict:
    """Cheap -> expensive gating for binary stages (pure).

    Returns ``{"escalate": bool, "next_stages": [...], "reason": str}``.
    Cheap stages (metadata/imports/strings/signatures) always run;
    expensive backends (capa/FLOSS/Ghidra) run only when the cheap
    pass justifies them: weak/uncertain hit, packed/obfuscated flags,
    or low confidence.
    """
    try:
        sig = dict(signals or {})
    except Exception:
        sig = {}
    next_stages: list[str] = []
    reason = "no-escalation"
    escalate = False
    try:
        for key in ("weak_hit", "needs_deep", "packed", "obfuscated"):
            if sig.get(key) is True:
                escalate = True
                reason = key
                break
        if not escalate:
            has_hit = bool(sig.get("has_hit", sig.get("weak_hit", False)))
            if has_hit:
                try:
                    conf = float(sig.get("confidence", 0.0))
                except (TypeError, ValueError):
                    conf = 0.0
                    escalate = True
                    reason = "unparseable-confidence"
                if not escalate and conf < 0.65:
                    escalate = True
                    reason = "low-confidence"
                elif not escalate and sig.get("surface") == "binary":
                    escalate = True
                    reason = "binary-hit"
        # Distinct cheap-evidence kinds strengthen the reason but never
        # downgrade an escalation decision.
        if escalate:
            if sig.get("packed") is True or sig.get("obfuscated") is True:
                reason = "packed-or-obfuscated"
            next_stages = ["capa-full", "floss", "ghidra-optional"]
    except Exception:
        escalate = False
        next_stages = []
        reason = "error-no-escalation"
    return {"escalate": escalate, "next_stages": next_stages,
            "reason": reason}


def cert_asset_vs_operation(finding: object) -> str:
    """Classify a certificate-family finding as asset material vs operation.

    Certificates, keys, keystores, and trust material are *assets*:
    their presence never proves a crypto operation executed. Returns
    ``"operation"`` only when the finding demonstrates an actual
    operation (TLS handshake, sign/verify, encrypt/decrypt call);
    otherwise ``"asset"``.
    """
    try:
        data = finding if isinstance(finding, dict) else _as_dict(finding)
        if not isinstance(data, dict):
            return "asset"
        op_type = data.get("operation_type")
        if op_type is not None and str(op_type).strip().lower() not in (
                "", "none", "null"):
            text = _finding_text(data)
            # A cert-scanner hit with an attached operation type that
            # actually describes key use (not mere presence) counts.
            if any(word in text for word in (
                    "handshake", "verify", "sign", "encrypt", "decrypt",
                    "keyexchange", "tls")):
                return "operation"
            # Operation type present but no use evidence -> still asset.
            meta = data.get("metadata")
            usage = ""
            try:
                if isinstance(meta, dict) and meta.get("usage_state"):
                    usage = str(meta.get("usage_state"))
                usage = usage or str(data.get("usage_state", "") or "")
            except Exception:
                usage = ""
            if usage in _CONFIRMED_USAGE:
                return "operation"
            return "asset"
        return "asset"
    except Exception:
        return "asset"


def config_state_classify(finding: object) -> str:
    """Classify a config finding by deployment state (pure).

    - ``mentioned``: algorithm/cipher named in a comment, doc, or example.
    - ``supported``: offered as one option among many (cipher list entry).
    - ``configured``: actively selected/enforced by the config.
    - ``enabled-default``: active via shipped default (no explicit setting).
    """
    try:
        data = finding if isinstance(finding, dict) else _as_dict(finding)
        text = _finding_text(data) if isinstance(data, dict) else ""
        meta_state = ""
        try:
            if isinstance(data, dict):
                meta = data.get("metadata")
                if isinstance(meta, dict):
                    meta_state = str(
                        meta.get("config_state", "") or "").strip().lower()
                meta_state = meta_state or str(
                    data.get("config_state", "") or "").strip().lower()
        except Exception:
            meta_state = ""
        if meta_state in CONFIG_STATES:
            return meta_state
        if any(word in text for word in (
                "default", "out-of-the-box", "out of the box",
                "shipped", "by default")):
            return "enabled-default"
        if any(word in text for word in (
                "enforc", "requir", "mandat", "enabled", "active",
                "selected", "sslcontext")):
            # "cipher_suites = [...]" with a single enforced entry reads
            # as configured; bare lists are handled below.
            if "example" in text or "comment" in text:
                return "mentioned"
            return "configured"
        if any(word in text for word in (
                "support", "offer", "accept", "allow", "cipherlist",
                "cipher list", "ciphers:", "cipher_suites")):
            return "supported"
        if any(word in text for word in (
                "example", "comment", "sample", "doc", "readme")):
            return "mentioned"
        return "mentioned"
    except Exception:
        return "mentioned"
