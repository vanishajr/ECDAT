"""Core API facade (Person-1 Agent C).

Single-process + ThreadPool facade over the Agent C analysis stages. CIR
v0.1 (cir.schema.json) is the source of truth: ``scan`` runs inventory ->
triage -> pattern extract -> fuse (Agent B fusion usage) ->
assets/operations -> graph. Risks/recommendations are NOT embedded by
default (``include_risk`` / ``include_recommend`` default False -- they
are a downstream stage via :func:`enrich_cir`).

Interop with Agent A/B modules (imported defensively so this facade also
works standalone):
  cir_models   : new_asset_id / new_operation_id (deterministic ids)
  registry     : canonicalize + REGISTRY_VERSION
  fusion       : weighted_fusion + decide_usage (confidence/usage states)
  cir_validate : validate_cir (jsonschema, never imported here directly)
  graph/risk/recommend (Agent C): rich analysis + wire converters.

Stdlib only otherwise. No sqlite, no network.

Public surface:
  scan(target, ...)        -> CIR v0.1 dict (validated)
  scan_paths(targets, ...) -> [CIR v0.1] via ThreadPoolExecutor
  risk(cir, Z=10)          -> internal [RiskRecord] sorted desc
  recommend(cir, ...)      -> internal [Recommendation] by priority
  enrich_cir(cir, Z=10)    -> CIR copy + wire risks/recommendations
  to_canonical(cir)        -> canonical v1 dict (validated when possible)
  get_openapi()            -> minimal OpenAPI dict + curl examples
"""

from __future__ import annotations

import copy
import hashlib
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "scan",
    "scan_paths",
    "risk",
    "recommend",
    "enrich_cir",
    "to_canonical",
    "get_openapi",
]

_TOOL_VERSIONS = {"ecdat": "0.1.0", "ecdat-core-agentC": "0.1.0"}
_CIR_VERSION = "0.1"

try:
    from ecdat.core.cir_models import new_asset_id as _new_asset_id
    from ecdat.core.cir_models import new_operation_id as _new_operation_id
except ImportError:  # standalone fallback: same id shapes
    def _new_asset_id(canonical, key_size=None, mode=None, curve=None,
                      protocol=None):
        material = "|".join([canonical or "",
                             str(key_size) if key_size is not None else "",
                             mode or "", curve or "", protocol or ""])
        return "ast:" + hashlib.blake2s(material.encode()).hexdigest()[:16]

    def _new_operation_id(operation_type, asset_id, function=None,
                          location=None):
        material = "|".join([operation_type or "", asset_id or "",
                             function or "", location or ""])
        return "op:" + hashlib.blake2s(material.encode()).hexdigest()[:16]

try:
    from ecdat.core.registry import REGISTRY_VERSION as _REGISTRY_VERSION
    from ecdat.core.registry import canonicalize as _canonicalize
except ImportError:  # standalone fallback
    _REGISTRY_VERSION = "2026.09.11"

    def _canonicalize(name):
        return re.sub(r"[\s_]+", "-", str(name or "").strip()).upper() or "UNKNOWN"

try:
    from ecdat.core.fusion import decide_usage as _decide_usage
    from ecdat.core.fusion import weighted_fusion as _weighted_fusion
except ImportError:  # standalone fallback mirrors fusion thresholds
    def _weighted_fusion(evidence, param_resolved=False, binary_support=False,
                         config_runtime_agreement=False, dependency_only=False):
        return (0.5, {"detectors": []})

    def _decide_usage(confidence, dependency_only=False, **kwargs):
        if dependency_only:
            return "ProvidedOnly"
        try:
            conf = float(confidence)
        except (TypeError, ValueError):
            conf = 0.0
        if conf >= 0.85:
            return "Confirmed"
        if conf >= 0.65:
            return "Probable"
        return "Possible"

try:
    from ecdat.core.graph import build_graph as _build_graph
    from ecdat.core.graph import to_cir_graph as _to_cir_graph
except ImportError:  # standalone fallback: empty graph
    def _build_graph(operations, assets=None, contexts=None):
        return {"nodes": [], "edges": []}

    def _to_cir_graph(graph):
        return {"nodes": [], "edges": []}


def _validate_cir(doc: dict) -> dict:
    """Validate via Agent A's cir_validate when importable (pass-through)."""
    try:
        from ecdat.core import cir_validate as _cv
    except ImportError:
        return doc
    validator = getattr(_cv, "validate_cir", None) or getattr(_cv, "validate", None)
    if callable(validator):
        return validator(doc)
    return doc


_SOURCE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".cs", ".rs",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".rb", ".php", ".swift", ".kt",
}
_CONFIG_NAMES = {
    "nginx.conf", ".env", "openssl.cnf", "httpd.conf", "envoy.yaml",
    "caddyfile", "application.yml", "settings.py",
}
_CONFIG_EXTS = {".yaml", ".yml", ".toml", ".ini", ".conf", ".cnf", ".env"}
_KEY_EXTS = {".pem", ".der", ".crt", ".cer", ".key", ".p12", ".pfx",
             ".jks", ".pub", ".asc"}
_MAX_TEXT_BYTES = 2 * 1024 * 1024
_MAX_FILES = 5000

# Pattern-stage reliability per surface (fusion input only, never
# serialized: CIR evidence carries tool/detail/confidence/snippet alone).
# Values mirror the DETECTOR_RELIABILITY scale of the stage each surface
# stands in for. Consequence by design: the cheap pass peaks at Probable;
# Confirmed requires Agent B escalation evidence.
_SURFACE_RELIABILITY = {
    "source": 0.9,
    "binary": 0.8,
    "config": 0.85,
    "cert": 0.85,
    "cloud": 0.8,
    "container": 0.6,
}

# Pattern signals that constitute direct-use evidence in fusion terms.
_DIRECT_SIGNALS = {"source-api-call", "binary-import"}

# (raw_hint, operation_type, pattern, usage, role, confidence, library,
#  signal_type). Library attribution is a heuristic (documented
#  in scan()); version/api are filled per-hit only when observed.
_PATTERNS: list[tuple] = [
    ("RSA", "Encrypt", re.compile(r"\bRSA\b.{0,60}?(1024|2048|3072|4096)", re.I),
     "encrypt", "uses", 0.90, "openssl", "pattern-match"),
    ("RSA", "Encrypt", re.compile(r"rsa\.generate_private_key|RSA_generate_key|RSA\.create|"
                                  r"new\s+RSACryptoServiceProvider|EVP_PKEY_RSA|RSA_public_encrypt", re.I),
     "encrypt", "uses", 0.95, "cryptography", "source-api-call"),
    ("ECDSA", "Sign", re.compile(r"ECDSA|SHA256withECDSA|ecdsa\.SigningKey|EC_KEY_new_by_curve_name", re.I),
     "sign", "uses", 0.90, "cryptography", "source-api-call"),
    ("ECDH", "KeyExchange", re.compile(r"\bECDH\b|KeyAgreement\(\s*[\"']ECDH|EVP_PKEY_EC|deriveBits", re.I),
     "key-exchange", "uses", 0.85, "openssl", "source-api-call"),
    ("DH", "KeyExchange", re.compile(r"\bDH_compute_key\b|DiffieHellman|EVP_PKEY_DH|dhparam", re.I),
     "key-exchange", "uses", 0.85, "openssl", "binary-import"),
    ("X25519", "KeyExchange", re.compile(r"\bX25519\b|\bX448\b", re.I),
     "key-exchange", "uses", 0.90, "libsodium", "source-api-call"),
    ("Ed25519", "Sign", re.compile(r"\bEd25519\b|\bEd448\b|\bEdDSA\b", re.I),
     "sign", "uses", 0.90, "libsodium", "source-api-call"),
    ("AES-256-GCM", "Encrypt", re.compile(r"AES.{0,20}?GCM|aes.{0,10}?256.{0,10}?gcm|"
                                          r"EVP_aes_256_gcm|AES/GCM/NoPadding", re.I),
     "encrypt", "uses", 0.95, "cryptography", "source-api-call"),
    ("AES-ECB", "Encrypt", re.compile(r"AES.{0,20}?ECB|AES\.MODE_ECB|EVP_aes_128_ecb", re.I),
     "encrypt", "uses", 0.95, "cryptography", "source-api-call"),
    ("AES", "Encrypt", re.compile(r"\bAES\b|EVP_aes_|Cipher\(\s*[\"']AES", re.I),
     "encrypt", "uses", 0.80, "openssl", "pattern-match"),
    ("ChaCha20-Poly1305", "Encrypt", re.compile(r"ChaCha20|chacha20poly1305|EVP_chacha20|"
                                                r"expand 32-byte k", re.I),
     "encrypt", "uses", 0.90, "libsodium", "source-api-call"),
    ("DES", "Encrypt", re.compile(r"\bDES\b|DESede|TripleDES|EVP_des_ede3|\bRC4\b|\bARC4\b", re.I),
     "encrypt", "uses", 0.90, "openssl", "pattern-match"),
    ("MD5", "Hash", re.compile(r"\bMD5\b|hashlib\.md5|MessageDigest\.getInstance\(\s*[\"']MD5", re.I),
     "hash", "uses", 0.90, "hashlib", "source-api-call"),
    ("SHA-1", "Sign", re.compile(r"\bSHA-?1\b|hashlib\.sha1|SHA1_Init|sha1WithRSA", re.I),
     "sign", "uses", 0.85, "hashlib", "source-api-call"),
    ("SHA-256", "Hash", re.compile(r"SHA-?256|SHA256_Init|sha256WithRSA", re.I),
     "hash", "uses", 0.85, "hashlib", "source-api-call"),
    ("HMAC-SHA256", "Sign", re.compile(r"\bHMAC\b|hmac\.new|HmacSHA256", re.I),
     "mac", "uses", 0.85, "hashlib", "source-api-call"),
    ("PBKDF2", "KDF", re.compile(r"\bPBKDF2\b|PKCS5_PBKDF2_HMAC|Rfc2898DeriveBytes", re.I),
     "kdf", "uses", 0.85, "hashlib", "source-api-call"),
    ("TLS1.0", "TLS", re.compile(r"TLSv1(\.0)?\b|PROTOCOL_TLSv1\b|TLS_RSA_WITH|SSLv3|SSLv2", re.I),
     "tls", "uses", 0.85, "openssl", "config-match"),
    ("TLS1.3", "TLS", re.compile(r"TLSv1\.3|TLS_AES_128_GCM_SHA256|TLS_CHACHA20_POLY1305", re.I),
     "tls", "uses", 0.85, "openssl", "config-match"),
    ("X.509", "Storage", re.compile(r"-----BEGIN CERTIFICATE-----|server\.crt|\.pem\b", re.I),
     "certificate", "provides", 0.80, "openssl", "cert-parse"),
    ("ML-KEM", "KeyExchange", re.compile(r"ML-KEM|MLKEM|Kyber|liboqs.*kem|oqs_provider", re.I),
     "key-exchange", "uses", 0.90, "liboqs", "source-api-call"),
    ("ML-DSA", "Sign", re.compile(r"ML-DSA|MLDSA|Dilithium|liboqs.*sig", re.I),
     "sign", "uses", 0.90, "liboqs", "source-api-call"),
    ("hybrid X25519+ML-KEM", "KeyExchange", re.compile(r"X25519\+ML-KEM|hybrid.*kem|"
                                                      r"ECDHE\+Kyber|X25519MLKEM", re.I),
     "key-exchange", "uses", 0.90, "oqs-provider", "source-api-call"),
    ("OpenSSL", "Encrypt", re.compile(r"#include\s*<openssl/|import\s+OpenSSL|"
                                      r"from\s+OpenSSL|libssl|libcrypto", re.I),
     "capability", "provides", 0.40, "openssl", "dependency-capability"),
    ("KMS", "Storage", re.compile(r"kms:|KMS|KeyVault|EnableRotation", re.I),
     "key-management", "uses", 0.80, "boto3", "cloud-inventory"),
]


# --------------------------------------------------------------------------
# internal pipeline stages
# --------------------------------------------------------------------------

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _redact(snippet: str, limit: int = 200) -> str:
    text = " ".join(str(snippet or "").split())
    text = re.sub(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", "[REDACTED-PEM]", text)
    text = re.sub(r"(?i)(secret|password|passwd|api[_-]?key|token)\s*[:=]\s*\S+", r"\1=***", text)
    return text[:limit]


def _inventory(target) -> list[Path]:
    path = Path(target)
    if not path.exists():
        raise ValueError(f"scan target does not exist: {target}")
    if path.is_file():
        return [path]
    return sorted(p for p in path.rglob("*") if p.is_file())[:_MAX_FILES]


def _triage(files: list[Path]) -> list[tuple[Path, str]]:
    triaged = []
    for path in files:
        name = path.name
        suffix = path.suffix.lower()
        if suffix in _KEY_EXTS or name.lower() in ("id_rsa", "id_ed25519"):
            triaged.append((path, "cert"))
        elif suffix in _SOURCE_EXTS:
            triaged.append((path, "source"))
        elif suffix in _CONFIG_EXTS or name in _CONFIG_NAMES:
            triaged.append((path, "config"))
        elif suffix in (".exe", ".dll", ".so", ".bin", ".o", ".a", ".jar", ".apk", ""):
            triaged.append((path, "binary"))
        else:
            triaged.append((path, "binary"))
    return triaged


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_TEXT_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    return data.decode("utf-8", errors="ignore")


def _service_for(target: Path) -> str:
    stem = target.stem if target.is_file() else target.name
    slug = re.sub(r"\s+", "-", stem.strip().lower()) or "default-service"
    return re.sub(r"[^a-z0-9._-]", "-", slug)


def _extract(path: Path, kind: str, service: str) -> list[dict]:
    """Extract pattern hits shaped for fusion grouping."""
    text = _read_text(path)
    if not text:
        return []
    hits = []
    for hint, op_type, pattern, usage, role, conf, library, signal in _PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            key_size = None
            size_match = re.search(r"(1024|2048|3072|4096|128|192|256)", match.group(0))
            if size_match:
                try:
                    key_size = int(size_match.group(1))
                except ValueError:
                    key_size = None
            mode = None
            mode_match = re.search(r"(?i)\b(ECB|CBC|GCM|CTR)\b", match.group(0))
            if mode_match:
                mode = mode_match.group(1).upper()
            hits.append({
                "operation_type": op_type,
                "canonical_name": hint,
                "key_size": key_size,
                "mode": mode,
                "curve": None,
                "file": str(path),
                "function": None,
                "service": service,
                "endpoint": None,
                "line": 0 if kind == "binary" else line,
                "usage": usage,
                "role": role,
                "confidence": conf,
                "kind": kind,
                "library": library,
                "signal_type": signal,
                "snippet": _redact(text[max(0, match.start() - 60):match.end() + 60]),
            })
    return hits


def _group_key(hit: dict) -> tuple:
    return (hit.get("operation_type") or "", hit.get("canonical_name") or "",
            str(hit.get("key_size") or ""), hit.get("mode") or "",
            hit.get("curve") or "", hit.get("file") or "",
            hit.get("function") or "", hit.get("service") or "",
            hit.get("endpoint") or "", hit.get("role") or "")


def _location_for(hit: dict) -> dict:
    """Schema Location: line only when a real source line (>=1) exists."""
    loc: dict = {"file": hit["file"]}
    if isinstance(hit.get("line"), int) and hit["line"] >= 1:
        loc["line"] = hit["line"]
    if hit.get("function"):
        loc["function"] = hit["function"]
    if hit.get("kind") == "binary":
        loc["uri"] = f"binary-offset:{hit['file']}"
    return loc


def _notes_for(hit: dict, service: str) -> str:
    bits = [f"service {service}", f"surface {hit.get('kind', 'unknown')}"]
    if hit.get("usage"):
        bits.append(f"usage {hit['usage']}")
    # Mosca defaults carried in notes so the risk engine parses them back.
    bits.append("data_lifetime_years=5; migration_years=3")
    return "; ".join(bits)


def _fuse(hits: list[dict], service: str) -> tuple[list[dict], list[dict], list[dict]]:
    """Fuse hits into (schema assets, schema operations, rich ops for graph).

    Grouping mirrors Agent B's operation collapse (crypto/location tuple,
    ProvidedOnly never merged with direct use); confidence/usage come from
    Agent B fusion (weighted_fusion/decide_usage) over the group's signals.
    """
    groups: dict[tuple, list[dict]] = {}
    for hit in sorted(hits, key=lambda h: (h["file"], h["line"], h["canonical_name"])):
        groups.setdefault(_group_key(hit), []).append(hit)

    assets, operations, rich_ops = [], [], []
    for key in sorted(groups):
        members = groups[key]
        first = members[0]
        dep_only = first.get("role") == "provides"
        evidence_in = [{
            "detector": "pattern-extract",
            "signal_type": ("call" if m.get("signal_type") in _DIRECT_SIGNALS
                            else str(m.get("signal_type", "pattern-match"))),
            "confidence": m.get("confidence", 0.5),
            # Fusion-input only (stripped from wire evidence below).
            "detector_reliability": _SURFACE_RELIABILITY.get(m.get("kind"), 0.7),
        } for m in members]
        confidence, _breakdown = _weighted_fusion(
            evidence_in,
            param_resolved=first.get("key_size") is not None,
            binary_support=first.get("kind") == "binary",
            config_runtime_agreement=False,
            dependency_only=dep_only,
        )
        if dep_only and confidence > 0.35:
            confidence = 0.35
        confidence = round(min(1.0, max(0.0, float(confidence))), 3)
        usage_state = _decide_usage(confidence, dependency_only=dep_only)

        canonical = _canonicalize(first["canonical_name"])
        key_size = first.get("key_size")
        mode = first.get("mode")
        asset_id = _new_asset_id(canonical, key_size, mode, first.get("curve"), None)
        exposure = "internet-facing" if (
            first.get("kind") == "config" or "nginx" in first["file"]
        ) else "internal"
        best = max(members, key=lambda m: m.get("confidence", 0.0))
        signals = [{
            "tool": "pattern-extract",
            "detail": (f"{m.get('signal_type', 'pattern-match')} "
                       f"{m['canonical_name']} at {m['file']}:{m['line']}"),
            "confidence": m.get("confidence", 0.5),
            "snippet": m.get("snippet", ""),
        } for m in members]
        location = _location_for(first)
        implementation = {"library": first.get("library", "openssl")}
        context = {"exposure": exposure, "environment": "unknown",
                   "data_classification": "internal",
                   "notes": _notes_for(first, service)}
        risk_inputs = {"usage_state": usage_state, "exposure": exposure,
                       "sensitive_data": False,
                       "external_dependency": dep_only}
        asset = {"asset_id": asset_id, "canonical": canonical,
                 "original": first["canonical_name"],
                 "usage_state": usage_state, "confidence": confidence,
                 "evidence": signals}
        if isinstance(key_size, int):
            asset["key_size"] = key_size
        if mode:
            asset["mode"] = mode
        if first.get("curve"):
            asset["curve"] = first["curve"]
        asset["library"] = implementation["library"]
        asset["location"] = dict(location)
        asset["implementation"] = dict(implementation)
        asset["context"] = dict(context)
        asset["risk_inputs"] = dict(risk_inputs)
        assets.append(asset)

        loc_label = f"{first['file']}:{first.get('line', 0)}"
        op_id = _new_operation_id(first["operation_type"], asset_id,
                                  first.get("function"), loc_label)
        operations.append({
            "operation_id": op_id, "operation_type": first["operation_type"],
            "asset_id": asset_id, "confidence": confidence,
            "evidence": signals,
            **({"function": first["function"]} if first.get("function") else {}),
            "location": dict(location), "implementation": dict(implementation),
            "context": dict(context), "risk_inputs": dict(risk_inputs),
        })
        # Rich sidecar (graph only, never serialized): service + role links.
        rich_ops.append({
            "operation_id": op_id, "operation_type": first["operation_type"],
            "canonical_name": canonical, "key_size": key_size, "mode": mode,
            "usage_state": usage_state, "confidence": confidence,
            "asset_ids": [asset_id],
            "location": {"file": first["file"], "line": first.get("line", 0),
                         "service": service},
            "implementation": {"role": first.get("role", "uses"),
                               "library": implementation["library"]},
            "context": {"service": service, "exposure": exposure,
                        "criticality": "medium"},
            "material": {}, "evidence": [{}],
        })
    return assets, operations, rich_ops


def _scan_id_for(target: str) -> str:
    seed = f"{target}|{uuid.uuid4().hex}".encode("utf-8")
    return "scan:" + hashlib.blake2s(seed, digest_size=8).hexdigest()


# --------------------------------------------------------------------------
# public facade
# --------------------------------------------------------------------------

def scan(target, include_risk: bool = False, include_recommend: bool = False,
         Z: float = 10, service: str | None = None) -> dict:
    """Scan one target -> CIR v0.1 source-of-truth dict (validated)."""
    started = _utcnow()
    path = Path(target)
    service_name = service or _service_for(path)
    files = _inventory(path)
    triaged = _triage(files)

    hits: list[dict] = []
    for file_path, kind in triaged:
        hits.extend(_extract(file_path, kind, service_name))

    assets, operations, rich_ops = _fuse(hits, service_name)
    wire_graph = _to_cir_graph(_build_graph(rich_ops, [], []))
    finished = _utcnow()
    doc = {
        "cir_version": _CIR_VERSION,
        "scan_id": _scan_id_for(str(target)),
        "target": str(target),
        "started_at": started,
        "finished_at": finished,
        "tool_versions": dict(_TOOL_VERSIONS),
        "registry_version": str(_REGISTRY_VERSION),
        "assets": assets,
        "operations": operations,
        "graph": wire_graph,
        "stats": {
            "asset_count": len(assets),
            "operation_count": len(operations),
            "node_count": len(wire_graph["nodes"]),
            "edge_count": len(wire_graph["edges"]),
        },
    }
    if include_risk or include_recommend:
        doc = enrich_cir(doc, Z=Z, with_risk=include_risk,
                         with_recommend=include_recommend)
    return _validate_cir(doc)


def scan_paths(targets, max_workers: int = 4, **kwargs) -> list[dict]:
    """Scan several targets concurrently (ThreadPool, single process)."""
    targets = list(targets or [])
    if not targets:
        return []
    workers = max(1, min(int(max_workers or 1), len(targets)))
    if workers == 1:
        return [scan(t, **kwargs) for t in targets]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda t: scan(t, **kwargs), targets))


def risk(cir: dict, Z: float = 10) -> list[dict]:
    """Score a CIR document -> internal RiskRecords sorted by score desc."""
    try:
        from ecdat.core.risk import score_cir as _score_cir
    except ImportError:  # pragma: no cover
        return []
    return _score_cir(cir, Z)


def recommend(cir: dict, risks: list[dict] | dict | None = None) -> list[dict]:
    """Recommend PQC/modern replacements for a CIR document (internal view).

    When ``risks`` is omitted, internal risks are scored first (default
    Z=10) so priorities reflect measurement, not hints. Wire ``risks``
    embedded in the CIR are intentionally ignored (different shape);
    pass ``risk(cir)`` output explicitly to reuse it.
    """
    try:
        from ecdat.core.recommend import recommend_cir as _recommend_cir
    except ImportError:  # pragma: no cover
        return []
    if risks is None:
        try:
            risks = risk(cir)
        except Exception:
            risks = None
    return _recommend_cir(cir, risks)


def enrich_cir(cir: dict, Z: float = 10, with_risk: bool = True,
               with_recommend: bool = True) -> dict:
    """Downstream stage: CIR copy + wire risks/recommendations (validated).

    Never mutates the input. ``scan`` output stays lean; call this when the
    caller explicitly wants the scored/migration view attached.
    """
    try:
        from ecdat.core.recommend import to_cir_recommendation as _to_cir_rec
        from ecdat.core.risk import to_cir_risk as _to_cir_risk
    except ImportError:  # pragma: no cover
        return copy.deepcopy(cir)
    doc = copy.deepcopy(cir)
    assets_by_id = {a.get("asset_id"): a for a in (doc.get("assets", []) or [])
                    if isinstance(a, dict) and a.get("asset_id")}
    internal_risks = risk(doc, Z) if with_risk else []
    if with_risk:
        wire_risks = []
        for record in internal_risks:
            op_id = record.get("operation_id")
            op = next((o for o in (doc.get("operations", []) or [])
                       if isinstance(o, dict) and o.get("operation_id") == op_id), {})
            wire_risks.append(_to_cir_risk(
                record, asset_id=op.get("asset_id"),
                confidence=op.get("confidence")))
        doc["risks"] = wire_risks
    if with_recommend:
        internal_recs = recommend(doc, internal_risks if with_risk else None)
        wire_recs = []
        for rec in internal_recs:
            op_id = rec.get("operation_id")
            op = next((o for o in (doc.get("operations", []) or [])
                       if isinstance(o, dict) and o.get("operation_id") == op_id), {})
            asset = assets_by_id.get(op.get("asset_id", ""), {}) or {}
            wire_recs.append(_to_cir_rec(
                rec, asset_ids=rec.get("asset_ids") or (
                    [op["asset_id"]] if op.get("asset_id") else []),
                canonical=str(asset.get("canonical", "UNKNOWN"))))
        doc["recommendations"] = wire_recs
    stats = dict(doc.get("stats", {}) or {})
    if with_risk:
        stats["risk_count"] = len(doc.get("risks", []) or [])
    if with_recommend:
        stats["recommendation_count"] = len(doc.get("recommendations", []) or [])
    doc["stats"] = stats
    return _validate_cir(doc)


# -- canonical v1 mapping ----------------------------------------------------

def _severity_for(usage_state: str, risk_class: str | None) -> str:
    state = str(usage_state or "Possible").strip().lower()
    if state in ("providedonly", "provided-only", "falsepositivesuppressed",
                 "false-positive-suppressed", "false_positive_suppressed",
                 "suppressed"):
        return "info"
    if state == "possible":
        return "low"
    if state == "probable":
        return "medium"
    # Confirmed -> high/critical by measured risk, high when risk unavailable.
    if risk_class == "Critical":
        return "critical"
    return "high"


def _human_title(canonical: str, operation_type: str = "",
                 key_size=None, mode: str = "") -> str:
    """Human-readable finding title from data ECDAT already produces.

    Never invents new facts: the canonical name (plus key size / mode
    when the asset records them) and the operation type are the only
    inputs. Internal op/asset IDs stay in finding metadata, never in
    the title.
    """
    name = str(canonical or "UNKNOWN").strip() or "UNKNOWN"
    upper = name.upper()
    if upper == "RSA" and isinstance(key_size, int):
        return f"{key_size}-bit RSA usage detected"
    nouns = {
        "ENCRYPT": "encryption", "DECRYPT": "decryption",
        "SIGN": "signing", "VERIFY": "verification",
        "KEYEXCHANGE": "key exchange", "HASH": "hashing",
        "KDF": "key derivation", "TLS": "TLS configuration",
        "STORAGE": "key/certificate storage",
        "KEYMANAGEMENT": "key management",
    }
    noun = nouns.get(re.sub(r"[^A-Za-z]", "", str(operation_type or "")).upper(), "")
    if noun and noun not in ("encryption", "signing") and upper not in (
            "TLS1.0", "TLS-1.0", "TLS1.3", "TLS-1.3"):
        return f"{name} {noun} detected"
    if upper in ("TLS1.0", "TLS-1.0"):
        return "Legacy TLS 1.0/1.1 usage detected"
    if upper in ("TLS1.3", "TLS-1.3"):
        return "TLS 1.3 usage detected"
    return f"{name} usage detected"


def _rule_id_for(canonical: str, key_size=None, mode: str = "",
                 protocol: str = "") -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", str(canonical or "UNKNOWN")).strip("-").upper()
    slug = slug or "UNKNOWN"
    if isinstance(key_size, int) and slug == "RSA":
        slug = f"RSA-{key_size}"
    if "ECB" in str(mode or "").upper() and "ECB" not in slug:
        slug = f"{slug}-ECB"
    if re.search(r"1\.0(?!\d)", str(protocol or "")) and "TLS" in slug:
        slug = "TLS-1.0"
    return {"TLS1-0": "TLS-1.0", "TLS1-3": "TLS-1.3", "X-509": "X.509"}.get(slug, slug)


def to_canonical(cir: dict) -> dict:
    """Map CIR v0.1 -> canonical v1 document dict (validated when possible).

    usage_state (operation risk_inputs, else asset) -> severity:
    Confirmed->high/critical by risk, Probable->medium, Possible->low,
    ProvidedOnly/Suppressed->info. Location -> file/line (missing line ->
    0 for binary/cloud-style evidence via uri, else the stored line).
    """
    if not isinstance(cir, dict):
        cir = {}
    ops = cir.get("operations", []) or []
    assets_by_id = {a.get("asset_id"): a for a in (cir.get("assets", []) or [])
                    if isinstance(a, dict) and a.get("asset_id")}
    risks: dict[str, dict] = {}
    try:
        for record in risk(cir):
            risks[str(record.get("operation_id"))] = record
    except Exception:  # risk must never break the canonical export
        risks = {}

    findings = []
    for op in ops:
        if not isinstance(op, dict):
            continue
        op_id = str(op.get("operation_id", "op-unknown"))
        asset = assets_by_id.get(op.get("asset_id", ""), {}) or {}
        canonical = str(asset.get("canonical", op.get("canonical_name", "UNKNOWN")))
        risk_inputs = op.get("risk_inputs", {}) if isinstance(op.get("risk_inputs"), dict) else {}
        usage_state = str(risk_inputs.get("usage_state",
                                          asset.get("usage_state", "Possible")))
        location = op.get("location", {}) if isinstance(op.get("location"), dict) else {}
        evidence = op.get("evidence", []) if isinstance(op.get("evidence"), list) else []
        first = evidence[0] if evidence and isinstance(evidence[0], dict) else {}
        line = location.get("line", 0)
        try:
            line = int(line)
        except (TypeError, ValueError):
            line = 0
        if line < 0:
            line = 0
        snippet = str(first.get("snippet", "") or "")
        confidence = op.get("confidence", asset.get("confidence"))
        try:
            confidence = float(confidence) if confidence is not None else None
        except (TypeError, ValueError):
            confidence = None
        finding = {
            "rule_id": _rule_id_for(canonical, asset.get("key_size"),
                                    asset.get("mode", ""), asset.get("protocol", "")),
            "title": _human_title(canonical, op.get("operation_type", ""),
                                  asset.get("key_size"), asset.get("mode", "")),
            "severity": _severity_for(usage_state,
                                      risks.get(op_id, {}).get("class")),
            "file": str(location.get("file", first.get("file", "unknown")) or "unknown"),
            "line": line,
        }
        if snippet:
            finding["snippet"] = snippet[:500]
        if confidence is not None:
            finding["confidence"] = min(1.0, max(0.0, confidence))
        finding["metadata"] = {
            "cir_op_id": op_id,
            "cir_asset_id": op.get("asset_id", ""),
            "canonical_name": canonical,
            "usage_state": usage_state,
            **({"risk_class": risks[op_id]["class"],
                "risk_score": risks[op_id]["score"]} if op_id in risks else {}),
        }
        findings.append(finding)

    now = _utcnow()
    files_scanned = 0
    doc = {
        "schema_version": "1.0",
        "scan_id": str(cir.get("scan_id", f"scan-{uuid.uuid4().hex[:12]}")),
        "target": str(cir.get("target", "unknown")),
        "started_at": str(cir.get("started_at", now)),
        "finished_at": str(cir.get("finished_at", now)),
        "tool_versions": {str(k): str(v) for k, v in
                          dict(cir.get("tool_versions", _TOOL_VERSIONS)).items()},
        "findings": findings,
        "stats": {"files_scanned": files_scanned,
                  "findings_count": len(findings)},
    }
    try:  # validate canonical shape when the platform module is importable
        from ecdat.core.validate import validate as _validate_canonical
        return _validate_canonical(doc)
    except ImportError:
        return doc


# -- minimal OpenAPI ----------------------------------------------------------

def get_openapi() -> dict:
    """Minimal OpenAPI 3.0 dict for scan/risk/recommend/graph/export + curl."""
    base = "http://127.0.0.1:8734"
    return {
        "openapi": "3.0.0",
        "info": {"title": "ECDAT Core API (Agent C facade)", "version": "0.1.0",
                 "description": "CIR v0.1 source of truth. scan returns lean "
                                "CIR; risk/recommend are downstream stages."},
        "paths": {
            "/scan": {"post": {
                "summary": "Scan a target -> CIR v0.1 document",
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object",
                    "required": ["target"],
                    "properties": {
                        "target": {"type": "string"},
                        "include_risk": {"type": "boolean", "default": False},
                        "include_recommend": {"type": "boolean", "default": False},
                        "Z": {"type": "number", "default": 10},
                    }}}}},
                "responses": {"200": {"description": "CIR v0.1 document"},
                              "400": {"description": "bad target"}}}},
            "/risk": {"post": {
                "summary": "Score a CIR document -> wire RiskRecords",
                "requestBody": {"content": {"application/json":
                    {"schema": {"type": "object"}}}},
                "responses": {"200": {"description": "risk list"}}}},
            "/recommend": {"post": {
                "summary": "Recommend PQC/modern replacements for a CIR",
                "requestBody": {"content": {"application/json":
                    {"schema": {"type": "object"}}}},
                "responses": {"200": {"description": "recommendation list"}}}},
            "/graph": {"post": {
                "summary": "Build the knowledge graph for CIR operations",
                "requestBody": {"content": {"application/json":
                    {"schema": {"type": "object"}}}},
                "responses": {"200": {"description": "nodes + edges"}}}},
            "/export": {"post": {
                "summary": "Export CIR as canonical v1 (format=canonical)",
                "parameters": [{"name": "format", "in": "query",
                                "schema": {"type": "string",
                                           "enum": ["canonical", "cir"]}}],
                "requestBody": {"content": {"application/json":
                    {"schema": {"type": "object"}}}},
                "responses": {"200": {"description": "exported document"}}}},
        },
        "x-curl-examples": {
            "scan": ("curl -X POST " + base + "/scan -H 'Content-Type: application/json'"
                     " -d '{\"target\": \"./repo\"}'"),
            "risk": ("curl -X POST " + base + "/risk -H 'Content-Type: application/json'"
                     " -d @scan.cir.json"),
            "recommend": ("curl -X POST " + base + "/recommend"
                          " -H 'Content-Type: application/json' -d @scan.cir.json"),
            "graph": ("curl -X POST " + base + "/graph -H 'Content-Type: application/json'"
                      " -d @scan.cir.json"),
            "export": ("curl -X POST '" + base + "/export?format=canonical'"
                       " -H 'Content-Type: application/json' -d @scan.cir.json"),
        },
    }
