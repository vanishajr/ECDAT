"""Staged binary analysis: cheap pass, escalation, expensive backends.

Architecture pipeline (Phase 6)::

    metadata/imports -> strings -> signatures/constants -> behavior
    -> deobfuscation/decompiler only when justified

Cheap stages (LIEF imports/symbols when installed, builtin strings,
constant/OID byte signatures) run for EVERY binary. Expensive backends
(capa behavior rules, FLOSS decoded strings, optional Ghidra) run only
for escalation candidates, gated by profile. Missing tools reduce the
reported coverage status; they never crash a scan and never read as
"nothing found".

Stdlib only for orchestration (shutil/subprocess for optional CLIs).
"""

from __future__ import annotations

import hashlib
import math
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "CheapSignals",
    "EscalationDecision",
    "BinaryStageReport",
    "ExpensiveStatus",
    "expensive_tool_status",
    "analyze_cheap",
    "decide_escalation",
    "match_constants",
    "match_oids",
    "match_symbol_strings",
    "file_entropy",
    "detect_format",
]

_CHEAP_STAGES = ("lief", "strings", "signatures")


@dataclass
class CheapSignals:
    """Everything the cheap pass learned about one binary."""

    path: str
    size: int
    fmt: str  # elf | pe | mach-o | unknown
    magic: str
    finding_count: int = 0
    min_confidence: float = 1.0
    distinct_canonicals: tuple[str, ...] = ()
    has_import_evidence: bool = False
    has_symbol_evidence: bool = False
    has_constant_evidence: bool = False
    has_oid_evidence: bool = False
    strings_only: bool = True
    linked_libs: tuple[str, ...] = ()
    crypto_symbols: tuple[str, ...] = ()
    stripped: bool | None = None  # None = unknown (no LIEF)
    packed: str = "unknown"  # yes | suspected | no | unknown
    entropy: float = 0.0
    high_value_name: bool = False
    stage_times: dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path, "size": self.size, "format": self.fmt,
            "magic": self.magic, "finding_count": self.finding_count,
            "min_confidence": self.min_confidence,
            "distinct_canonicals": list(self.distinct_canonicals),
            "has_import_evidence": self.has_import_evidence,
            "has_symbol_evidence": self.has_symbol_evidence,
            "has_constant_evidence": self.has_constant_evidence,
            "has_oid_evidence": self.has_oid_evidence,
            "strings_only": self.strings_only,
            "linked_libs": list(self.linked_libs),
            "crypto_symbols": list(self.crypto_symbols),
            "stripped": self.stripped,
            "packed": self.packed,
            "entropy": round(self.entropy, 3),
            "high_value_name": self.high_value_name,
            "stage_times": dict(self.stage_times),
        }


@dataclass
class EscalationDecision:
    """Explainable escalation verdict for one binary."""

    escalate: bool
    reasons: list[str]
    signals: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"escalate": self.escalate, "reasons": list(self.reasons),
                "signals": dict(self.signals)}


@dataclass
class ExpensiveStatus:
    """Outcome of one expensive backend on one binary."""

    backend: str
    status: str  # success | unavailable | skipped | failed | not-configured
    detail: str = ""
    finding_count: int = 0
    elapsed_sec: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {"backend": self.backend, "status": self.status,
                "detail": self.detail, "finding_count": self.finding_count,
                "elapsed_sec": round(self.elapsed_sec, 3)}


@dataclass
class BinaryStageReport:
    """Full staged record for one binary."""

    signals: CheapSignals
    escalation: EscalationDecision
    expensive: list[ExpensiveStatus] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"signals": self.signals.as_dict(),
                "escalation": self.escalation.as_dict(),
                "expensive": [e.as_dict() for e in self.expensive]}


def detect_format(head: bytes) -> tuple[str, str]:
    """(format, magic-hex) from magic bytes (never raises)."""
    try:
        magic = bytes(head or b"")[:8]
        if magic.startswith(b"\x7fELF"):
            return "elf", magic.hex()
        if magic.startswith(b"MZ"):
            return "pe", magic.hex()
        if magic[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                         b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                         b"\xca\xfe\xba\xbe"):
            return "mach-o", magic.hex()
        return "unknown", magic.hex()
    except Exception:
        return "unknown", ""


def file_entropy(path: Path, sample: int = 262144) -> float:
    """Shannon entropy over the first ``sample`` bytes (never raises)."""
    try:
        data = path.read_bytes()[:sample]
    except Exception:
        return 0.0
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            prob = count / total
            entropy -= prob * math.log2(prob)
    return entropy


def match_constants(data: bytes) -> list[tuple[str, int]]:
    """(canonical, offset) hits for known crypto constant bytes."""
    from ecdat.scanners.binary.crypto_signatures import CRYPTO_CONSTANTS
    blob = bytes(data or b"").hex()
    hits: list[tuple[str, int]] = []
    for hex_prefix, canonical in CRYPTO_CONSTANTS.items():
        offset = blob.find(hex_prefix)
        if offset >= 0:
            hits.append((canonical, offset // 2))
    return hits


def match_oids(data: bytes, text: str = "") -> list[tuple[str, str]]:
    """(canonical, form) OID hits in raw bytes and decoded text."""
    from ecdat.scanners.binary.crypto_signatures import (
        CRYPTO_OIDS, CRYPTO_OID_STRINGS)
    hits: list[tuple[str, str]] = []
    try:
        blob = bytes(data or b"").hex()
        for hex_prefix, canonical in CRYPTO_OIDS.items():
            if hex_prefix in blob:
                hits.append((canonical, "der"))
    except Exception:
        pass
    for dotted, canonical in CRYPTO_OID_STRINGS.items():
        if dotted in (text or ""):
            hits.append((canonical, "string"))
    return hits


def match_symbol_strings(strings: list[str]) -> list[tuple[str, str]]:
    """(canonical, symbol) for symbol-table-like strings (no LIEF needed)."""
    from ecdat.scanners.binary.crypto_signatures import CRYPTO_SYMBOLS
    hits: list[tuple[str, str]] = []
    for text in strings or []:
        lowered = str(text).strip().lower()
        if not lowered or len(lowered) > 128:
            continue
        for pattern, canonical in CRYPTO_SYMBOLS.items():
            if pattern in lowered:
                hits.append((canonical, str(text).strip()[:120]))
                break
    return hits


_HIGH_VALUE_HINTS = ("crypto", "ssl", "tls", "vault", "keystore", "key",
                     "cipher", "ssh", "hsm", "kms", "cert")


def expensive_tool_status() -> dict[str, str]:
    """Availability of expensive backends (never raises, no execution)."""
    status = {
        "capa": "available" if shutil.which("capa") else "unavailable",
        "floss": "available" if shutil.which("floss") else "unavailable",
    }
    try:
        import os
        ghidra = os.environ.get("GHIDRA_INSTALL", "") or shutil.which(
            "ghidra") or ""
        status["ghidra"] = "configured" if ghidra else "not-configured"
    except Exception:
        status["ghidra"] = "not-configured"
    return status


def analyze_cheap(path: Path, cheap_findings: list,
                  lief_symbols: list[str] | None = None,
                  lief_imports: list[str] | None = None,
                  lief_stripped: bool | None = None) -> CheapSignals:
    """Fold cheap-stage findings + byte probes into candidate state."""
    from ecdat.scanners.binary.crypto_signatures import PACKER_MARKERS

    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    try:
        with path.open("rb") as handle:
            head = handle.read(8)
    except OSError:
        head = b""
    fmt, magic = detect_format(head)

    tools: set[str] = set()
    canonicals: set[str] = set()
    libs: set[str] = set()
    symbols: set[str] = set()
    min_conf = 1.0
    for finding in cheap_findings or []:
        try:
            for evidence in (finding.evidence or []):
                tool = str(getattr(evidence, "tool", "") or "")
                tools.add(tool)
                detail = str(getattr(evidence, "detail", "") or "")
                if tool == "binary-lief" and "Imported symbol:" in detail:
                    symbols.add(detail.rsplit(":", 1)[-1].strip()[:120])
                if tool == "binary-lief" and detail.startswith("Linked library:"):
                    libs.add(detail.rsplit(":", 1)[-1].strip()[:120])
                conf = getattr(evidence, "confidence", None)
                if isinstance(conf, (int, float)):
                    min_conf = min(min_conf, float(conf))
            canonicals.add(str(getattr(finding, "canonical", "")))
            for lib in (getattr(finding, "library", "") or "",):
                if lib and lib != "unknown":
                    libs.add(str(lib)[:120])
        except Exception:
            continue
    for extra in (lief_symbols or []):
        symbols.add(str(extra)[:120])
    for extra in (lief_imports or []):
        libs.add(str(extra)[:120])

    has_import = any("binary-import:" in _uri_of(f) for f in (cheap_findings or []))
    has_symbol = bool(symbols) or any(
        "binary-symbol:" in _uri_of(f) for f in (cheap_findings or []))
    strings_only = not (has_import or has_symbol)
    if not cheap_findings:
        min_conf = 1.0

    entropy = file_entropy(path)
    packed = "unknown"
    try:
        sample = path.read_bytes()[:1048576]
        text = sample.decode("ascii", errors="ignore").lower()
        if any(marker.lower() in text for marker in PACKER_MARKERS):
            packed = "yes"
        elif entropy >= 7.4 and len(
                [s for s in text.split() if len(s) >= 4]) < 50:
            packed = "suspected"
        else:
            packed = "no"
    except Exception:
        packed = "unknown"

    name = path.name.lower()
    high_value = any(hint in name for hint in _HIGH_VALUE_HINTS)
    return CheapSignals(
        path=str(path), size=size, fmt=fmt, magic=magic,
        finding_count=len(cheap_findings or []),
        min_confidence=round(min_conf, 3) if cheap_findings else 1.0,
        distinct_canonicals=tuple(sorted(canonicals)),
        has_import_evidence=has_import, has_symbol_evidence=has_symbol,
        strings_only=strings_only,
        linked_libs=tuple(sorted(libs)), crypto_symbols=tuple(sorted(symbols)),
        stripped=lief_stripped, packed=packed, entropy=entropy,
        high_value_name=high_value)


def _uri_of(finding) -> str:
    try:
        loc = getattr(finding, "location", None)
        return str(getattr(loc, "uri", "") or "")
    except Exception:
        return ""


def decide_escalation(signals: CheapSignals, *,
                      allowed: bool = True) -> EscalationDecision:
    """Roadmap-taxonomy reasons + a REAL ``should_escalate()`` call.

    Reasons are explicit even when escalation is disabled by profile
    (explainable "would escalate, profile forbids it" instead of silence).
    """
    from ecdat.core.scheduler import AdaptiveScheduler

    reasons: list[str] = []
    if signals.finding_count == 0:
        return EscalationDecision(
            escalate=False, reasons=["no-crypto-evidence"],
            signals={"finding_count": 0})
    if signals.stripped is True:
        reasons.append("stripped: no symbol table, imports only")
    if signals.packed in ("yes", "suspected"):
        reasons.append(f"packed: {signals.packed}")
    if signals.min_confidence < 0.65:
        reasons.append(
            f"weak-confidence: cheapest evidence at {signals.min_confidence}")
    if len(signals.distinct_canonicals) >= 3 and signals.strings_only:
        reasons.append("ambiguous-crypto-evidence: "
                       f"{len(signals.distinct_canonicals)} families from "
                       "strings alone")
    if len(signals.distinct_canonicals) >= 2 and signals.has_import_evidence:
        reasons.append("conflicting-evidence: imports disagree with "
                       "string-level families")
    if signals.high_value_name and signals.finding_count > 0:
        reasons.append("high-value-target: crypto-role filename")
    if signals.has_constant_evidence or signals.has_oid_evidence:
        reasons.append("static-implementation: embedded constants/OIDs merit "
                       "behavior confirmation")

    scheduler = AdaptiveScheduler()
    verdict = scheduler.should_escalate({
        "has_hit": True,
        "confidence": signals.min_confidence,
        "surface": "binary",
        "weak_hit": signals.min_confidence < 0.65,
        "packed": signals.packed == "yes",
        "obfuscated": signals.packed in ("yes", "suspected"),
    }) if reasons else False
    escalate = bool(verdict and reasons and allowed)
    if reasons and not allowed:
        reasons = reasons + ["escalation-not-allowed-by-profile"]
    if not reasons:
        reasons = ["cheap-pass-conclusive"]
    return EscalationDecision(
        escalate=escalate, reasons=reasons,
        signals={"finding_count": signals.finding_count,
                 "min_confidence": signals.min_confidence,
                 "should_escalate": bool(verdict),
                 "allowed": bool(allowed)})


def run_capa(path: Path, timeout: int = 300) -> tuple[str, list, float]:
    """Run capa behavior rules (candidate-only). Returns (status, findings, secs)."""
    from ecdat.scanners.base import ScannerFinding, create_evidence_signal
    from ecdat.core.cir_models import (
        Location, Implementation, Context, UsageState, Exposure)
    from ecdat.core.signature_registry import normalize_algorithm, get_category

    if not shutil.which("capa"):
        return "unavailable", [], 0.0
    started = time.monotonic()
    try:
        proc = subprocess.run(
            ["capa", "-j", str(path)], capture_output=True, text=True,
            timeout=timeout)
    except subprocess.TimeoutExpired:
        return "failed: timeout", [], time.monotonic() - started
    except Exception as exc:
        return f"failed: {exc}", [], time.monotonic() - started
    elapsed = time.monotonic() - started
    if proc.returncode not in (0, 1):
        return f"failed: rc={proc.returncode}", [], elapsed
    try:
        import json as _json
        data = _json.loads(proc.stdout or "{}")
    except Exception:
        return "failed: unparsable-output", [], elapsed
    findings: list = []
    rules = data.get("rules", {}) if isinstance(data, dict) else {}
    for rule_name, rule in rules.items():
        if not isinstance(rule, dict) or not rule.get("matches"):
            continue
        namespace = str(rule.get("meta", {}).get("namespace", ""))
        if "crypto" not in namespace.lower() and "crypt" not in str(rule_name).lower():
            continue
        token = re_token(rule_name)
        canonical, _original = normalize_algorithm(token)
        if get_category(canonical) is None and canonical.upper() == token.upper():
            continue  # unknown token, not crypto evidence
        confidence = 0.75
        findings.append(ScannerFinding(
            canonical=canonical, original=token,
            usage_state=UsageState.PROBABLE, confidence=confidence,
            evidence=[create_evidence_signal(
                tool="binary-capa",
                detail=f"capa behavior rule: {rule_name}",
                confidence=confidence,
                snippet=f"{namespace}::{rule_name}"[:200])],
            location=Location(file=str(path), uri=f"binary-capa:{rule_name}"),
            implementation=Implementation(library="unknown", provider="capa",
                                          api=str(rule_name)),
            context=Context(exposure=Exposure.INTERNAL),
        ))
    return "success", findings, elapsed


def re_token(rule_name: str) -> str:
    """Best crypto token from a capa rule name."""
    import re as _re
    parts = _re.split(r"[/_\-.\s]+", str(rule_name or ""))
    for part in parts:
        if len(part) >= 3 and part.lower() not in (
                "crypto", "crypt", "cryptography", "encode", "using",
                "with", "data", "detection", "detect"):
            return part
    return str(rule_name or "capa")


def run_floss(path: Path, timeout: int = 300) -> tuple[str, list, float]:
    """Run FLOSS decoded strings, re-matched against crypto tables."""
    from ecdat.scanners.base import ScannerFinding, create_evidence_signal
    from ecdat.core.cir_models import (
        Location, Implementation, Context, UsageState, Exposure)
    from ecdat.core.signature_registry import normalize_algorithm, get_category
    from ecdat.scanners.binary.crypto_signatures import (
        CRYPTO_STRINGS, CRYPTO_SYMBOLS, CRYPTO_OID_STRINGS)

    if not shutil.which("floss"):
        return "unavailable", [], 0.0
    started = time.monotonic()
    try:
        proc = subprocess.run(
            ["floss", str(path)], capture_output=True, text=True,
            timeout=timeout)
    except subprocess.TimeoutExpired:
        return "failed: timeout", [], time.monotonic() - started
    except Exception as exc:
        return f"failed: {exc}", [], time.monotonic() - started
    elapsed = time.monotonic() - started
    if proc.returncode not in (0, 1):
        return f"failed: rc={proc.returncode}", [], elapsed
    findings: list = []
    seen: set[str] = set()
    for line in (proc.stdout or "").splitlines():
        text = line.strip()
        if len(text) < 4 or len(text) > 256:
            continue
        lowered = text.lower()
        hit = None
        for pattern, canonical in CRYPTO_SYMBOLS.items():
            if pattern in lowered:
                hit = canonical
                break
        if hit is None:
            for pattern, canonical in CRYPTO_STRINGS.items():
                if pattern in lowered:
                    hit = canonical
                    break
        if hit is None:
            for dotted, canonical in CRYPTO_OID_STRINGS.items():
                if dotted in text:
                    hit = canonical
                    break
        if hit is None or hit in seen:
            continue
        seen.add(hit)
        canonical, _original = normalize_algorithm(hit)
        if get_category(canonical) is None:
            continue
        confidence = 0.5  # decoded strings: above plain strings, below symbols
        findings.append(ScannerFinding(
            canonical=canonical, original=hit,
            usage_state=UsageState.POSSIBLE, confidence=confidence,
            evidence=[create_evidence_signal(
                tool="binary-floss",
                detail=f"FLOSS decoded string: {text[:100]}",
                confidence=confidence,
                snippet=text[:200])],
            location=Location(file=str(path), uri="binary-floss:decoded"),
            implementation=Implementation(library="unknown", provider="floss"),
            context=Context(exposure=Exposure.INTERNAL),
        ))
    return "success", findings, elapsed
