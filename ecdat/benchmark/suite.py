"""Benchmark suite + case registry (Person 3 platform layer).

Turns the Task 16 ground-truth primitives into a structured,
deterministic catalogue of benchmark cases grouped by category.
Strict separation is enforced by construction:

    CASE DEFINITION (this module: SuiteCase, no predictions)
        -> PREDICTION (a future detector/baseline output set)
        -> CASE EXECUTION + METRIC EVALUATION
           (Task 16: with_predictions() -> BenchmarkCase ->
            pair()/evaluate_cases()/confusion_metrics())

A `SuiteCase` carries NO predictions, so ground truth cannot be
"correct by definition". All seed cases are explicitly synthetic
fixtures — NOT claims that any real detector finds them. Real
Person 1/Person 2 outputs and baseline predictions later become
`predicted` sets evaluated against these cases via
`with_predictions()`, without redesigning this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ecdat.benchmark.ground_truth import (
    BenchmarkCase,
    GroundTruth,
    finding_key,
)

SUITE_ID = "ecdat-seed-suite"
SUITE_VERSION = "1"

# Stable group identifiers. One canonical id per category, no aliases.
GROUPS: tuple[str, ...] = (
    "source",
    "binary",
    "dependency",
    "container",
    "config",
    "certificate_key",
    "runtime_tls",
    "cloud_kms",
    "fusion",
    "risk",
    "pqc_recommendation",
)

GROUP_DESCRIPTIONS: dict[str, str] = {
    "source": "Source-code crypto findings (algorithms, hashes, protocols in code).",
    "binary": "Binary observations (crypto symbols/strings in binaries).",
    "dependency": "Dependency findings (crypto libraries declared by a project).",
    "container": "Container findings (crypto packages/configs in images).",
    "config": "Configuration findings (TLS/crypto settings in config files).",
    "certificate_key": "Certificate/key findings (expiry, weakness, rotation metadata).",
    "runtime_tls": "Runtime TLS observations (negotiated versions/ciphers on services).",
    "cloud_kms": "Cloud KMS findings (key rotation/policy configuration).",
    "fusion": "Multi-source fusion cases (same asset seen by several hypothetical sources).",
    "risk": "Deterministic synthetic finding sets shaped for risk-scoring checks.",
    "pqc_recommendation": "Deterministic synthetic inputs shaped for PQC-relevance checks.",
}

_SYNTH_NOTE = (
    "Synthetic benchmark fixture: independently hand-authored labels "
    "for registry/evaluation machinery. Not a detection claim and "
    "not production accuracy."
)


@dataclass(frozen=True)
class SuiteCase:
    """One registered benchmark case. Prediction-free by design.

    `input_ref` is a deterministic fixture reference (a virtual path,
    not a file that is read). `ground_truth` holds ONLY expected keys
    plus an optional universe; decoy universe members are
    absent-by-construction candidate keys (checked, not present).
    """

    case_id: str
    group: str
    title: str
    description: str
    input_ref: str
    ground_truth: GroundTruth
    tags: tuple[str, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        if not self.case_id or not isinstance(self.case_id, str):
            raise ValueError("case_id must be a non-empty string")
        if self.group not in GROUPS:
            raise ValueError(
                f"unknown group {self.group!r}; expected one of {list(GROUPS)}")
        if not isinstance(self.ground_truth, GroundTruth):
            raise ValueError("ground_truth must be a GroundTruth instance")


def _c(case_id: str, group: str, title: str, description: str,
       input_ref: str, expected: Iterable[str],
       decoys: Iterable[str], polarity: str) -> SuiteCase:
    """Compact hand-authored case constructor (all synthetic)."""
    return SuiteCase(
        case_id=case_id,
        group=group,
        title=title,
        description=description,
        input_ref=input_ref,
        ground_truth=GroundTruth(
            expected=frozenset(expected),
            universe=frozenset(set(expected) | set(decoys)),
            synthetic=True,
            note=_SYNTH_NOTE,
        ),
        tags=("synthetic", polarity),
        note=_SYNTH_NOTE,
    )


def _build_seed_cases() -> tuple[SuiteCase, ...]:
    K = finding_key
    return (
        # -- source ------------------------------------------------------
        _c("source.aes.direct", "source", "Direct AES-ECB usage",
           "Source file calls AES in ECB mode at line 8.",
           "seed/source/aes_direct.py",
           [K("AES-ECB", "seed/source/aes_direct.py", 8)],
           [K("RSA-1024", "seed/source/aes_direct.py", 3)], "positive"),
        _c("source.hash.weak", "source", "Weak MD5 hash usage",
           "Source file uses MD5 for integrity at line 5.",
           "seed/source/hash_weak.py",
           [K("MD5-USAGE", "seed/source/hash_weak.py", 5)],
           [K("AES-ECB", "seed/source/hash_weak.py", 9)], "positive"),
        _c("source.plain.no_crypto", "source", "Non-crypto source file",
           "Source file with no crypto constructs; nothing expected.",
           "seed/source/plain.py",
           [], [K("AES-ECB", "seed/source/plain.py", 4),
                K("MD5-USAGE", "seed/source/plain.py", 11)], "negative"),
        # -- binary ------------------------------------------------------
        _c("binary.crypto.symbol", "binary", "Crypto symbol in binary",
           "Binary contains a libcrypto AES symbol reference.",
           "seed/binary/firmware.bin",
           [K("LIBCRYPTO-SYMBOL", "seed/binary/firmware.bin", 1024)],
           [K("LIBCRYPTO-SYMBOL", "seed/binary/firmware.bin", 2048)], "positive"),
        _c("binary.plain.no_crypto", "binary", "Unrelated binary",
           "Binary with no crypto symbols/strings; nothing expected.",
           "seed/binary/tool.bin",
           [], [K("LIBCRYPTO-SYMBOL", "seed/binary/tool.bin", 512)], "negative"),
        # -- dependency --------------------------------------------------
        _c("dependency.crypto.library", "dependency", "Known crypto dependency",
           "Manifest pins an outdated OpenSSL build.",
           "seed/dependency/requirements.txt",
           [K("OPENSSL-OLD", "seed/dependency/requirements.txt", 2)],
           [K("OPENSSL-OLD", "seed/dependency/requirements.txt", 5)], "positive"),
        _c("dependency.plain.unrelated", "dependency", "Unrelated dependency",
           "Manifest with no crypto packages; nothing expected.",
           "seed/dependency/requirements-clean.txt",
           [], [K("OPENSSL-OLD", "seed/dependency/requirements-clean.txt", 1)],
           "negative"),
        # -- container ---------------------------------------------------
        _c("container.crypto.package", "container", "Crypto package in image",
           "Image manifest installs an outdated crypto package.",
           "seed/container/image-manifest.json",
           [K("CRYPTO-PACKAGE", "seed/container/image-manifest.json", 7)],
           [K("CRYPTO-PACKAGE", "seed/container/image-manifest.json", 9)], "positive"),
        _c("container.plain.base_image", "container", "Unrelated image layer",
           "Image manifest with no crypto packages; nothing expected.",
           "seed/container/image-clean-manifest.json",
           [], [K("CRYPTO-PACKAGE", "seed/container/image-clean-manifest.json", 3)],
           "negative"),
        # -- config ------------------------------------------------------
        _c("config.tls.weak", "config", "Weak TLS configuration",
           "Config allows deprecated TLS 1.0.",
           "seed/config/tls.conf",
           [K("TLS-1.0", "seed/config/tls.conf", 12)],
           [K("TLS-1.0", "seed/config/tls.conf", 20)], "positive"),
        _c("config.plain.unrelated", "config", "Unrelated configuration",
           "Config with no TLS/crypto settings; nothing expected.",
           "seed/config/app.conf",
           [], [K("TLS-1.0", "seed/config/app.conf", 2)], "negative"),
        # -- certificate_key ---------------------------------------------
        _c("certificate_key.expiry", "certificate_key", "Expiring certificate",
           "Certificate metadata shows expiry inside the warning window.",
           "seed/certificate_key/app.pem",
           [K("ACM-EXPIRY", "seed/certificate_key/app.pem", 1)],
           [K("ACM-EXPIRY", "seed/certificate_key/app.pem", 2)], "positive"),
        _c("certificate_key.plain.non_crypto_file", "certificate_key",
           "Non-crypto file alongside certificates",
           "Plain text file with no key material; nothing expected.",
           "seed/certificate_key/readme.txt",
           [], [K("ACM-EXPIRY", "seed/certificate_key/readme.txt", 1)], "negative"),
        # -- runtime_tls -------------------------------------------------
        _c("runtime_tls.weak_cipher", "runtime_tls", "Weak cipher observed",
           "Runtime observation reports a weak negotiated cipher.",
           "seed/runtime_tls/payments.json",
           [K("TLS-WEAK-CIPHER", "seed/runtime_tls/payments.json", 2)],
           [K("TLS-WEAK-CIPHER", "seed/runtime_tls/payments.json", 5)], "positive"),
        _c("runtime_tls.plain.modern", "runtime_tls", "Modern TLS service",
           "Runtime observation reports only modern TLS; nothing expected.",
           "seed/runtime_tls/status.json",
           [], [K("TLS-WEAK-CIPHER", "seed/runtime_tls/status.json", 1)],
           "negative"),
        # -- cloud_kms ---------------------------------------------------
        _c("cloud_kms.no_rotation", "cloud_kms", "KMS key without rotation",
           "KMS configuration reference has rotation disabled.",
           "seed/cloud_kms/keys.json",
           [K("KMS-NO-ROTATION", "seed/cloud_kms/keys.json", 3)],
           [K("KMS-NO-ROTATION", "seed/cloud_kms/keys.json", 6)], "positive"),
        _c("cloud_kms.plain.unrelated", "cloud_kms", "Unrelated cloud config",
           "Cloud configuration with no KMS references; nothing expected.",
           "seed/cloud_kms/network.json",
           [], [K("KMS-NO-ROTATION", "seed/cloud_kms/network.json", 1)],
           "negative"),
        # -- fusion ------------------------------------------------------
        _c("fusion.multi_source.same_asset", "fusion",
           "Same asset from multiple sources",
           "One weak RSA asset observed by two hypothetical sources.",
           "seed/fusion/asset-rsa.json",
           [K("RSA-1024", "seed/fusion/asset-rsa.json", 1),
            K("RSA-1024", "seed/fusion/asset-rsa.json", 2)],
           [K("RSA-1024", "seed/fusion/asset-rsa.json", 3)], "positive"),
        _c("fusion.multi_source.unrelated", "fusion",
           "Unrelated multi-source observations",
           "Observations from several sources with no shared asset.",
           "seed/fusion/noise.json",
           [], [K("RSA-1024", "seed/fusion/noise.json", 1)], "negative"),
        # -- risk --------------------------------------------------------
        _c("risk.high.synthetic", "risk", "High-risk synthetic input",
           "Deterministic critical+high finding pair for risk checks.",
           "seed/risk/high.json",
           [K("AES-ECB", "seed/risk/high.json", 1),
            K("RSA-1024", "seed/risk/high.json", 2)],
           [K("MD5-USAGE", "seed/risk/high.json", 3)], "positive"),
        _c("risk.low.synthetic", "risk", "Lower-risk synthetic input",
           "Deterministic single low finding for risk checks.",
           "seed/risk/low.json",
           [K("TLS-1.0", "seed/risk/low.json", 1)],
           [K("AES-ECB", "seed/risk/low.json", 2)], "positive"),
        # -- pqc_recommendation ------------------------------------------
        _c("pqc_recommendation.rsa_weak", "pqc_recommendation",
           "PQC-relevant weak RSA input",
           "Deterministic weak-RSA finding for PQC-relevance checks.",
           "seed/pqc/rsa.json",
           [K("RSA-1024", "seed/pqc/rsa.json", 4)],
           [K("AES-ECB", "seed/pqc/rsa.json", 7)], "positive"),
        _c("pqc_recommendation.plain.non_pqc", "pqc_recommendation",
           "Non-PQC-relevant input",
           "Modern configuration with no PQC-relevant findings expected.",
           "seed/pqc/modern.json",
           [], [K("RSA-1024", "seed/pqc/modern.json", 1)], "negative"),
    )


_CASES: tuple[SuiteCase, ...] = _build_seed_cases()
_BY_ID: dict[str, SuiteCase] = {c.case_id: c for c in _CASES}


# --- registry API (pure; no I/O, no DB, no network) -------------------------------


def list_groups() -> list[str]:
    """Stable group identifiers in canonical order."""
    return list(GROUPS)


def group_description(group: str) -> str:
    """One-line meaning of a group. Raises KeyError for unknown groups."""
    return GROUP_DESCRIPTIONS[group]


def list_cases(group: str | None = None) -> list[SuiteCase]:
    """Registered cases in stable registry order, optionally filtered.

    Raises ValueError for an unknown group (fail fast, deterministic).
    """
    if group is None:
        return list(_CASES)
    if group not in GROUPS:
        raise ValueError(
            f"unknown group {group!r}; expected one of {list(GROUPS)}")
    return [c for c in _CASES if c.group == group]


def get_case(case_id: str) -> SuiteCase | None:
    """One case by stable id, or None when unknown. Pure."""
    return _BY_ID.get(case_id)


def case_to_dict(case: SuiteCase) -> dict:
    """JSON-serializable view of a registered case (definition only)."""
    gt = case.ground_truth
    return {
        "case_id": case.case_id,
        "group": case.group,
        "title": case.title,
        "description": case.description,
        "input_ref": case.input_ref,
        "expected": sorted(gt.expected),
        "universe": sorted(gt.universe) if gt.universe is not None else None,
        "tags": list(case.tags),
        "synthetic": gt.synthetic,
        "note": case.note,
    }


def get_default_suite() -> dict:
    """The full seed suite envelope. Deterministic across calls."""
    return {
        "suite_id": SUITE_ID,
        "version": SUITE_VERSION,
        "case_count": len(_CASES),
        "groups": list(GROUPS),
        "cases": [case_to_dict(c) for c in _CASES],
        "synthetic": all(c.ground_truth.synthetic for c in _CASES),
        "note": ("Seed benchmark case registry (synthetic fixtures). "
                 "Case definitions only: no detector has evaluated "
                 "these cases and no accuracy is claimed."),
    }


def with_predictions(case: SuiteCase, predicted: Iterable[str]) -> BenchmarkCase:
    """Attach a prediction set for evaluation (Task 16 model). Pure.

    This is the ONLY bridge from definition to evaluation: ground
    truth stays independent; predictions arrive here from a future
    detector/baseline and are paired via Task 16 machinery.
    """
    return BenchmarkCase(
        case_id=case.case_id,
        group=case.group,
        ground_truth=case.ground_truth,
        predicted=frozenset(predicted),
    )
