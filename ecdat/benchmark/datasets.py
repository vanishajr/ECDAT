"""Deterministic seeded benchmark datasets (Person 3 platform layer).

Workloads for engineering/performance measurement, built ONLY from
canonical-v1-valid finding structures (same rule/severity vocabulary
as the existing fixtures). No unsupported fields are invented; every
doc passes `validate()` at build time.

These datasets carry NO ground-truth labels: they measure pipeline
cost (validate/store/export/report), never detection accuracy. Future
accuracy datasets must add explicit ground-truth labels per finding
(see `metrics.accuracy_status`).
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from ecdat.core.validate import validate

# Finding vocabulary mirrors the existing canonical fixtures so the
# mock pipeline exercises realistic rule/severity mixes.
FINDING_TEMPLATES: tuple[tuple[str, str, str, str], ...] = (
    ("RSA-1024", "Weak RSA key size (1024-bit)", "high", "rsa.generate_private_key(key_size=1024)"),
    ("MD5-USAGE", "Weak hash MD5 in use", "medium", "hashlib.md5(data).hexdigest()"),
    ("AES-ECB", "AES in ECB mode leaks structure", "critical", "AES.new(key, AES.MODE_ECB)"),
    ("TLS-1.0", "Deprecated TLS version allowed", "low", "ssl.PROTOCOL_TLSv1"),
    ("KMS-NO-ROTATION", "KMS key without rotation", "medium", "EnableKeyRotation: false"),
    ("ACM-EXPIRY", "ACM certificate near expiry", "high", "NotAfter: 2026-02-01"),
    ("ELB-TLS-OLD", "ELB listener on old TLS policy", "low", "Policy: ELBSecurityPolicy-2016-08"),
    ("SHA1-USAGE", "Weak hash SHA-1 in use", "medium", "hashlib.sha1(data).hexdigest()"),
    ("DES-USAGE", "Weak cipher DES in use", "high", "DES.new(key, DES.MODE_CBC, iv)"),
    ("INFO-CIPHER", "Cipher inventory note", "info", "cipher_suite: TLS_AES_128_GCM_SHA256"),
)

# name -> (doc count, findings per doc, seed). Kept small so the suite
# stays fast; scale comes from finding counts, not fixtures on disk.
DATASET_SPECS: dict[str, tuple[int, int, int]] = {
    "small": (2, 4, 11),
    "medium": (5, 20, 22),
    "large": (10, 100, 33),
}

_BASE_START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def list_datasets() -> list[str]:
    """Available dataset names, sorted."""
    return sorted(DATASET_SPECS)


def _finding(rng: random.Random, dataset: str, doc_idx: int, i: int) -> dict:
    rule_id, title, severity, snippet = FINDING_TEMPLATES[
        rng.randrange(len(FINDING_TEMPLATES))
    ]
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "file": f"samples/bench/{dataset}/mod{rng.randrange(8)}.py",
        "line": rng.randrange(1, 500),
        "snippet": f"{snippet}  # bench {dataset}/{doc_idx}/{i}",
        "confidence": round(rng.uniform(0.7, 0.99), 2),
    }


def build_dataset(name: str) -> dict:
    """Build a deterministic dataset dict: {name, seed, docs}.

    Raises KeyError for unknown names. Every doc is validated before
    return, so construction fails fast on any schema drift.
    """
    n_docs, per_doc, seed = DATASET_SPECS[name]
    rng = random.Random(seed)
    docs = []
    for d in range(n_docs):
        started = _BASE_START + timedelta(seconds=d * 10)
        findings = [_finding(rng, name, d, i) for i in range(per_doc)]
        doc = {
            "schema_version": "1.0",
            "scan_id": f"bench-{name}-{d:04d}",
            "target": f"bench/{name}/case-{d}",
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "finished_at": (started + timedelta(seconds=1)).isoformat().replace(
                "+00:00", "Z"
            ),
            "tool_versions": {"ecdat": "0.1.0"},
            "findings": findings,
            "stats": {
                "files_scanned": len({f["file"] for f in findings}),
                "findings_count": len(findings),
            },
        }
        docs.append(validate(doc))
    return {"name": name, "seed": seed, "docs": docs}
