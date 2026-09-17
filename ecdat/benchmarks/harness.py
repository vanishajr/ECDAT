"""Reproducible Phase 13 benchmark harness.

Runs small, deterministic source and binary fixtures through the production
orchestrator and writes machine-readable JSON/CSV metrics.  It intentionally
does not claim OpenSSL results unless ``--openssl`` points at a checkout.
"""

from __future__ import annotations

import argparse
import csv
import json
import tempfile
import time
from pathlib import Path


SOURCE = """\
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
key = b'0' * 32
iv = b'1' * 12
cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
encryptor = cipher.encryptor()
"""


def _fixture(root: Path) -> None:
    (root / "app.py").write_text(SOURCE, encoding="utf-8")
    (root / "requirements.txt").write_text("cryptography==42.0.0\n", encoding="utf-8")
    (root / "nginx.conf").write_text(
        "ssl_protocols TLSv1.2 TLSv1.3;\nssl_certificate cert.pem;\n",
        encoding="utf-8",
    )


def _run(target: Path, profile: str) -> dict:
    from ecdat.core.orchestrator import (
        ScanOrchestrator,
        ScanPermissions,
        ScanRequest,
    )

    request = ScanRequest(
        target=str(target),
        scanners=["source", "dependency", "config", "certificate", "binary"],
        permissions=ScanPermissions(),
        profile=profile,
        caller="benchmark",
        display_name="phase13-fixture",
    )
    started = time.perf_counter()
    result = ScanOrchestrator().scan(request)
    elapsed = time.perf_counter() - started
    cir, canonical = result.as_tuple()
    operations = cir.get("operations", []) or []
    expected = {"AES", "TLS"}
    assets = {str(a.get("asset_id")): a for a in cir.get("assets", []) or []}
    observed = {
        str(
            op.get("algorithm")
            or op.get("canonical")
            or assets.get(str(op.get("asset_id")), {}).get("canonical")
            or ""
        ).upper()
        for op in operations
    }
    observed = {name for name in observed if name}
    tp = len(expected & observed)
    return {
        "fixture": "phase13-fixture",
        "profile": profile,
        "elapsed_sec": round(elapsed, 6),
        "files_scanned": canonical.get("stats", {}).get("files_scanned", 0),
        "findings": len(canonical.get("findings", [])),
        "assets": len(cir.get("assets", []) or []),
        "operations": len(operations),
        "expected_algorithms": sorted(expected),
        "observed_algorithms": sorted(observed),
        "precision": round(tp / len(observed), 6) if observed else 0.0,
        "recall": round(tp / len(expected), 6),
        "cache_hit": bool(result.diagnostics.get("cache_hit", False)),
        "escalated": (result.diagnostics.get("escalation", {}) or {}).get("escalated", 0),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run ECDAT Phase 13 benchmark fixtures")
    parser.add_argument("--output", type=Path, default=Path("benchmark-results.json"))
    parser.add_argument("--openssl", type=Path, help="optional OpenSSL checkout (recorded only)")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="ecdat-benchmark-") as name:
        rows = [_run(Path(name), profile) for profile in ("quick", "standard", "deep")]
    payload = {
        "schema_version": 1,
        "harness": "ecdat.benchmarks.harness",
        "rows": rows,
        "openssl_checkout": str(args.openssl) if args.openssl else None,
        "openssl_executed": False,
        "notes": ["OpenSSL is not executed unless a dedicated acceptance adapter is supplied."],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    csv_path = args.output.with_suffix(".csv")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {args.output} and {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
