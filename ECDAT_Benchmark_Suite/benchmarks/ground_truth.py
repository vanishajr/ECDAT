from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml

from .metrics import match_operation, score_operations


def load_ground_truth(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "id" not in data:
        raise ValueError(f"Malformed ground truth: {path}")
    return data


def extract_operations(result: dict[str, Any]) -> list[dict[str, Any]]:
    # Canonical locations seen across ECDAT iterations. Keep this tolerant while
    # making the matcher strict.
    candidates = [
        result.get("operations"),
        result.get("canonical", {}).get("operations") if isinstance(result.get("canonical"), dict) else None,
        result.get("result", {}).get("operations") if isinstance(result.get("result"), dict) else None,
        result.get("cir", {}).get("operations") if isinstance(result.get("cir"), dict) else None,
    ]
    for value in candidates:
        if isinstance(value, list):
            operations = [x for x in value if isinstance(x, dict)]
            assets = {
                asset.get("asset_id"): asset
                for asset in result.get("assets", [])
                if isinstance(asset, dict) and asset.get("asset_id")
            }
            if not assets and isinstance(result.get("cir"), dict):
                assets = {
                    asset.get("asset_id"): asset
                    for asset in result["cir"].get("assets", [])
                    if isinstance(asset, dict) and asset.get("asset_id")
                }
            return [_benchmark_operation_shape(operation, assets) for operation in operations]
    return []


def _benchmark_operation_shape(
    operation: dict[str, Any], assets: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Flatten the current CIR operation/asset relation for oracle matching.

    CIR keeps algorithm, mode, key size, and usage on the referenced asset,
    while the operation carries only ``operation_type`` and ``asset_id``.
    This is an evaluation-boundary conversion, not a product-data mutation.
    """
    asset = assets.get(operation.get("asset_id"), {})
    merged = dict(asset)
    merged.update(operation)
    canonical = str(asset.get("canonical") or asset.get("original") or "")
    algorithm = next(
        (
            name
            for name in (
                "TLS1.3", "TLS1.2", "TLS1.0", "AES", "3DES", "DES",
                "SHA-256", "SHA-1", "MD5", "RC4", "PBKDF2", "Argon2",
                "X25519", "Ed25519", "ECDH", "RSA", "KMS",
            )
            if canonical.upper().startswith(name.upper())
        ),
        None,
    )
    if algorithm and not merged.get("algorithm"):
        merged["algorithm"] = algorithm
    if operation.get("operation_type") and not merged.get("operation"):
        merged["operation"] = str(operation["operation_type"]).lower()
    if asset.get("usage_state") and not merged.get("usage"):
        merged["usage"] = asset["usage_state"]
    return merged


def extract_risks(result: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("risks", "risk", "risk_items"):
        value = result.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    canonical = result.get("canonical")
    if isinstance(canonical, dict):
        for key in ("risks", "risk"):
            value = canonical.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
    cir = result.get("cir")
    if isinstance(cir, dict) and isinstance(cir.get("risks"), list):
        return [x for x in cir["risks"] if isinstance(x, dict)]
    return []


def extract_recommendations(result: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("recommendations", "migration_recommendations"):
        value = result.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    canonical = result.get("canonical")
    if isinstance(canonical, dict):
        value = canonical.get("recommendations")
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    cir = result.get("cir")
    if isinstance(cir, dict) and isinstance(cir.get("recommendations"), list):
        return [x for x in cir["recommendations"] if isinstance(x, dict)]
    return []


def evaluate_ground_truth(gt: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    expected = gt.get("expected", {})
    actual_ops = extract_operations(result)
    expected_ops = expected.get("operations", [])
    op_score = score_operations(expected_ops, actual_ops)

    forbidden_hits = []
    for forbidden in expected.get("forbidden_operations", []):
        for actual in actual_ops:
            if match_operation(forbidden, actual):
                forbidden_hits.append({"forbidden": forbidden, "actual": actual})

    recs = extract_recommendations(result)
    rec_expect = expected.get("recommendation", {})
    recommendation_ok = True
    if rec_expect.get("required") is True and not recs:
        recommendation_ok = False
    if rec_expect.get("required") is False and recs and rec_expect.get("strict_none", False):
        recommendation_ok = False

    return {
        "id": gt["id"],
        "operations": op_score,
        "forbidden_hits": forbidden_hits,
        "recommendation_ok": recommendation_ok,
        "pass": (
            op_score["fn"] == 0
            and not forbidden_hits
            and recommendation_ok
        ),
    }
