"""ECDAT core package (Person 3 platform layer).

Lazy re-exports (PEP 562) so `import ecdat.core.client` never pulls
pydantic or scanner dependencies: the mock/demo path stays
stdlib-only (+jsonschema). Real-mode modules are imported on first
attribute access only.
"""

from __future__ import annotations

_LAZY = {
    # cir_models (pydantic; P2-vendored CIR substrate)
    "CIRDocument": "ecdat.core.cir_models",
    "CryptoAsset": "ecdat.core.cir_models",
    "CryptoOperation": "ecdat.core.cir_models",
    "EvidenceSignal": "ecdat.core.cir_models",
    "Graph": "ecdat.core.cir_models",
    "GraphEdge": "ecdat.core.cir_models",
    "GraphNode": "ecdat.core.cir_models",
    "Implementation": "ecdat.core.cir_models",
    "Location": "ecdat.core.cir_models",
    "Context": "ecdat.core.cir_models",
    "RiskInputs": "ecdat.core.cir_models",
    "Stats": "ecdat.core.cir_models",
    "UsageState": "ecdat.core.cir_models",
    "OperationType": "ecdat.core.cir_models",
    "Exposure": "ecdat.core.cir_models",
    "GraphNodeKind": "ecdat.core.cir_models",
    "GraphRelationship": "ecdat.core.cir_models",
    "new_asset_id": "ecdat.core.cir_models",
    "new_operation_id": "ecdat.core.cir_models",
    "load_cir_json": "ecdat.core.cir_models",
    "validate_cir_json": "ecdat.core.cir_models",
    # signature_registry (P2-vendored scanner registry)
    "load_registry": "ecdat.core.signature_registry",
    "get_registry_version": "ecdat.core.signature_registry",
    "normalize_algorithm": "ecdat.core.signature_registry",
    "get_algorithm_info": "ecdat.core.signature_registry",
    "is_library_only": "ecdat.core.signature_registry",
    "get_category": "ecdat.core.signature_registry",
    "get_key_sizes": "ecdat.core.signature_registry",
    "get_curves": "ecdat.core.signature_registry",
    "get_mode": "ecdat.core.signature_registry",
    "infer_usage_state": "ecdat.core.signature_registry",
    "infer_operation_type": "ecdat.core.signature_registry",
    # cir_validate (P1 raising validator)
    "validate_cir": "ecdat.core.cir_validate",
}

__all__ = sorted(_LAZY)


def __getattr__(name: str):
    if name in _LAZY:
        import importlib

        module = importlib.import_module(_LAZY[name])
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
