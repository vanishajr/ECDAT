"""Phase 4 (semantic operation reconstruction) + Phase 7 (correlation/dedup).

Additive only: exercises the new evidence/semantic modules and the
opt-in semantic path in operations.py without touching existing APIs.
"""

from __future__ import annotations

from ecdat.core.evidence import (
    EvidenceClass,
    Relationship,
    SemanticState,
    classify_evidence,
    semantic_state_for,
)
from ecdat.core.operations import (
    build_operations,
    build_semantic_operations,
)
from ecdat.core.semantic_ops import (
    build_semantic_operation,
    correlate_operations,
    dedup_metrics,
    semantic_identity_key,
)


def _api_hit(function="encrypt_data", tool="source:api-call",
             confidence=0.92, **overrides):
    hit = {
        "operation_type": "Encrypt",
        "canonical_name": "AES-256-GCM",
        "key_size": 256,
        "mode": "GCM",
        "file": "app/crypto.py",
        "function": function,
        "evidence": [{"detector": "source", "signal_type": "call",
                      "confidence": confidence,
                      "tool": tool}],
        "tool": tool,
        "confidence": confidence,
    }
    hit.update(overrides)
    return hit


# --- Phase 4: isolated API hits -> one CryptoOperation ----------------------

def test_isolated_api_hits_collapse_to_one_semantic_op():
    hits = [_api_hit(function=f"caller_{i}") for i in range(5)]
    op = build_semantic_operation(hits)
    assert op["algorithm"] == "AES-256-GCM"
    assert op["operation"] == "Encrypt"
    assert op["mode"] == "GCM"
    assert len(op["evidence"]) == 5  # all provenance preserved
    assert len(op["locations"]) == 5
    assert op["confidence"] >= 0.9


def test_semantic_op_has_required_fields():
    op = build_semantic_operation([_api_hit()])
    for field in ("primitive", "algorithm", "variant", "mode", "operation",
                  "key", "nonce_iv", "random_source", "provider",
                  "call_sequence", "locations", "scope", "evidence",
                  "confidence"):
        assert field in op, f"missing field {field}"
    assert op["primitive"] == "symmetric-encryption"
    assert op["key"] == {"size": 256, "curve": None}
    assert op["call_sequence"] == ["encrypt_data"]


def test_unknown_stays_unresolved_never_guessed():
    op = build_semantic_operation([{"operation_type": "Hash"}])
    assert op["algorithm"] is None
    assert op["primitive"] is None
    assert op["variant"] is None
    assert op["mode"] is None
    assert op["key"] is None
    assert op["nonce_iv"] is None
    assert op["random_source"] is None
    assert op["provider"] is None
    assert op["call_sequence"] == []
    assert op["scope"] == {"file": None, "service": None, "endpoint": None}


def test_unknown_tool_never_guessed_as_invocation():
    assert classify_evidence("some-brand-new-tool-xyz") is EvidenceClass.REFERENCE
    assert classify_evidence("") is EvidenceClass.REFERENCE
    assert classify_evidence(None) is EvidenceClass.REFERENCE
    op = build_semantic_operation([_api_hit(tool="mystery-tool")])
    assert op["evidence"][0]["class"] == EvidenceClass.REFERENCE.value


# --- Phase 4: evidence taxonomy ----------------------------------------------

def test_evidence_classes_cover_tool_families():
    assert classify_evidence("source:api-call") is EvidenceClass.INVOCATION
    assert classify_evidence("source:wrapper-call") is EvidenceClass.INVOCATION
    assert classify_evidence("runtime-tls-probe") is EvidenceClass.INVOCATION
    assert classify_evidence("binary-lief-imports") is EvidenceClass.BINARY_SIGNATURE
    assert classify_evidence("binary-signatures-yara") is EvidenceClass.BINARY_SIGNATURE
    assert classify_evidence("config:dockerfile") is EvidenceClass.CONFIGURATION
    assert classify_evidence("dependency:syft-pkg") is EvidenceClass.DEPENDENCY
    assert classify_evidence("container-syft-sbom") is EvidenceClass.DEPENDENCY
    assert classify_evidence("cloud-aws-kms") is EvidenceClass.REGISTRATION
    assert classify_evidence("certificate-x509-parse") is EvidenceClass.ASSET
    assert classify_evidence("secret-gitleaks") is EvidenceClass.ASSET


def test_evidence_class_enum_and_relationships_complete():
    assert {c.value for c in EvidenceClass} == {
        "reference", "declaration", "implementation", "registration",
        "configuration", "invocation", "asset", "dependency",
        "binary-signature"}
    assert {r.value for r in Relationship} == {
        "implements", "provides", "uses", "configures", "registers",
        "invokes", "contains", "depends_on", "derives", "protects"}


# --- Phase 4: semantic states -------------------------------------------------

def test_semantic_states_lifecycle():
    assert semantic_state_for("Confirmed", ["invocation"]) is SemanticState.INVOKED
    assert semantic_state_for("Confirmed", []) is SemanticState.CONFIRMED
    assert semantic_state_for("Probable", ["invocation"]) is SemanticState.PROBABLE
    assert (semantic_state_for("ProvidedOnly", ["invocation"])
            is SemanticState.SUPPORTED)  # dependency-only capped
    assert (semantic_state_for("FalsePositiveSuppressed", ["invocation"])
            is SemanticState.REFERENCED)
    assert semantic_state_for("Possible", ["reference"]) is SemanticState.REFERENCED
    assert (semantic_state_for("Possible", ["configuration"])
            is SemanticState.CONFIGURED)
    assert semantic_state_for("Possible", []) is SemanticState.REFERENCED


def test_build_operations_annotates_semantic_state_additively():
    ops = build_operations([_api_hit()])
    assert len(ops) == 1
    # Legacy keys untouched...
    assert ops[0]["usage_state"] == "Confirmed"
    assert "dedup_key" in ops[0] and "breakdown" in ops[0]
    # ...with additive Phase 4 annotations.
    assert "invocation" in ops[0]["evidence_classes"]
    assert ops[0]["semantic_state"] == SemanticState.INVOKED.value


# --- Phase 7: wrapper correlation / no duplicate explosion -------------------

def test_wrapper_does_not_explode_without_semantic_flag():
    hits = [_api_hit(function="encrypt_data", tool="source:api-call"),
            _api_hit(function="my_wrapper", tool="source:wrapper-call")]
    legacy = build_operations(hits)
    assert len(legacy) == 2  # legacy 9-tuple keeps function split
    assert len(build_operations(hits, use_semantic=True)) == 1


def test_semantic_correlation_preserves_all_evidence():
    op_a = build_semantic_operation([_api_hit(function="encrypt_data")])
    op_b = build_semantic_operation([_api_hit(function="my_wrapper",
                                              tool="source:wrapper-call",
                                              confidence=0.85)])
    merged = correlate_operations([op_a, op_b])
    assert len(merged) == 1
    assert len(merged[0]["evidence"]) == 2  # distinct signals both kept
    assert len(merged[0]["locations"]) == 2  # all locations preserved
    assert set(merged[0]["call_sequence"]) == {"encrypt_data", "my_wrapper"}
    assert merged[0]["confidence"] >= 0.9


def test_semantic_identity_keys_split_on_mode():
    gcm = build_semantic_operation([_api_hit(mode="GCM")])
    cbc = build_semantic_operation([_api_hit(mode="CBC")])
    assert semantic_identity_key(gcm) != semantic_identity_key(cbc)
    assert len(correlate_operations([gcm, cbc])) == 2
    # Same identity merges.
    twin = build_semantic_operation([_api_hit(mode="GCM")])
    assert semantic_identity_key(gcm) == semantic_identity_key(twin)
    assert len(correlate_operations([gcm, twin])) == 1


def test_semantic_identity_key_covers_required_dimensions():
    op = build_semantic_operation([_api_hit()])
    key = semantic_identity_key(op)
    assert len(key) == 11  # primitive,variant,mode,key,curve,protocol,
    # op_type,scope,build_state,lineage,provider
    assert key[1] == "AES-256-GCM"  # variant
    assert key[2] == "GCM"  # mode
    assert key[3] == "256"  # key_size


def test_dedup_metrics_raw_to_logical():
    metrics = dedup_metrics([_api_hit() for _ in range(10)], [{"id": "op-1"}])
    assert metrics["raw_hits"] == 10
    assert metrics["logical_ops"] == 1
    assert metrics["duplicates_removed"] == 9
    assert metrics["dedup_ratio"] == 0.9
    assert metrics["reduction_factor"] == 10.0
    assert dedup_metrics([], []) == {
        "raw_hits": 0, "logical_ops": 0, "duplicates_removed": 0,
        "dedup_ratio": 0.0, "reduction_factor": 0.0}
    assert dedup_metrics(4, 4)["dedup_ratio"] == 0.0


def test_build_semantic_operations_helper_end_to_end():
    hits = ([_api_hit(function=f"caller_{i}", confidence=0.9 - i * 0.01)
             for i in range(3)]
            + [_api_hit(mode="CBC", function="legacy")])
    semantic = build_semantic_operations(hits)
    assert len(semantic) == 2  # GCM callers merge, CBC stays distinct
    gcm = next(o for o in semantic if o["mode"] == "GCM")
    assert len(gcm["evidence"]) == 3
    assert len(gcm["locations"]) == 3


def test_legacy_signatures_still_work_positionally():
    # Backward compat: old call shapes keep working.
    assert build_operations(None) == []
    assert build_operations([]) == []
    single = build_operations([_api_hit()])
    assert single[0]["operation_type"] == "Encrypt"
