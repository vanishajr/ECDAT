"""Phase 6/9/10/11: scope, misuse, risk dimensions, recommendation classes."""

from ecdat.core import misuse as misuse_mod
from ecdat.core import recommend as rec_mod
from ecdat.core import risk as risk_mod
from ecdat.core.scope import classify_build_state, classify_scope


def _op(canonical="RSA", **kw):
    op = {
        "operation_id": "op-test-001",
        "operation_type": kw.pop("operation_type", "Encrypt"),
        "canonical_name": canonical,
        "confidence": 0.9,
        "usage_state": "Confirmed",
        "context": {},
        "location": {},
        "implementation": {},
        "risk_inputs": {"usage_state": "Confirmed"},
    }
    op.update(kw)
    return op


# --- Phase 6: scope -------------------------------------------------------


def test_scope_application_default():
    assert classify_scope("src/app/service.py", "python") == "APPLICATION"


def test_scope_test_paths():
    assert classify_scope("tests/test_crypto.py", "python") == "TEST"
    assert classify_scope("src/test_vector.py", "python") == "TEST"


def test_scope_fixture_beats_test_dir():
    # Fixture evidence wins even under tests/.
    assert classify_scope("tests/fixtures/key.pem") == "CERTIFICATE_ASSET" or \
        classify_scope("tests/fixtures/key.pem") in ("FIXTURE", "CERTIFICATE_ASSET")
    assert classify_scope("tests/fixtures/data.json") == "FIXTURE"


def test_scope_other_roles():
    assert classify_scope("bench/hash_bench.py", "python") == "BENCHMARK"
    assert classify_scope("examples/tls_client.py", "python") == "EXAMPLE"
    assert classify_scope("demos/pqc.py", "python") == "DEMO"
    assert classify_scope("docs/design.md") == "DOCUMENTATION"
    assert classify_scope("src/gen/message_pb2.py") == "GENERATED"
    assert classify_scope("vendor/openssl/ssl.py") == "VENDOR"
    assert classify_scope("build/Makefile", None) in ("BUILD", "CONFIG", "UNKNOWN")
    assert classify_scope("CMakeLists.txt") == "BUILD"
    assert classify_scope("config/app.yaml") == "CONFIG"
    assert classify_scope("app-1.0.0-py3-none-any.whl", None) in ("BINARY", "UNKNOWN")
    assert classify_scope("prog.exe") == "BINARY"
    assert classify_scope("certs/server.pem") == "CERTIFICATE_ASSET"
    assert classify_scope(None, None) == "UNKNOWN"


def test_scope_stronger_evidence_overrides_path():
    # Syntax facts beat a test-looking path.
    assert classify_scope("tests/test_x.py", "python",
                          None, None, {"scope": "APPLICATION"}) == "APPLICATION"
    assert classify_scope("src/app.py", "python",
                          None, {"is_test": True}, None) == "TEST"
    assert classify_scope("src/app.py", "python",
                          {"scope": "FIXTURE"}, None, None) == "FIXTURE"


def test_build_state_defaults():
    assert classify_build_state("src/app.py") == "DEFAULT_ENABLED"
    assert classify_build_state("tests/t.py") == "SUPPORTED"
    assert classify_build_state(None, None, None, None) == "UNKNOWN"


def test_build_state_evidence():
    assert classify_build_state("src/a.c", {"enabled": False}) == "DISABLED"
    assert classify_build_state("src/a.c", {"excluded": True}) == "DISABLED"
    assert classify_build_state("src/a.c", {"condition": "USE_PQC"}) == "CONDITIONAL"
    assert classify_build_state("src/a.c", None, None,
                                {"ifdef": "HAVE_OPENSSL"}) == "CONDITIONAL"
    assert classify_build_state("src/a.c", None, {"optional": True}) == "SUPPORTED"
    assert classify_build_state("src/a.c", {"build_state": "CONDITIONAL"}) == "CONDITIONAL"


# --- Phase 9: misuse ------------------------------------------------------


def test_misuse_ecb_and_static_key():
    findings = misuse_mod.check_operation(_op("AES", mode="ECB"))
    assert any(f["rule_id"] == "ECB_MODE" for f in findings)
    findings = misuse_mod.check_operation(
        _op("AES", parameters={"key_static": True}))
    assert any(f["rule_id"] == "STATIC_KEY" for f in findings)


def test_misuse_static_iv_weak_rng_cert():
    assert any(f["rule_id"] == "STATIC_IV_NONCE"
               for f in misuse_mod.check_operation(
                   _op("AES", mode="GCM", parameters={"nonce_static": True})))
    assert any(f["rule_id"] == "WEAK_RNG"
               for f in misuse_mod.check_operation(
                   _op("AES", parameters={"rng": "rand()"})))
    assert any(f["rule_id"] == "CERT_VALIDATION_DISABLED"
               for f in misuse_mod.check_operation(
                   _op("X.509", parameters={"verify": False})))


def test_misuse_keysize_protocol_deprecated_kdf():
    assert any(f["rule_id"] == "INSUFFICIENT_KEY_SIZE"
               for f in misuse_mod.check_operation(_op("RSA", key_size=1024)))
    assert any(f["rule_id"] == "INSECURE_PROTOCOL"
               for f in misuse_mod.check_operation(
                   _op("TLS", protocol_version="TLS 1.0")))
    assert any(f["rule_id"] == "DEPRECATED_ALGO"
               for f in misuse_mod.check_operation(_op("MD5")))
    assert any(f["rule_id"] == "LOW_KDF_FACTOR"
               for f in misuse_mod.check_operation(
                   _op("PBKDF2", parameters={"iterations": 1000})))


def test_misuse_missing_auth_password_sig():
    assert any(f["rule_id"] == "MISSING_AUTH"
               for f in misuse_mod.check_operation(
                   _op("AES", mode="CBC", operation_type="Encrypt")))
    assert any(f["rule_id"] == "PASSWORD_AS_KEY"
               for f in misuse_mod.check_operation(
                   _op("AES", parameters={"key_source": "password"})))
    assert any(f["rule_id"] == "UNSAFE_SIG_HASH"
               for f in misuse_mod.check_operation(
                   _op("RSA", operation_type="Sign",
                       parameters={"hash": "SHA-1"})))
    assert any(f["rule_id"] == "PREDICTABLE_KEY"
               for f in misuse_mod.check_operation(
                   _op("AES", parameters={"key_source": "time"})))


def test_misuse_clean_pqc_no_findings():
    assert misuse_mod.check_operation(_op("ML-KEM-768")) == []
    assert set(misuse_mod.MISUSE_RULES) >= {
        "STATIC_KEY", "PREDICTABLE_KEY", "STATIC_IV_NONCE", "ECB_MODE",
        "WEAK_RNG", "CERT_VALIDATION_DISABLED", "INSUFFICIENT_KEY_SIZE",
        "INSECURE_PROTOCOL", "DEPRECATED_ALGO", "LOW_KDF_FACTOR",
        "MISSING_AUTH", "PASSWORD_AS_KEY", "UNSAFE_SIG_HASH",
    }
    for rule in misuse_mod.MISUSE_RULES.values():
        assert {"id", "applies_to", "requires", "condition",
                "severity_basis", "references"} <= set(rule)


# --- Phase 10: risk dimensions --------------------------------------------


def test_classical_posture_levels():
    assert risk_mod.assess_classical_posture(_op("DES"))["level"] == "broken"
    assert risk_mod.assess_classical_posture(_op("SHA-1"))["level"] == "deprecated"
    assert risk_mod.assess_classical_posture(_op("AES"))["level"] == "secure"
    assert risk_mod.assess_classical_posture(_op("FROBNICATE-1"))["level"] == "unknown"


def test_misuse_severity_takes_precedence():
    strong = risk_mod.assess_misuse_severity(_op("AES", mode="GCM"))
    assert strong["level"] == "none"
    bad = risk_mod.assess_misuse_severity(_op("AES", mode="ECB"))
    assert bad["level"] == "high" and bad["findings"]


def test_protocol_posture():
    assert risk_mod.assess_protocol_posture(
        _op("TLS", protocol_version="TLS 1.3"))["level"] == "secure"
    assert risk_mod.assess_protocol_posture(
        _op("TLS", protocol_version="TLS 1.0"))["level"] == "broken"
    assert risk_mod.assess_protocol_posture(_op("AES"))["level"] == "not-applicable"


def test_quantum_exposure_and_v2_dimensions():
    q = risk_mod.assess_quantum_exposure(_op("RSA"))
    assert q["level"] == "critical" and q["q"] == 1.0
    rec = risk_mod.score_operation_v2(_op("RSA"))
    assert set(rec["dimensions"]) == {
        "classical_posture", "misuse_severity", "protocol_posture",
        "quantum_exposure", "deployment_impact", "migration_urgency"}
    assert 0.0 <= rec["score"] <= 1.0
    assert rec["class"] in ("Critical", "High", "Medium", "Low", "Informational")
    # v1 untouched: same signature + shape.
    v1 = risk_mod.score_operation(_op("RSA"))
    assert set(v1) >= {"operation_id", "score", "class", "explanation",
                       "assumptions", "provenance"}


def test_v2_non_deployment_scope_reduces_deployment():
    prod = risk_mod.score_operation_v2(_op("AES"))
    test_op = _op("AES")
    test_op["location"] = {"file": "tests/test_x.py"}
    test_scored = risk_mod.score_operation_v2(test_op)
    assert (test_scored["dimensions"]["deployment_impact"]["score"]
            <= prod["dimensions"]["deployment_impact"]["score"])


# --- Phase 11: recommendation classes -------------------------------------


def test_recommend_fix_misuse_keeps_strong_primitive():
    op = _op("AES", mode="GCM", parameters={"nonce_static": True})
    rec = rec_mod.recommend_for_operation_v2(op)
    assert rec["class"] == "fix-misuse"
    assert "STATIC_IV_NONCE" in rec["misuse"]


def test_recommend_replace_primitive():
    rec = rec_mod.recommend_for_operation_v2(_op("DES"))
    assert rec["class"] == "replace-primitive"


def test_recommend_protocol_upgrade():
    rec = rec_mod.recommend_for_operation_v2(
        _op("TLS", protocol_version="TLS 1.0"))
    assert rec["class"] == "protocol-upgrade"


def test_recommend_pqc_operation_correct():
    kem = rec_mod.recommend_for_operation_v2(
        _op("RSA", operation_type="Encrypt"))
    assert kem["class"] == "pqc-transition"
    assert "ML-KEM" in kem["target_algorithms"][0]
    sig = rec_mod.recommend_for_operation_v2(
        _op("RSA", operation_type="Sign"))
    assert sig["class"] == "pqc-transition"
    assert "ML-DSA" in sig["target_algorithms"][0]
    assert "ML-KEM" not in sig["target_algorithms"][0]
    # Helper is operation-correct too.
    assert "ML-DSA" in rec_mod.pqc_target_for_operation(
        {"operation_type": "Sign"}, "ECDSA")[0]
    assert "ML-KEM" in rec_mod.pqc_target_for_operation(
        {"operation_type": "KeyExchange"}, "ECDH")[0]


def test_recommend_monitor_no_action():
    assert rec_mod.recommend_for_operation_v2(_op("AES", mode="GCM"))["class"] in (
        "monitor", "no-action")
    assert rec_mod.recommend_for_operation_v2(_op("ML-KEM-768"))["class"] == "no-action"
    # v1 still works.
    v1 = rec_mod.recommend_for_operation(_op("RSA"), None)
    assert v1["rule_key"] in rec_mod.RECOMMENDATIONS
