"""Phase 12 tests: scanner-family semantic alignment (additive).

Exercises ecdat.scanners.semantics pure helpers only; no scanner
behaviour is changed.
"""

from __future__ import annotations

from ecdat.scanners.semantics import (
    binary_escalation_policy,
    cert_asset_vs_operation,
    config_state_classify,
    dependency_capability_only,
)


def test_dependency_presence_is_capability_not_operation():
    assert dependency_capability_only({"scanner": "dependency"}) is True
    assert dependency_capability_only({"dependency_only": True}) is True
    assert dependency_capability_only(
        {"scanner": "syft", "library": "openssl",
         "operation_type": None}) is True
    # Demonstrated use with an operation escapes capability-only.
    assert dependency_capability_only(
        {"scanner": "source", "operation_type": "encrypt",
         "usage_state": "Confirmed"}) is False


def test_dependency_unconfirmed_use_stays_capability():
    assert dependency_capability_only(
        {"scanner": "source", "operation_type": None,
         "usage_state": "Possible"}) is True
    assert dependency_capability_only({}) is True  # empty -> safe default


def test_binary_escalation_cheap_first():
    quiet = binary_escalation_policy({})
    assert quiet["escalate"] is False
    assert quiet["next_stages"] == []
    weak = binary_escalation_policy(
        {"weak_hit": True, "confidence": 0.4, "surface": "binary"})
    assert weak["escalate"] is True
    assert set(weak["next_stages"]) == {
        "capa-full", "floss", "ghidra-optional"}
    low_conf = binary_escalation_policy(
        {"has_hit": True, "confidence": 0.5})
    assert low_conf["escalate"] is True
    confident = binary_escalation_policy(
        {"has_hit": True, "confidence": 0.95, "surface": "source"})
    assert confident["escalate"] is False
    packed = binary_escalation_policy({"packed": True})
    assert packed["escalate"] is True
    assert binary_escalation_policy(None)["escalate"] is False


def test_cert_material_is_asset_not_operation():
    assert cert_asset_vs_operation(
        {"scanner": "certificate", "canonical": "RSA-2048"}) == "asset"
    assert cert_asset_vs_operation(
        {"scanner": "pem", "operation_type": None}) == "asset"
    # Demonstrated TLS use with confirmed state reads as operation.
    assert cert_asset_vs_operation(
        {"scanner": "certificate", "operation_type": "handshake",
         "title": "TLS handshake with RSA cert",
         "usage_state": "Confirmed"}) == "operation"


def test_config_state_classification():
    assert config_state_classify(
        {"title": "MD5 mentioned in example comment"}) == "mentioned"
    assert config_state_classify(
        {"title": "cipher_suites offers AES and ChaCha20"}) == "supported"
    assert config_state_classify(
        {"title": "TLS enforced with AES-256-GCM required"}) == "configured"
    assert config_state_classify(
        {"title": "default cipher is AES enabled by default"}) == (
        "enabled-default")
    assert config_state_classify(
        {"metadata": {"config_state": "configured"}}) == "configured"
    assert config_state_classify({}) == "mentioned"
