"""Registry loaders must degrade (not crash) when JSON data is missing.

Installed deployments once shipped without package data (fixed via
MANIFEST.in): discovery must still run with reduced canonicalization
instead of failing the whole scan with FileNotFoundError.
"""

import ecdat.core.registry as p1
import ecdat.core.signature_registry as p2


def test_p2_registry_missing_falls_back(tmp_path, monkeypatch):
    monkeypatch.setattr(p2, "_REGISTRY_PATH", tmp_path / "nope.json")
    monkeypatch.setattr(p2, "_REGISTRY", None)
    assert p2.load_registry() == {}
    assert p2.normalize_algorithm("AES-256-GCM") == ("AES-256-GCM", "AES-256-GCM")
    assert p2.get_registry_version() == "2026.09.11"
    assert p2.get_algorithm_info("AES-256-GCM") is None


def test_p1_registry_missing_falls_back(tmp_path, monkeypatch):
    monkeypatch.setattr(p1, "_REGISTRY_PATH", tmp_path / "nope.json")
    p1.load_registry.cache_clear()
    try:
        assert p1.load_registry() == {}
        assert p1.canonicalize("aes-256-gcm") == "AES-256-GCM"
        assert p1.is_weak_asset("AES-256-GCM") is False
        assert p1.pqc_targets_for("RSA") == []
        assert p1.lookup_oid("1.2.3") is None
    finally:
        p1.load_registry.cache_clear()
