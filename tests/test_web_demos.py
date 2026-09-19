"""GUI demo inputs: registry lists bundled demos with preview code."""
from __future__ import annotations

import pytest

from ecdat.web.demos import demo_snippet, get_demo, list_demos


def test_demo_registry_lists_four():
    demos = list_demos()
    assert {d["id"] for d in demos} >= {
        "openssl_aes_gcm", "weak_hash_ecb", "custom_aes", "legacy_tls"}
    for demo in demos:
        assert demo["name"] and demo["files"] and demo["code"].strip()


def test_demo_snippets_contain_expected_markers():
    assert "EVP_aes_256_gcm" in demo_snippet("openssl_aes_gcm")
    assert "EVP_aes_128_ecb" in demo_snippet("weak_hash_ecb")
    assert "AES_ECB_encrypt" in demo_snippet("custom_aes")
    assert "TLSv1" in demo_snippet("legacy_tls")


def test_unknown_demo_rejected():
    with pytest.raises(ValueError):
        get_demo("../scanner")
    with pytest.raises(ValueError):
        get_demo("no-such-demo")
    assert demo_snippet("no-such-demo") == ""


def test_custom_aes_demo_scans_with_operations(tmp_path):
    import shutil

    from ecdat.core.orchestrator import ScanRequest, get_orchestrator

    directory, _meta = get_demo("custom_aes")
    root = tmp_path / "demo"
    root.mkdir()
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.name != "meta.json":
            shutil.copy2(path, root / path.name)
    result = get_orchestrator().scan(
        ScanRequest(target=str(root), profile="standard", caller="test"))
    cir, canonical = result.as_tuple()
    assert int(canonical["stats"]["files_scanned"]) >= 3
    assert any(a["canonical"] == "AES" for a in cir["assets"])
    assert any(o["operation_type"] == "Encrypt" for o in cir["operations"])
