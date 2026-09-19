"""Phase 1 regression: cheaper candidate detection (exact-first matching).

Verifies:
- exact lookup vs regex fallback produce the same semantic result
  (same first-row-wins row id for every indexed token),
- matcher/prefilter structures compile once per registry version,
- ambiguous APIs (one name, several rows) still resolve via fallback order.
"""

from __future__ import annotations

import re

from ecdat.scanners.source import api_knowledge as ak


def _regex_first_id(name: str, lang: str) -> str | None:
    probe = name + "("
    for row, rx in ak.compile_matchers(lang):
        try:
            if rx.search(probe):
                return str(row.get("id", ""))
        except re.error:
            continue
    return None


def test_exact_vs_regex_equivalence_all_tokens():
    checked = 0
    for lang, bucket in ak.EXACT_API_INDEX.items():
        assert bucket, f"empty exact index for {lang}"
        for token in bucket:
            exact = ak.lookup_exact(token, lang)
            exact_id = str(exact[0].get("id", "")) if exact else None
            assert exact_id == _regex_first_id(token, lang), \
                f"{lang}:{token} exact={exact_id}"
            checked += 1
            # Prefixed call path (crypto.subtle.encrypt style).
            prefixed = "outer." + token
            exact_p = ak.lookup_exact(prefixed, lang)
            exact_p_id = str(exact_p[0].get("id", "")) if exact_p else None
            assert exact_p_id == _regex_first_id(prefixed, lang), \
                f"{lang}:{prefixed} exact={exact_p_id}"
            checked += 1
    assert checked > 100


def test_exact_vs_regex_non_matches():
    for name in ["foo", "bar", "myEncrypt", "AES_init_ctx", "notACryptoCall"]:
        for lang in ["c", "cpp", "java", "js", "go", "csharp", "rust"]:
            exact = ak.lookup_exact(name, lang)
            exact_id = str(exact[0].get("id", "")) if exact else None
            assert exact_id == _regex_first_id(name, lang), \
                f"{lang}:{name} exact={exact_id}"


def test_single_compilation_per_registry_version():
    ak.invalidate_matcher_caches()
    first = ak.compile_matchers("c")
    second = ak.compile_matchers("c")
    assert first is second
    stats = ak.get_matcher_stats()
    assert stats["registry_version"] == ak.REGISTRY_VERSION
    assert stats["compile_calls"] == 1
    # Prefilter also compiles once.
    assert ak.lex_prefilter("EVP_EncryptInit_ex(x);", "c") is True
    assert ak.lex_prefilter("EVP_EncryptInit_ex(x);", "c") is True
    stats2 = ak.get_matcher_stats()
    assert stats2["prefilter_compiles"] == 1
    assert stats2["compile_calls"] == 1


def test_ambiguous_apis_still_work():
    # EVP_PKEY_derive is claimed by two rows; exact lookup must return
    # both in patterns_for order with the regex fallback winner first.
    rows = ak.lookup_exact("EVP_PKEY_derive", "c")
    ids = [str(r.get("id", "")) for r in rows]
    assert ids == ["ossl-evp-pkey-derive", "ossl-ecdh"]
    assert ids[0] == _regex_first_id("EVP_PKEY_derive", "c")
    # Dotted suffix form still resolves (webcrypto subtle.*).
    web = ak.lookup_exact("crypto.subtle.encrypt", "js")
    assert web and str(web[0].get("id", "")) == "webcrypto-op"
    # Rust :: separators survive prefixing.
    rust = ak.lookup_exact("foo.Aes256Gcm::new", "rust")
    assert rust and str(rust[0].get("id", "")) == "rust-aesgcm"


def test_prefilter_single_combined_regex():
    assert ak.lex_prefilter("EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm());", "c")
    assert not ak.lex_prefilter("int main(void) { return 0; }", "c")
    assert not ak.lex_prefilter("", "c")
    assert not ak.lex_prefilter("EVP_EncryptInit_ex", "go")


def test_patterns_for_backward_compatible():
    for lang in ["c", "cpp", "java", "js", "go", "csharp", "rust"]:
        rows = ak.patterns_for(lang)
        assert rows, f"no rows for {lang}"
        for row in rows:
            assert "id" in row and "re" in row and "langs" in row
            assert lang in row["langs"]
            assert row.get("match_type") in (
                "exact", "prefix", "regex", "constructor", "string-parameter")
            re.compile(str(row["re"]))  # still valid regex
    # Deterministic order across calls.
    assert [r["id"] for r in ak.patterns_for("c")] == \
        [r["id"] for r in ak.patterns_for("c")]


def test_scanner_cache_parity(tmp_path):
    from ecdat.scanners.source import SourceScanner

    target = tmp_path / "enc.c"
    target.write_text(
        "#include <openssl/evp.h>\n"
        "int app_encrypt(EVP_CIPHER_CTX *ctx) {\n"
        "    return EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),\n"
        "                              NULL, NULL, NULL);\n"
        "}\n")
    scanner = SourceScanner()
    first = scanner.scan(target)
    assert any(f.canonical == "AES-256-GCM" for f in first)
    second = scanner.scan(target)
    assert [(f.canonical, f.location.line) for f in first] == \
        [(f.canonical, f.location.line) for f in second]
