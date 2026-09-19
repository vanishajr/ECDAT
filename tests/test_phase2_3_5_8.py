"""Phase 2/3/5/8 tests: facts, demand-driven resolver, fingerprints, knowledge.

Additive only: exercises the new modules without touching existing
scanners/registries. All fixtures are inline strings / tmp files.
"""

from __future__ import annotations

import pytest

from ecdat.scanners.source import facts as F
from ecdat.scanners.source import resolver as R
from ecdat.core.crypto_knowledge import constants as KC
from ecdat.core.crypto_knowledge import registry as KR
from ecdat.core.crypto_knowledge import algorithms as KA


# --- Phase 2: facts --------------------------------------------------------

def test_python_def_vs_call_distinction():
    src = (
        "import hashlib\n"
        "def my_hash(data):\n"
        "    return hashlib.sha256(data)\n"
        "my_hash(b'x')\n"
    )
    facts = F.extract_facts_python(src, "m.py")
    defs = [f for f in facts if f.kind == "function_definition"]
    calls = [f for f in facts if f.kind == "function_call"]
    assert [d.name for d in defs] == ["my_hash"]
    call_names = {c.name for c in calls}
    assert "hashlib.sha256" in call_names
    assert "my_hash" in call_names  # the call site, distinct from the def
    assert all(d.name != c.name or d.kind != c.kind
               for d in defs for c in calls
               if d.name == c.name and d.kind == "function_definition")


def test_python_string_vs_api_ref():
    src = 'ALGO = "AES-256-GCM"\nimport ssl\nctx = ssl.SSLContext()\n'
    facts = F.extract_facts_python(src, "m.py")
    strings = [f for f in facts if f.kind == "string_literal"]
    calls = [f for f in facts if f.kind == "function_call"]
    assert any(s.value == "AES-256-GCM" for s in strings)
    assert any(c.name == "ssl.SSLContext" for c in calls)
    # String facts never masquerade as calls and vice versa.
    assert all(s.kind == "string_literal" for s in strings)
    assert all(c.name for c in calls)


def test_brace_facts_include_macro_and_call(tmp_path):
    src = ('#include <openssl/evp.h>\n#define KEYBITS 256\n'
           'int main() { EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), 0, 0, 0); }\n')
    facts = F.extract_facts_brace(src, "a.c", "c")
    kinds = {f.kind for f in facts}
    assert "include" in kinds and "macro" in kinds
    assert "function_call" in kinds and "function_definition" in kinds
    assert any(f.name == "EVP_EncryptInit_ex" for f in facts
               if f.kind == "function_call")


def test_extract_facts_dispatch_and_cache(tmp_path):
    target = tmp_path / "s.py"
    target.write_text('X = "hello"\n')
    first = F.extract_facts(target)
    assert first
    cached_a = F.get_cached_facts(target)
    cached_b = F.get_cached_facts(target)
    assert cached_a is cached_b  # same bytes -> same object
    target.write_text('Y = "other"\n')
    assert F.get_cached_facts(target) is not cached_a


# --- Phase 3: resolver -----------------------------------------------------

def _literal_chain_facts():
    return [
        F.SourceFact(kind="assignment", language="py", name="ALGO",
                     file="m.py", line=1, value='"AES-256-GCM"'),
        F.SourceFact(kind="assignment", language="py", name="MODE",
                     file="m.py", line=2, value="ALGO"),
    ]


def test_resolve_literal_var_arg():
    facts = _literal_chain_facts()
    direct = R.resolve_value("ALGO", facts)
    assert direct is not None and direct.value == "AES-256-GCM"
    chained = R.resolve_value("MODE", facts)  # var -> var -> literal
    assert chained is not None and chained.value == "AES-256-GCM"
    assert chained.hops >= 1
    assert chained.confidence <= (direct.confidence or 1.0)


def test_resolve_call_algorithm_from_var():
    facts = _literal_chain_facts() + [
        F.SourceFact(kind="function_call", language="py",
                     name="Cipher", file="m.py", line=3,
                     arguments=("ALGO",)),
    ]
    call = facts[-1]
    hit = R.resolve_algorithm(call, facts)
    assert hit is not None and hit.value == "AES-256-GCM"


def test_wrapper_expansion_hops_and_decay():
    def _def(name):
        return F.SourceFact(kind="function_definition", language="py",
                            name=name, file="m.py", line=1)
    facts = [
        _def("l1"), _def("l2"), _def("l3"),
        F.SourceFact(kind="function_call", language="py", name="l2",
                     file="m.py", line=2, function="l1"),
        F.SourceFact(kind="function_call", language="py", name="l3",
                     file="m.py", line=3, function="l2"),
        F.SourceFact(kind="function_call", language="py",
                     name="EVP_EncryptInit_ex", file="m.py", line=4,
                     function="l3"),
    ]
    R.reset_stats()
    hop1 = R.expand_wrapper("l3", facts)
    hop3 = R.expand_wrapper("l1", facts)
    assert hop1 is not None and hop1.target == "EVP_EncryptInit_ex"
    assert hop3 is not None and hop3.target == "EVP_EncryptInit_ex"
    assert hop3.hops > hop1.hops
    assert hop3.confidence < hop1.confidence
    assert R.get_stats()["wrappers_expanded"] >= 2


def test_wrapper_cycle_returns_none():
    def _def(name):
        return F.SourceFact(kind="function_definition", language="py",
                            name=name, file="m.py", line=1)
    facts = [
        _def("a"), _def("b"),
        F.SourceFact(kind="function_call", language="py", name="b",
                     file="m.py", line=2, function="a"),
        F.SourceFact(kind="function_call", language="py", name="a",
                     file="m.py", line=3, function="b"),
    ]
    R.reset_stats()
    assert R.expand_wrapper("a", facts) is None
    stats = R.get_stats()
    assert stats["cycles_cut"] >= 1 or stats["unresolved"] >= 1


def test_unresolved_returns_none_not_guess():
    facts = _literal_chain_facts()
    assert R.resolve_value("MISSING", facts) is None
    assert R.resolve_value("os.environ.get('X')", facts) is None
    call = F.SourceFact(kind="function_call", language="py", name="Cipher",
                        file="m.py", line=9, arguments=("MISSING",))
    assert R.resolve_algorithm(call, facts) is None
    assert R.resolve_curve(call, facts) is None
    assert R.resolve_key_size(call, facts) is None
    assert R.resolve_provider(
        F.SourceFact(kind="function_call", language="py",
                     name="mystery_call", file="m.py", line=1)) is None


def test_resolver_stats_recorded():
    R.reset_stats()
    facts = _literal_chain_facts()
    assert R.resolve_value("ALGO", facts) is not None
    assert R.resolve_value("NOPE", facts) is None
    stats = R.get_stats()
    assert stats["resolutions"] >= 1 and stats["unresolved"] >= 1


# --- Phase 5: fingerprints -------------------------------------------------

def test_prefilter_hit_and_miss():
    assert KC.is_crypto_prefilter_hit("use EVP_aes_256_gcm here") is True
    assert KC.is_crypto_prefilter_hit("plain hello world") is False
    assert KC.is_crypto_prefilter_hit(b"tls1.3 handshake") is True
    assert KC.fingerprint_prefilter_hit("nothing here") is None
    hit = KC.fingerprint_prefilter_hit("negotiate aes-256-gcm now")
    assert hit == "AES-256-GCM"


def test_fingerprint_tables_shared_with_binary():
    from ecdat.scanners.binary.crypto_signatures import (
        CRYPTO_CONSTANTS, CRYPTO_OIDS, CRYPTO_STRINGS, CRYPTO_SYMBOLS)
    assert KC.FINGERPRINT_SYMBOLS == CRYPTO_SYMBOLS
    assert KC.FINGERPRINT_STRINGS == CRYPTO_STRINGS
    assert KC.FINGERPRINT_CONSTANTS == CRYPTO_CONSTANTS
    assert KC.FINGERPRINT_OIDS == CRYPTO_OIDS
    assert "aes-256-gcm" in KC.CRYPTO_PREFILTER_TOKENS


# --- Phase 8: unified knowledge --------------------------------------------

def test_knowledge_lookup_canonical_model():
    assert KR.REGISTRY_VERSION == "2026.09.11"
    rec = KR.lookup_algorithm("EVP_aes_256_gcm")
    assert rec is not None and rec.canonical == "AES-256-GCM"
    assert rec.modes and rec.key_sizes  # EVP table folded in
    assert rec.oids or rec.aliases
    rsa = KR.lookup_algorithm("rsa")
    assert rsa is not None and rsa.canonical == "RSA"
    assert rsa.pqc_successors  # quantum posture present
    assert KR.lookup_algorithm("no-such-algo-xyz") is None
    assert KR.canonicalize("no-such-algo-xyz") == "no-such-algo-xyz"


def test_knowledge_seed_covers_registries():
    table = KA.get_algorithm_table()
    assert "RSA" in table and "AES-256-GCM" in table
    assert set(KA.list_canonicals()) == set(table)
    assert table["AES-256-GCM"].family == "AES"
    assert table["ML-KEM"].quantum_safe is True


def test_knowledge_helpers_do_not_break_scanners():
    from ecdat.core.registry import canonicalize as p1_canon
    # Unified registry folds EVP constructor spellings in (P2's JSON lacks
    # them); P1's alias table agrees.
    assert KR.canonicalize("EVP_aes_256_gcm") == "AES-256-GCM"
    assert p1_canon("EVP_aes_256_gcm") == "AES-256-GCM"
    from ecdat.scanners.source.scanner import SourceScanner  # import-safe
    assert SourceScanner.name == "source"
