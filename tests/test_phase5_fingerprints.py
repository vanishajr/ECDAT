"""Phase 5 hardening tests: custom-implementation fingerprints,
custom-API invocation resolution, generic-config token matching,
and honest files_scanned counts.

Grounded in real-world misses: tiny-AES-c (custom AES, zero findings)
and B-Con/crypto-algorithms reported "0 files / category+keywords junk".
"""
from __future__ import annotations

from pathlib import Path

from ecdat.scanners.source import c_parser as _cp
from ecdat.scanners.source import fingerprints as _fp
from ecdat.scanners.source.scanner import SourceScanner
from ecdat.scanners.config.generic_scanner import GenericConfigScanner
from ecdat.core.cir_models import UsageState

AES_IMPL = """\
#include <stdint.h>
static const uint8_t sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 };
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
static void AddRoundKey(uint8_t s[16], uint8_t k[16]) { }
void AES_init_ctx(struct AesCtx *ctx, const uint8_t *key) { }
void AES_ECB_encrypt(struct AesCtx *ctx, uint8_t *buf) { }
void AES_ECB_decrypt(struct AesCtx *ctx, uint8_t *buf) { }
"""

AES_CALLER = """\
#include "aes.h"
void run(void) {
  struct AesCtx ctx;
  uint8_t buf[16];
  AES_init_ctx(&ctx, key);
  AES_ECB_encrypt(&ctx, buf);
}
"""

AES_HEADER = """\
#pragma once
#include <stdint.h>
struct AesCtx { uint8_t k[32]; };
void AES_init_ctx(struct AesCtx *ctx, const uint8_t *key);
void AES_ECB_encrypt(struct AesCtx *ctx, uint8_t *buf);
"""


def _masked(text: str) -> str:
    masked, _suppressed = _cp.mask_source(text)
    return masked


def test_aes_sbox_rcon_confirmed_implementation():
    hits = _fp.analyze_file(_masked(AES_IMPL), "c")
    aes = [h for h in hits if h.canonical == "AES"]
    assert aes and aes[0].confidence >= 0.90


def test_single_weak_signal_yields_nothing():
    hits = _fp.analyze_file(_masked("void foo(void) { int sbox_tmp = 1; }\n"), "c")
    assert hits == []


def test_base64_and_rot13_never_fingerprint():
    src = ("void base64_encode(char *o, char *i) { }\n"
           "void rot13(char *s) { }\n"
           "static int T[64];\n")
    assert _fp.analyze_file(_masked(src), "c") == []


def test_md5_vs_sha1_disambiguation():
    md5 = ("static const unsigned long K[64] = {0xd76aa478, 0xe8c7b756};\n"
           "unsigned long a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476;\n"
           "void md5_transform(void) { }\n")
    sha1 = ("unsigned long h0=0x67452301,h1=0xefcdab89,h2=0x98badcfe,h3=0x10325476;\n"
            "unsigned long k=0x5a827999;\n"
            "void sha1_transform(void) { }\n")
    md5_hits = {h.canonical for h in _fp.analyze_file(_masked(md5), "c")}
    sha1_hits = {h.canonical for h in _fp.analyze_file(_masked(sha1), "c")}
    assert "MD5" in md5_hits and "SHA-1" not in md5_hits
    assert "SHA-1" in sha1_hits and "MD5" not in sha1_hits


def test_op_hint_mapping():
    assert _fp.op_hint_for_name("AES_ECB_encrypt") == "ENCRYPT"
    assert _fp.op_hint_for_name("AES_ECB_decrypt") == "DECRYPT"
    assert _fp.op_hint_for_name("AES_init_ctx") == "KEY_MANAGEMENT"
    assert _fp.op_hint_for_name("sha256_update") == "HASH"
    assert _fp.op_hint_for_name("helper") is None


def test_def_name_matches_family():
    assert _fp.def_name_matches_family("AES_ECB_encrypt", "AES")
    assert not _fp.def_name_matches_family("AES_ECB_encrypt", "DES")
    assert not _fp.def_name_matches_family("init", "AES")


def test_scanner_impl_plus_invocation(tmp_path: Path):
    (tmp_path / "aes.c").write_text(AES_IMPL, encoding="utf-8")
    (tmp_path / "run.c").write_text(AES_CALLER, encoding="utf-8")
    findings = SourceScanner().scan(str(tmp_path))
    impl = [f for f in findings
            if any(getattr(e, "tool", "") == "source:fingerprint"
                   for e in (f.evidence or []))]
    assert len(impl) == 1 and impl[0].canonical == "AES"
    assert impl[0].usage_state == UsageState.PROVIDED_ONLY
    inv = [f for f in findings
           if any(getattr(e, "tool", "") == "source:custom-invocation"
                  for e in (f.evidence or []))]
    assert {f.operation_type.name for f in inv} >= {"ENCRYPT", "KEY_MANAGEMENT"}
    assert all(f.usage_state == UsageState.CONFIRMED for f in inv)


def test_scanner_prototypes_are_not_invocations(tmp_path: Path):
    (tmp_path / "aes.c").write_text(AES_IMPL, encoding="utf-8")
    (tmp_path / "aes.h").write_text(AES_HEADER, encoding="utf-8")
    findings = SourceScanner().scan(str(tmp_path))
    header_inv = [f for f in findings
                  if str(f.location.file).endswith("aes.h")
                  and any(getattr(e, "tool", "") == "source:custom-invocation"
                          for e in (f.evidence or []))]
    assert header_inv == []


def test_scanner_test_file_gets_no_impl_finding(tmp_path: Path):
    (tmp_path / "aes.c").write_text(AES_IMPL, encoding="utf-8")
    vectors = ("static const uint8_t TV[] = {0x63,0x7c,0x77,0x7b,0xf2,0x6b,"
               "0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76};\n"
               "void test_main(void) { AES_ECB_encrypt(&ctx, buf); }\n")
    (tmp_path / "test.c").write_text(vectors, encoding="utf-8")
    findings = SourceScanner().scan(str(tmp_path))
    test_impl = [f for f in findings
                 if str(f.location.file).endswith("test.c")
                 and any(getattr(e, "tool", "") == "source:fingerprint"
                         for e in (f.evidence or []))]
    assert test_impl == []


def test_generic_config_ignores_category_and_keywords(tmp_path: Path):
    props = tmp_path / "library.properties"
    props.write_text("name=tiny-AES-c\ncategory=Signal Input/Output\n",
                     encoding="utf-8")
    data = tmp_path / "library.json"
    data.write_text('{"name": "x", "keywords": ["communication"]}',
                    encoding="utf-8")
    findings = GenericConfigScanner().scan(str(tmp_path))
    assert findings == []


def test_generic_config_keeps_real_canonical(tmp_path: Path):
    conf = tmp_path / "app.conf"
    conf.write_text("ssl_cert = /etc/ssl/cert.pem\n", encoding="utf-8")
    findings = GenericConfigScanner().scan(str(tmp_path))
    assert findings and findings[0].canonical == "X.509"


def test_files_scanned_counts_inventory_not_findings(tmp_path: Path):
    (tmp_path / "a.c").write_text("int alpha(void) { return 1; }\n",
                                   encoding="utf-8")
    (tmp_path / "b.c").write_text("int beta(void) { return 2; }\n",
                                   encoding="utf-8")
    (tmp_path / "c.h").write_text("int gamma(void);\n",
                                   encoding="utf-8")
    from ecdat.core.orchestrator import ScanRequest, get_orchestrator
    result = get_orchestrator().scan(
        ScanRequest(target=str(tmp_path), profile="quick", caller="test"))
    _cir, canonical = result.as_tuple()
    assert int(canonical["stats"]["files_scanned"]) >= 3
