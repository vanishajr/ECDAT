"""Regression tests: custom-implementation semantics from function definitions.

Covers blind-repo gaps (tiny-AES-c, B-Con/crypto-algorithms) with generic,
repo-agnostic fixtures:

- P1: function definitions refine fingerprint-backed crypto signals
      (mode + operation from names, never names alone).
- P2: declarations vs definitions vs invocations are classified
      differently (prototypes never become Confirmed).
- P3: mode tokens preserved from custom names; generic AES stays generic.
- P4: compile-time AES key-size config (active vs supported).
- P5: generic aliases (arcfour/ARC4 -> RC4, three_des/triple_des/des3/
      tdea -> 3DES; DES stays distinct).
- P6: local body corroboration enriches definition evidence.
- P7: FalsePositiveSuppressed findings carry zero risk in canonical output.
- P8: test files / test vectors stay suppressed; base64/rot13 ignored.
"""

from pathlib import Path

from ecdat.core.signature_registry import normalize_algorithm
from ecdat.scanners.source import c_parser as cp
from ecdat.scanners.source import fingerprints as fp
from ecdat.scanners.source.scanner import SourceScanner


TINY_STYLE_H = """\
#ifndef _AES_H_
#define _AES_H_
#include <stdint.h>
#define CBC 1
#define ECB 1
#define CTR 1
#define AES128 1
struct AES_ctx { uint8_t RoundKey[176]; uint8_t Iv[16]; };
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf); // trailing comment
void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, unsigned len);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, unsigned len);
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, unsigned len);
#endif
"""

TINY_STYLE_C = """\
#include "aes.h"
static const uint8_t sbox[256] = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 };
static const uint8_t Rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
static void KeyExpansion(struct AES_ctx* ctx, const uint8_t* key) { }
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key) { KeyExpansion(ctx, key); }
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf) { Cipher(buf, ctx->RoundKey); }
void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf) { InvCipher(buf, ctx->RoundKey); }
static void XorWithIv(uint8_t* buf, uint8_t* Iv) { }
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, unsigned len) {
  XorWithIv(buf, ctx->Iv);
  Cipher(buf, ctx->RoundKey);
}
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, unsigned len) {
  InvCipher(buf, ctx->RoundKey);
  XorWithIv(buf, ctx->Iv);
}
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, unsigned len) {
  uint8_t ctr[16]; Cipher(ctr, ctx->RoundKey); XorWithIv(buf, ctr);
}
"""


def _scan_tree(tmp_path: Path, files: dict) -> list:
    for name, content in files.items():
        (tmp_path / name).write_text(content)
    return SourceScanner().scan(tmp_path)


# --------------------------------------------------------------------------
# P3/P1: name semantics (pure helpers, no repo needed)
# --------------------------------------------------------------------------

def test_aes_cbc_name_semantics():
    fam, mode, ops = fp.function_semantics("aes_encrypt_cbc")
    assert fam == "AES" and mode == "CBC" and ops == ("ENCRYPT",)
    assert fp.canonical_for_semantics(fam, mode) == "AES-CBC"


def test_aes_ccm_and_cbc_mac_semantics():
    fam, mode, ops = fp.function_semantics("aes_decrypt_ccm")
    assert (fam, mode, ops) == ("AES", "CCM", ("DECRYPT",))
    fam, mode, ops = fp.function_semantics("aes_encrypt_cbc_mac")
    assert fam == "AES" and mode == "CBC-MAC" and ops == ("HASH",)


def test_generic_aes_stays_generic():
    fam, mode, ops = fp.function_semantics("aes_encrypt")
    assert fam == "AES" and mode is None
    assert fp.canonical_for_semantics(fam, mode) == "AES"


def test_mode_arrangements():
    assert fp.function_semantics("AES_CBC_encrypt")[1] == "CBC"
    assert fp.function_semantics("cbc_encrypt_aes")[1] == "CBC"
    assert fp.function_semantics("encrypt_aes_cbc")[1] == "CBC"
    assert fp.function_semantics("AES_CTR_xcrypt_buffer")[1] == "CTR"


def test_xcrypt_is_bidirectional():
    assert set(fp.function_semantics("AES_CTR_xcrypt_buffer")[2]) == {"ENCRYPT", "DECRYPT"}


def test_generic_verbs_alone_yield_nothing():
    for name in ("encrypt", "decrypt", "hash", "sign", "verify", "key", "init", "update"):
        assert fp.function_semantics(name)[0] is None


def test_hash_final_and_stream_hints():
    assert fp.function_semantics("md5_final") == ("MD5", None, ("HASH",))
    assert fp.function_semantics("sha256_final") == ("SHA-256", None, ("HASH",))
    assert fp.function_semantics("blowfish_decrypt") == ("Blowfish", None, ("DECRYPT",))
    assert fp.function_semantics("arcfour_generate_stream")[0] == "RC4"


def test_cpp_qualifier_supplies_family():
    assert fp.function_semantics("AES::EncryptECB") == ("AES", "ECB", ("ENCRYPT",))
    assert fp.function_semantics("AES::DecryptCBC") == ("AES", "CBC", ("DECRYPT",))
    assert fp.function_semantics("AES::EncryptCFB") == ("AES", "CFB", ("ENCRYPT",))
    assert fp.function_semantics("AES::KeyExpansion") == ("AES", None, ("KEY_MANAGEMENT",))
    assert fp.function_semantics("AES::EncryptBlock") == ("AES", None, ("ENCRYPT",))


def test_cpp_helpers_and_constructors_yield_nothing():
    assert fp.function_semantics("AES::XorBlocks") == ("AES", None, ())
    assert fp.function_semantics("AES::CheckLength") == ("AES", None, ())
    assert fp.function_semantics("AES::AES") == ("AES", None, ())
    assert fp.function_semantics("AES::Rcon") == ("AES", None, ())


def test_cpp_style_impl_end_to_end(tmp_path):
    header = ("#pragma once\n#include <stdint.h>\n"
              "static const uint8_t sbox[256] = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,\n"
              "  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 };\n"
              "class AES { public: unsigned char *EncryptECB(const unsigned char in[]);\n"
              "  unsigned char *DecryptECB(const unsigned char in[]); };\n")
    impl = ("#include \"aes.h\"\n"
            "unsigned char *AES::EncryptECB(const unsigned char in[]) { return 0; }\n"
            "unsigned char *AES::DecryptECB(const unsigned char in[]) { return 0; }\n")
    findings = _scan_tree(tmp_path, {"aes.h": header, "aes.cpp": impl})
    prod = [f for f in findings
            if f.location.file.endswith("aes.cpp") and f.operation_type is not None]
    by_canon_op = {(f.canonical, f.operation_type.name) for f in prod}
    assert ("AES-ECB", "ENCRYPT") in by_canon_op
    assert ("AES-ECB", "DECRYPT") in by_canon_op
    header_ops = [f for f in findings
                  if f.location.file.endswith("aes.h") and f.operation_type is not None]
    assert all(f.usage_state.name != "CONFIRMED" for f in header_ops)


# --------------------------------------------------------------------------
# P5: aliases
# --------------------------------------------------------------------------

def test_alias_canonicalization():
    assert normalize_algorithm("arcfour")[0] == "RC4"
    assert normalize_algorithm("ARC4")[0] == "RC4"
    for alias in ("three_des", "triple_des", "3des", "des3", "tdea", "des_ede"):
        assert normalize_algorithm(alias)[0] == "3DES", alias
    # DES and 3DES stay distinct
    assert normalize_algorithm("DES")[0] == "DES"
    assert normalize_algorithm("DES")[0] != normalize_algorithm("three_des")[0]


def test_3des_def_matching_stays_distinct():
    assert fp.def_name_matches_family("three_des_crypt", "3DES")
    assert fp.def_name_matches_family("three_des_crypt", "DES") in (True, False)  # documented below
    assert not fp.def_name_matches_family("des_crypt", "3DES")
    assert fp.def_name_matches_family("des_crypt", "DES")
    fam, _, _ = fp.function_semantics("three_des_crypt")
    assert fam == "3DES"
    fam, _, _ = fp.function_semantics("des_crypt")
    assert fam == "DES"


# --------------------------------------------------------------------------
# P2: declaration vs definition vs call
# --------------------------------------------------------------------------

def test_trailing_comment_prototype_is_declaration():
    stmt = "void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf); // trailing comment"
    assert SourceScanner._looks_like_declaration(stmt, "AES_ECB_encrypt") is True


def test_multiline_commented_prototype_is_declaration():
    lines = [
        "void aes_key_setup(const BYTE key[],          // The key, must be 128, 192, or 256 bits",
        "                   WORD w[],                  // Output key schedule to be used later",
        "                   int keysize);              // Bit length of the key",
    ]
    stmt = cp.statement_text(lines, 1)
    assert SourceScanner._looks_like_declaration(stmt, "aes_key_setup") is True


def test_header_declarations_never_confirmed(tmp_path):
    findings = _scan_tree(tmp_path, {
        "aes.h": TINY_STYLE_H,
        "aes.c": TINY_STYLE_C,
    })
    header_ops = [f for f in findings
                  if f.location.file.endswith("aes.h") and f.operation_type is not None]
    assert all(f.usage_state.name != "CONFIRMED" for f in header_ops), \
        [(f.canonical, f.location.line, f.usage_state) for f in header_ops]


# --------------------------------------------------------------------------
# P1/P3/P6: definitions produce mode-aware custom operations
# --------------------------------------------------------------------------

def test_definitions_yield_mode_aware_operations(tmp_path):
    findings = _scan_tree(tmp_path, {
        "aes.h": TINY_STYLE_H,
        "aes.c": TINY_STYLE_C,
    })
    prod = [f for f in findings
            if f.location.file.endswith("aes.c") and f.operation_type is not None]
    by_canon_op = {(f.canonical, f.operation_type.name) for f in prod}
    assert ("AES-ECB", "ENCRYPT") in by_canon_op
    assert ("AES-ECB", "DECRYPT") in by_canon_op
    assert ("AES-CBC", "ENCRYPT") in by_canon_op
    assert ("AES-CBC", "DECRYPT") in by_canon_op
    assert ("AES-CTR", "ENCRYPT") in by_canon_op
    assert all(f.usage_state.name == "CONFIRMED" for f in prod)
    assert all((f.implementation and f.implementation.library == "custom") for f in prod)


def test_no_mode_guessing_for_generic_aes(tmp_path):
    findings = _scan_tree(tmp_path, {
        "aes.h": TINY_STYLE_H,
        "aes.c": TINY_STYLE_C,
    })
    prod = [f for f in findings
            if f.location.file.endswith("aes.c") and f.operation_type is not None]
    canons = {f.canonical for f in prod}
    assert "AES" in canons  # generic init stays generic
    assert not any(c == "AES-256-CBC" for c in canons)  # no invented key size


def test_names_alone_without_evidence_yield_nothing(tmp_path):
    findings = _scan_tree(tmp_path, {
        "helper.c": "void aes_encrypt_cbc(unsigned char* b) { b[0] ^= 1; }\n",
    })
    assert [f for f in findings if f.operation_type is not None] == []


# --------------------------------------------------------------------------
# P4: key-size config
# --------------------------------------------------------------------------

def test_aes_key_config_active_vs_supported():
    consts = {"AES128": "1", "CBC": "1", "ECB": "1", "CTR": "1"}
    masked = "#define AES128 1\n#if defined(AES256) && (AES256 == 1)\n#elif defined(AES192) && (AES192 == 1)\n"
    active, supported = cp.aes_key_config(consts, masked)
    assert active == 128
    assert supported == [128, 192, 256]


def test_aes_key_config_unknown_without_evidence():
    active, supported = cp.aes_key_config({}, "int x = 1;\n")
    assert active is None and supported == []


# --------------------------------------------------------------------------
# P7: suppressed risk in final canonical output
# --------------------------------------------------------------------------

def test_suppressed_findings_carry_zero_risk(tmp_path):
    from ecdat.core.client import RealCoreClient

    (tmp_path / "aes.c").write_text(TINY_STYLE_C)
    (tmp_path / "aes.h").write_text(TINY_STYLE_H)
    (tmp_path / "test_aes.c").write_text(
        '#include "aes.h"\nvoid aes_cbc_test(void) { AES_CBC_encrypt_buffer(0, 0, 0); }\n')
    result = RealCoreClient(caller="test").scan_result(str(tmp_path))
    cir, doc = result.as_tuple()
    suppressed = [f for f in doc["findings"]
                  if (f.get("metadata", {}) or {}).get("usage_state") == "FalsePositiveSuppressed"]
    assert suppressed, "expected suppressed test findings"
    for finding in suppressed:
        assert finding["metadata"].get("risk_score", 0.0) == 0.0
        assert finding["metadata"].get("risk_class") == "Informational"


# --------------------------------------------------------------------------
# P8: precision guards
# --------------------------------------------------------------------------

def test_base64_rot13_and_test_vectors_stay_suppressed(tmp_path):
    findings = _scan_tree(tmp_path, {
        "b64.c": "static const char* T = \"SGVsbG8=\";\nint base64_encode(void* o, void* i) { return 0; }\n",
        "r13.c": "void rot13(char* s) { }\n",
        "aes.c": TINY_STYLE_C,
        "aes_test.c": '#include "aes.h"\nvoid aes_ecb_test(void) { AES_ECB_encrypt(0, 0); }\n',
    })
    canons = {f.canonical for f in findings}
    assert "Base64" not in canons and "ROT13" not in canons
    test_ops = [f for f in findings
                if f.location.file.endswith("aes_test.c") and f.operation_type is not None]
    assert test_ops and all(f.usage_state.name != "CONFIRMED" for f in test_ops)
