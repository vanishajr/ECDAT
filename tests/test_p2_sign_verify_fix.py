"""P2 regression fixtures: OpenSSL Sign/Verify/keygen/provisioning rows.

Minimal C fixtures, one API per test, driven through the real
SourceScanner. Dynamic digest/cipher arguments resolve to the honest
OpenSSL capability ceiling (never a guessed algorithm); statically
visible type tokens (EVP_PKEY_HMAC) resolve fully.
"""

from pathlib import Path

from ecdat.scanners.source.scanner import SourceScanner

HDR = "#include <openssl/evp.h>\n"


def _scan(tmp_path: Path, src: str):
    target = tmp_path / "t.c"
    target.write_text(src)
    return SourceScanner().scan(tmp_path)


def _at(findings, line):
    return [f for f in findings if f.location.line == line]


def test_digest_sign_init_ex_found(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(EVP_MD_CTX *m) {\n"
                     "  return EVP_DigestSignInit_ex(m, 0, \"SHA256\", 0, 0, 0);\n"
                     "}\n")
    hits = _at(findings, 3)
    assert len(hits) == 1
    assert hits[0].operation_type.name == "SIGN"


def test_digest_sign_final_found(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(EVP_MD_CTX *c) {\n"
                     "  return EVP_DigestSignFinal(c, 0, 0);\n"
                     "}\n")
    hits = _at(findings, 3)
    assert len(hits) == 1
    assert hits[0].operation_type.name == "SIGN"


def test_digest_verify_init_and_final_found(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(EVP_MD_CTX *m) {\n"
                     "  EVP_DigestVerifyInit_ex(m, 0, \"SHA256\", 0, 0, 0);\n"
                     "  return EVP_DigestVerifyFinal(m, 0, 0);\n"
                     "}\n")
    assert _at(findings, 3)[0].operation_type.name == "VERIFY"
    assert _at(findings, 4)[0].operation_type.name == "VERIFY"


def test_oneshot_sign_verify_found(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(EVP_MD_CTX *c) {\n"
                     "  EVP_DigestSign(c, 0, 0, 0, 0);\n"
                     "  return EVP_DigestVerify(c, 0, 0, 0, 0);\n"
                     "}\n")
    assert _at(findings, 3)[0].operation_type.name == "SIGN"
    assert _at(findings, 4)[0].operation_type.name == "VERIFY"


def test_xof_final_found(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(EVP_MD_CTX *c) {\n"
                     "  return EVP_DigestFinalXOF(c, 0, 0);\n"
                     "}\n")
    hits = _at(findings, 3)
    assert len(hits) == 1
    assert hits[0].operation_type.name == "HASH"


def test_pkey_new_raw_hmac_resolves(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(void) {\n"
                     "  EVP_PKEY *k = EVP_PKEY_new_raw_private_key("
                     "EVP_PKEY_HMAC, 0, \"k\", 1);\n"
                     "  return k != 0;\n"
                     "}\n")
    hits = _at(findings, 3)
    assert len(hits) == 1
    assert hits[0].canonical == "HMAC"
    assert hits[0].operation_type.name == "KEY_MANAGEMENT"


def test_pkey_new_raw_dynamic_stays_capability(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(int t, void *b, int n) {\n"
                     "  return EVP_PKEY_new_raw_private_key(t, 0, b, n) != 0;\n"
                     "}\n")
    hits = _at(findings, 3)
    assert len(hits) == 1
    assert hits[0].canonical == "OpenSSL"


def test_cipher_init_ex_found(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(EVP_CIPHER_CTX *c) {\n"
                     "  return EVP_CipherInit_ex(c, 0, 0, 0, 0, 1);\n"
                     "}\n")
    hits = _at(findings, 3)
    assert len(hits) == 1
    assert hits[0].operation_type.name == "ENCRYPT"


def test_cipher_init_decrypt_flag(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(EVP_CIPHER_CTX *c) {\n"
                     "  return EVP_CipherInit_ex(c, 0, 0, 0, 0, 0);\n"
                     "}\n")
    hits = _at(findings, 3)
    assert len(hits) == 1
    assert hits[0].operation_type.name == "DECRYPT"


def test_memory_mgmt_stays_silent(tmp_path):
    findings = _scan(tmp_path, HDR + "void f(EVP_MD_CTX *c, EVP_PKEY *k) {\n"
                     "  EVP_MD_CTX_free(c);\n"
                     "  EVP_PKEY_free(k);\n"
                     "}\n")
    assert findings == []
