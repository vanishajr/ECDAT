"""P3 regression fixtures: TLS/cert semantic mappings (C).

Exact-match rows only: cert/key provisioning, cert digests (digest-arg
canonical), and TLS config primitives (cipher list, DH, curves, ECH).
Memory-management and accessor calls must stay silent.
"""

from pathlib import Path

from ecdat.scanners.source.scanner import SourceScanner

HDR = "#include <openssl/ssl.h>\n#include <openssl/x509.h>\n"


def _scan(tmp_path: Path, src: str):
    target = tmp_path / "t.c"
    target.write_text(src)
    return SourceScanner().scan(tmp_path)


def _at(findings, line):
    return [f for f in findings if f.location.line == line]


def test_use_certificate_found(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(SSL_CTX *c, X509 *x) {\n"
                     "  return SSL_CTX_use_certificate(c, x);\n"
                     "}\n")
    hits = _at(findings, 4)
    assert len(hits) == 1
    assert hits[0].canonical == "X.509"


def test_use_privatekey_found(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(SSL_CTX *c, EVP_PKEY *k) {\n"
                     "  return SSL_CTX_use_PrivateKey(c, k);\n"
                     "}\n")
    hits = _at(findings, 4)
    assert len(hits) == 1
    assert hits[0].canonical == "X.509"


def test_x509_digest_resolves_arg(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(X509 *c) {\n"
                     "  return X509_digest(c, EVP_sha256(), 0, 0);\n"
                     "}\n")
    hits = _at(findings, 4)
    assert len(hits) == 1
    assert hits[0].canonical == "SHA-256"


def test_cipher_list_is_tls(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(SSL_CTX *c) {\n"
                     '  return SSL_CTX_set_cipher_list(c, "HIGH");\n'
                     "}\n")
    hits = _at(findings, 4)
    assert len(hits) == 1
    assert hits[0].canonical == "TLS"


def test_tmp_dh_and_curves_found(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(SSL_CTX *c) {\n"
                     "  SSL_CTX_set_tmp_dh(c, 0);\n"
                     '  return SSL_CTX_set1_curves_list(c, "P-256");\n'
                     "}\n")
    assert _at(findings, 4)[0].canonical == "DH"
    assert _at(findings, 5)[0].canonical == "ECDH"


def test_ech_store_found(tmp_path):
    findings = _scan(tmp_path, HDR + "int f(SSL_CTX *c) {\n"
                     "  return SSL_CTX_set1_echstore(c, 0, 0);\n"
                     "}\n")
    hits = _at(findings, 4)
    assert len(hits) == 1
    assert hits[0].canonical == "TLS"


def test_accessors_and_frees_stay_silent(tmp_path):
    findings = _scan(tmp_path, HDR + "void f(X509 *c, SSL_CTX *s) {\n"
                     "  X509_free(c);\n"
                     "  X509_get_subject_name(c);\n"
                     "  SSL_CTX_free(s);\n"
                     "}\n")
    assert findings == []
