"""P4 regression fixtures: pyca alias/class attribution (Python).

Binding aliases (X = module.Attr) and cipher/mode class definitions
yield ProvidedOnly capability findings (never Confirmed ops). Unknown
attributes, SIV variants without a canonical, and generic classes stay
silent.
"""

from pathlib import Path

from ecdat.scanners.source.scanner import SourceScanner


def _scan(tmp_path: Path, src: str):
    target = tmp_path / "a.py"
    target.write_text(src)
    return SourceScanner().scan(tmp_path)


def _at(findings, line):
    return [f for f in findings if f.location.line == line]


def test_binding_alias_resolves(tmp_path):
    findings = _scan(tmp_path,
                     "from cryptography.hazmat.bindings._rust import openssl as rust_openssl\n"
                     "AESGCM = rust_openssl.aead.AESGCM\n"
                     "ChaCha20Poly1305 = rust_openssl.aead.ChaCha20Poly1305\n")
    aes = _at(findings, 2)
    assert len(aes) == 1 and aes[0].canonical == "AES-256-GCM"
    assert aes[0].usage_state.value != "Confirmed"
    cha = _at(findings, 3)
    assert len(cha) == 1 and cha[0].canonical == "ChaCha20-Poly1305"


def test_unknown_alias_stays_silent(tmp_path):
    findings = _scan(tmp_path,
                     "import foo\n"
                     "Bar = foo.baz.Qux\n")
    assert [f for f in findings if f.location.line == 2] == []


def test_siv_variant_stays_silent(tmp_path):
    findings = _scan(tmp_path,
                     "from cryptography.hazmat.bindings._rust import openssl as rust_openssl\n"
                     "AESGCMSIV = rust_openssl.aead.AESGCMSIV\n")
    assert [f for f in findings if f.location.line == 2] == []


def test_cipher_class_defs_are_capabilities(tmp_path):
    findings = _scan(tmp_path,
                     "class AES:\n"
                     "    pass\n"
                     "class ChaCha20:\n"
                     "    pass\n")
    aes = _at(findings, 1)
    assert len(aes) == 1 and aes[0].canonical == "AES"
    assert aes[0].usage_state.value != "Confirmed"
    cha = _at(findings, 3)
    assert len(cha) == 1 and cha[0].canonical == "ChaCha20"


def test_mode_class_def_is_capability(tmp_path):
    findings = _scan(tmp_path,
                     "class CBC:\n"
                     "    pass\n")
    cbc = _at(findings, 1)
    assert len(cbc) == 1 and cbc[0].canonical == "CBC"


def test_generic_class_stays_silent(tmp_path):
    findings = _scan(tmp_path,
                     "class Cipher:\n"
                     "    pass\n"
                     "class Helper:\n"
                     "    pass\n")
    assert findings == []


def test_mode_constant_alias_stays_silent(tmp_path):
    findings = _scan(tmp_path,
                     "from Crypto.Cipher import AES\n"
                     "MODE = AES.MODE_ECB\n")
    assert [f for f in findings if f.location.line == 2] == []
