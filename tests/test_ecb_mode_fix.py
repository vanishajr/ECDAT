"""Regression tests: PyCryptodome cipher-constructor mode resolution.

AES.new(..., AES.MODE_ECB) must yield an AES-ECB operation (mode ECB),
not a bare AES finding and not silence. Covers dotted constants, bare
imported names, module aliases, mode= keywords, fully-qualified calls,
and the no-mode case (no guessing).
"""

from pathlib import Path

from ecdat.scanners.source import facts as F
from ecdat.scanners.source import resolver as R
from ecdat.scanners.source.scanner import SourceScanner


def _scan_src(tmp_path: Path, src: str):
    target = tmp_path / "a.py"
    target.write_text(src)
    return SourceScanner().scan(tmp_path)


def _by_canonical(findings, canonical):
    return [f for f in findings if f.canonical == canonical]


def test_dotted_mode_constant_yields_aes_ecb(tmp_path):
    findings = _scan_src(
        tmp_path, "from Crypto.Cipher import AES\n"
        "AES.new(b'0'*16, AES.MODE_ECB)\n")
    hits = _by_canonical(findings, "AES-ECB")
    assert len(hits) == 1
    assert hits[0].mode == "ECB"


def test_bare_imported_mode_name_yields_aes_ecb(tmp_path):
    findings = _scan_src(
        tmp_path, "from Crypto.Cipher import AES\n"
        "from Crypto.Cipher.AES import MODE_ECB\n"
        "AES.new(b'0'*16, MODE_ECB)\n")
    hits = _by_canonical(findings, "AES-ECB")
    assert len(hits) == 1 and hits[0].mode == "ECB"


def test_mode_alias_yields_aes_ecb(tmp_path):
    findings = _scan_src(
        tmp_path, "from Crypto.Cipher import AES\n"
        "MODE = AES.MODE_ECB\n"
        "AES.new(b'0'*16, MODE)\n")
    hits = _by_canonical(findings, "AES-ECB")
    assert len(hits) == 1 and hits[0].mode == "ECB"


def test_mode_keyword_yields_moded_canonical(tmp_path):
    findings = _scan_src(
        tmp_path, "from Crypto.Cipher import AES\n"
        "AES.new(key=b'0'*16, mode=AES.MODE_CBC)\n")
    ecb_like = [f for f in findings if (f.mode or "") == "CBC"]
    assert len(ecb_like) == 1
    assert "CBC" in ecb_like[0].canonical


def test_fully_qualified_constructor_yields_mode(tmp_path):
    findings = _scan_src(
        tmp_path, "import Crypto.Cipher.AES\n"
        "Crypto.Cipher.AES.new(b'0'*16, Crypto.Cipher.AES.MODE_CTR)\n")
    hits = [f for f in findings if (f.mode or "") == "CTR"]
    assert len(hits) == 1
    assert hits[0].canonical == "AES-CTR"


def test_constructor_without_mode_stays_bare_aes(tmp_path):
    findings = _scan_src(
        tmp_path, "from Crypto.Cipher import AES\nAES.new(b'0'*16)\n")
    hits = _by_canonical(findings, "AES")
    assert len(hits) == 1 and hits[0].mode is None


def test_resolver_dotted_mode_direct():
    call = F.SourceFact(kind="function_call", language="py",
                        name="AES.new", file="m.py", line=1,
                        arguments=("k", "AES.MODE_ECB"))
    hit = R.resolve_mode(call, [])
    assert hit is not None and hit.value == "ECB"


def test_resolver_dotted_mode_alias():
    facts = [F.SourceFact(kind="assignment", language="py", name="MODE",
                          file="m.py", line=1, value="AES.MODE_ECB")]
    call = F.SourceFact(kind="function_call", language="py",
                        name="AES.new", file="m.py", line=2,
                        arguments=("k", "MODE"))
    hit = R.resolve_mode(call, facts)
    assert hit is not None and hit.value == "ECB"


def test_end_to_end_scan_reports_aes_ecb(tmp_path):
    from ecdat.core.client import RealCoreClient

    target = tmp_path / "app.py"
    target.write_text("from Crypto.Cipher import AES\n"
                      "AES.new(b'0'*16, AES.MODE_ECB)\n")
    cir, doc = RealCoreClient(caller="test").scan_result(
        str(tmp_path)).as_tuple()
    blob = "|".join(
        f"{f.get('rule_id', '')} {f.get('title', '')} "
        f"{(f.get('metadata', {}) or {}).get('canonical_name', '')}"
        for f in doc.get("findings", []))
    assert "AES-ECB" in blob
