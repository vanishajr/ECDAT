"""P1 regression fixtures: Java JCA arg resolution + wrapper attribution.

Each test drives the real SourceScanner on a minimal Java fixture.
All were failing before the P1 fix (missed findings or wrong canonicals).
"""

from pathlib import Path

from ecdat.scanners.source.scanner import SourceScanner


def _scan(tmp_path: Path, name: str, src: str):
    target = tmp_path / name
    target.write_text(src)
    return SourceScanner().scan(tmp_path)


def _at(findings, line):
    return [f for f in findings if f.location.line == line]


def test_jca_transformation_literal_resolves(tmp_path):
    findings = _scan(tmp_path, "A.java",
                     "import javax.crypto.Cipher;\n"
                     "class A {\n"
                     "  void e() throws Exception {\n"
                     '    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");\n'
                     "  }\n"
                     "}\n")
    hits = _at(findings, 4)
    assert len(hits) == 1
    assert hits[0].canonical == "AES"
    assert hits[0].mode == "CBC"


def test_jca_secretkeyfactory_literal_resolves(tmp_path):
    findings = _scan(tmp_path, "B.java",
                     "import javax.crypto.SecretKeyFactory;\n"
                     "class B {\n"
                     "  void k() throws Exception {\n"
                     '    SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");\n'
                     "  }\n"
                     "}\n")
    hits = _at(findings, 4)
    assert len(hits) == 1
    assert hits[0].canonical == "PBKDF2"


def test_wrapper_delegate_constant_propagates(tmp_path):
    d = tmp_path
    (d / "CipherUtils.java").write_text(
        "import javax.crypto.Cipher;\n"
        "final class CipherUtils {\n"
        "  static Cipher newCipher(String algorithm) throws Exception {\n"
        "    return Cipher.getInstance(algorithm);\n"
        "  }\n"
        "}\n")
    (d / "Use.java").write_text(
        "import javax.crypto.Cipher;\n"
        "class Use {\n"
        '  private static final String ALGORITHM = "AES/GCM/NoPadding";\n'
        "  private Cipher c;\n"
        "  void init() throws Exception {\n"
        "    this.c = CipherUtils.newCipher(ALGORITHM);\n"
        "  }\n"
        "}\n")
    findings = SourceScanner().scan(d)
    use_hits = [f for f in findings
                if f.location.file.endswith("Use.java")]
    assert len(use_hits) == 1
    assert use_hits[0].location.line == 6
    assert use_hits[0].canonical == "AES"
    assert use_hits[0].mode == "GCM"


def test_enum_indirection_resolves_rsa(tmp_path):
    d = tmp_path
    (d / "RsaAlgorithm.java").write_text(
        "public enum RsaAlgorithm {\n"
        '  DEFAULT("RSA", 117), OAEP("RSA/ECB/OAEPPadding", 86);\n'
        "  private final String name;\n"
        "  RsaAlgorithm(String name, int maxLength) { this.name = name; }\n"
        "  public String getJceName() { return this.name; }\n"
        "}\n")
    (d / "Enc.java").write_text(
        "import javax.crypto.Cipher;\n"
        "class Enc {\n"
        "  private RsaAlgorithm algorithm = RsaAlgorithm.DEFAULT;\n"
        "  byte[] go() throws Exception {\n"
        "    Cipher c = Cipher.getInstance(alg.getJceName());\n"
        "  }\n"
        "}\n".replace("alg.getJceName()", "algorithm.getJceName()"))
    findings = SourceScanner().scan(d)
    enc_hits = [f for f in findings
                if f.location.file.endswith("Enc.java")]
    assert len(enc_hits) == 1
    assert enc_hits[0].canonical == "RSA"


def test_bcrypt_static_calls_found(tmp_path):
    findings = _scan(tmp_path, "P.java",
                     "import org.mindrot.jbcrypt.BCrypt;\n"
                     "class P {\n"
                     "  String h(String pw, String salt) {\n"
                     "    return BCrypt.hashpw(pw, salt);\n"
                     "  }\n"
                     "  boolean v(String pw, String h) {\n"
                     "    return BCrypt.checkpw(pw, h);\n"
                     "  }\n"
                     "}\n")
    kinds = sorted(f.canonical for f in findings)
    assert kinds == ["bcrypt", "bcrypt"]


def test_secure_random_ctor_found(tmp_path):
    findings = _scan(tmp_path, "K.java",
                     "import java.security.SecureRandom;\n"
                     "class K {\n"
                     "  private final SecureRandom random = new SecureRandom();\n"
                     "}\n")
    assert len(findings) == 1
    assert findings[0].canonical == "RANDOM"


def test_k_and_r_function_spans_track_methods(tmp_path):
    from ecdat.scanners.source import c_parser as C
    masked, _ = C.mask_source(
        "package x;\npublic class R {\n"
        "  private static byte[] encrypt(byte[] t) {\n"
        "    return doFinal(t);\n  }\n"
        "  private static byte[] decrypt(byte[] t) {\n"
        "    return doFinal(t);\n  }\n}\n")
    sites = [s for s in C.extract_calls(masked) if s.name == "doFinal"]
    assert [(s.line, s.function) for s in sites] == [(4, "encrypt"),
                                                    (7, "decrypt")]
    masked2, _ = C.mask_source(
        "int dgst_main(int argc, char **argv)\n{\n"
        "  md = EVP_MD_fetch(a, b, c);\n}\n")
    sites2 = [s for s in C.extract_calls(masked2)
              if s.name == "EVP_MD_fetch"]
    assert len(sites2) == 1 and sites2[0].function == "dgst_main"


def test_field_flow_init_dofinal(tmp_path):
    d = tmp_path
    (d / "CipherUtils.java").write_text(
        "import javax.crypto.Cipher;\n"
        "final class CipherUtils {\n"
        "  static Cipher newCipher(String algorithm) throws Exception {\n"
        "    return Cipher.getInstance(algorithm);\n"
        "  }\n"
        "  static void initCipher(Cipher c, int mode, java.security.Key k,\n"
        "      java.security.spec.AlgorithmParameterSpec s) throws Exception {\n"
        "    c.init(mode, k, s);\n"
        "  }\n"
        "  static byte[] doFinal(Cipher c, byte[] in) throws Exception {\n"
        "    return c.doFinal(in);\n"
        "  }\n"
        "}\n")
    (d / "Flow.java").write_text(
        "import javax.crypto.Cipher;\n"
        "import javax.crypto.spec.IvParameterSpec;\n"
        "import javax.crypto.spec.SecretKeySpec;\n"
        "class Flow {\n"
        '  private static final String ALGORITHM = "AES/CBC/PKCS5Padding";\n'
        "  private final Cipher encryptor;\n"
        "  Flow() throws Exception {\n"
        "    this.encryptor = CipherUtils.newCipher(ALGORITHM);\n"
        "  }\n"
        "  byte[] enc(byte[] b, java.security.Key k, byte[] iv) throws Exception {\n"
        "    CipherUtils.initCipher(this.encryptor, Cipher.ENCRYPT_MODE, k,\n"
        "        new IvParameterSpec(iv));\n"
        "    return CipherUtils.doFinal(this.encryptor, b);\n"
        "  }\n"
        "}\n")
    findings = SourceScanner().scan(d)
    flow_hits = [f for f in findings
                 if f.location.file.endswith("Flow.java")]
    by_line = {f.location.line: f for f in flow_hits}
    assert 8 in by_line  # newCipher(ALGORITHM) resolves AES-CBC
    assert by_line[8].canonical == "AES"
    assert by_line[8].mode == "CBC"
    assert 13 in by_line  # doFinal on the ENCRYPT-init field
    assert by_line[13].canonical == "AES"
    assert by_line[13].operation_type.name == "ENCRYPT"


def test_instance_dofinal_anchored_to_function(tmp_path):
    findings = _scan(tmp_path, "R.java",
                     "import javax.crypto.Cipher;\n"
                     "class R {\n"
                     "  byte[] encrypt(Cipher cipher, byte[] t) throws Exception {\n"
                     '    Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");\n'
                     "    return cipher.doFinal(t);\n"
                     "  }\n"
                     "}\n")
    finals = [f for f in findings if f.location.line == 5]
    assert len(finals) == 1
    assert finals[0].canonical == "RSA"
    assert finals[0].operation_type.name == "ENCRYPT"
