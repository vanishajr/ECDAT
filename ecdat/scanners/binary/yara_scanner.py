from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional

from ecdat.scanners.base import Scanner, ScannerFinding, create_evidence_signal, normalize_finding
from ecdat.core.cir_models import UsageState, Location, Implementation, Context, Exposure
from ecdat.core.signature_registry import normalize_algorithm, get_category, is_library_only


YARA_RULES = """
rule Crypto_AES_GCM {
    meta:
        description = "AES-GCM constants and strings"
        algorithm = "AES-256-GCM"
        category = "symmetric"
        confidence = 0.7
    strings:
        $aes_gcm_1 = "AES-GCM" nocase
        $aes_gcm_2 = "AES_GCM" nocase
        $aes_gcm_3 = "gcm_encrypt" nocase
        $aes_gcm_4 = "gcm_decrypt" nocase
        $aes_gcm_5 = "GHASH" nocase
    condition:
        any of them
}

rule Crypto_AES_CBC {
    meta:
        description = "AES-CBC constants and strings"
        algorithm = "AES-256-CBC"
        category = "symmetric"
        confidence = 0.7
    strings:
        $aes_cbc_1 = "AES-CBC" nocase
        $aes_cbc_2 = "AES_CBC" nocase
        $aes_cbc_3 = "cbc_encrypt" nocase
        $aes_cbc_4 = "cbc_decrypt" nocase
    condition:
        any of them
}

rule Crypto_ChaCha20_Poly1305 {
    meta:
        description = "ChaCha20-Poly1305 constants"
        algorithm = "ChaCha20-Poly1305"
        category = "symmetric"
        confidence = 0.75
    strings:
        $chacha_1 = "ChaCha20-Poly1305" nocase
        $chacha_2 = "chacha20_poly1305" nocase
        $chacha_3 = "ChaChaPoly" nocase
        $poly1305 = "poly1305" nocase
    condition:
        any of them
}

rule Crypto_RSA {
    meta:
        description = "RSA constants and strings"
        algorithm = "RSA"
        category = "asymmetric"
        confidence = 0.7
    strings:
        $rsa_1 = "RSA" nocase
        $rsa_2 = "RSA_public_encrypt" nocase
        $rsa_3 = "RSA_private_decrypt" nocase
        $rsa_4 = "RSA_sign" nocase
        $rsa_5 = "RSA_verify" nocase
        $rsa_6 = "PKCS1" nocase
        $rsa_7 = "OAEP" nocase
        $rsa_8 = "PSS" nocase
    condition:
        any of them
}

rule Crypto_ECDSA {
    meta:
        description = "ECDSA constants and strings"
        algorithm = "ECDSA"
        category = "asymmetric"
        confidence = 0.7
    strings:
        $ecdsa_1 = "ECDSA" nocase
        $ecdsa_2 = "ecdsa_sign" nocase
        $ecdsa_3 = "ecdsa_verify" nocase
        $ecdsa_4 = "P-256" nocase
        $ecdsa_5 = "secp256k1" nocase
        $ecdsa_6 = "NIST P-256" nocase
    condition:
        any of them
}

rule Crypto_ECDH {
    meta:
        description = "ECDH constants and strings"
        algorithm = "ECDH"
        category = "key_exchange"
        confidence = 0.7
    strings:
        $ecdh_1 = "ECDH" nocase
        $ecdh_2 = "ecdh_key_agreement" nocase
        $ecdh_3 = "derive_key" nocase
    condition:
        any of them
}

rule Crypto_X25519 {
    meta:
        description = "X25519 constants and strings"
        algorithm = "X25519"
        category = "key_exchange"
        confidence = 0.75
    strings:
        $x25519_1 = "X25519" nocase
        $x25519_2 = "x25519" nocase
        $x25519_3 = "Curve25519" nocase
        $x25519_4 = "curve25519" nocase
    condition:
        any of them
}

rule Crypto_Ed25519 {
    meta:
        description = "Ed25519 constants and strings"
        algorithm = "Ed25519"
        category = "asymmetric"
        confidence = 0.75
    strings:
        $ed25519_1 = "Ed25519" nocase
        $ed25519_2 = "ed25519" nocase
        $ed25519_3 = "EdDSA" nocase
    condition:
        any of them
}

rule Crypto_SHA256 {
    meta:
        description = "SHA-256 constants and strings"
        algorithm = "SHA-256"
        category = "hash"
        confidence = 0.6
    strings:
        $sha256_1 = "SHA-256" nocase
        $sha256_2 = "SHA256" nocase
        $sha256_3 = "sha256" nocase
    condition:
        any of them
}

rule Crypto_SHA384 {
    meta:
        description = "SHA-384 constants and strings"
        algorithm = "SHA-384"
        category = "hash"
        confidence = 0.6
    strings:
        $sha384_1 = "SHA-384" nocase
        $sha384_2 = "SHA384" nocase
    condition:
        any of them
}

rule Crypto_SHA512 {
    meta:
        description = "SHA-512 constants and strings"
        algorithm = "SHA-512"
        category = "hash"
        confidence = 0.6
    strings:
        $sha512_1 = "SHA-512" nocase
        $sha512_2 = "SHA512" nocase
    condition:
        any of them
}

rule Crypto_SHA3 {
    meta:
        description = "SHA-3 constants and strings"
        algorithm = "SHA-3-256"
        category = "hash"
        confidence = 0.6
    strings:
        $sha3_1 = "SHA3-256" nocase
        $sha3_2 = "SHA3-512" nocase
        $sha3_3 = "Keccak-256" nocase
        $sha3_4 = "Keccak-512" nocase
    condition:
        any of them
}

rule Crypto_BLAKE2 {
    meta:
        description = "BLAKE2 constants and strings"
        algorithm = "BLAKE2b"
        category = "hash"
        confidence = 0.6
    strings:
        $blake2_1 = "BLAKE2b" nocase
        $blake2_2 = "BLAKE2s" nocase
        $blake2_3 = "blake2" nocase
    condition:
        any of them
}

rule Crypto_PBKDF2 {
    meta:
        description = "PBKDF2 constants and strings"
        algorithm = "PBKDF2"
        category = "kdf"
        confidence = 0.7
    strings:
        $pbkdf2_1 = "PBKDF2" nocase
        $pbkdf2_2 = "pbkdf2" nocase
        $pbkdf2_3 = "PBKDF2-HMAC" nocase
    condition:
        any of them
}

rule Crypto_HKDF {
    meta:
        description = "HKDF constants and strings"
        algorithm = "HKDF"
        category = "kdf"
        confidence = 0.7
    strings:
        $hkdf_1 = "HKDF" nocase
        $hkdf_2 = "hkdf" nocase
        $hkdf_3 = "HKDF-Extract" nocase
        $hkdf_4 = "HKDF-Expand" nocase
    condition:
        any of them
}

rule Crypto_Scrypt {
    meta:
        description = "scrypt constants and strings"
        algorithm = "scrypt"
        category = "kdf"
        confidence = 0.7
    strings:
        $scrypt_1 = "scrypt" nocase
        $scrypt_2 = "Scrypt" nocase
    condition:
        any of them
}

rule Crypto_Argon2 {
    meta:
        description = "Argon2 constants and strings"
        algorithm = "Argon2"
        category = "kdf"
        confidence = 0.7
    strings:
        $argon2_1 = "Argon2" nocase
        $argon2_2 = "argon2" nocase
        $argon2_3 = "Argon2id" nocase
        $argon2_4 = "Argon2i" nocase
    condition:
        any of them
}

rule Crypto_TLS {
    meta:
        description = "TLS/SSL constants and strings"
        algorithm = "TLS1.2"
        category = "protocol"
        confidence = 0.6
    strings:
        $tls_1 = "TLS" nocase
        $tls_2 = "SSL" nocase
        $tls_3 = "SSLv" nocase
        $tls_4 = "TLSv" nocase
        $tls_5 = "handshake" nocase
        $tls_6 = "cipher_suite" nocase
    condition:
        any of them
}

rule Crypto_SSH {
    meta:
        description = "SSH constants and strings"
        algorithm = "SSH"
        category = "protocol"
        confidence = 0.6
    strings:
        $ssh_1 = "SSH-" nocase
        $ssh_2 = "ssh-" nocase
        $ssh_3 = "ssh2" nocase
        $ssh_4 = "key exchange" nocase
    condition:
        any of them
}

rule Crypto_ML_KEM {
    meta:
        description = "ML-KEM/Kyber constants and strings"
        algorithm = "ML-KEM"
        category = "pqc_kem"
        confidence = 0.75
    strings:
        $kyber_1 = "ML-KEM" nocase
        $kyber_2 = "Kyber" nocase
        $kyber_3 = "kyber" nocase
        $kyber_4 = "Kyber512" nocase
        $kyber_5 = "Kyber768" nocase
        $kyber_6 = "Kyber1024" nocase
    condition:
        any of them
}

rule Crypto_ML_DSA {
    meta:
        description = "ML-DSA/Dilithium constants and strings"
        algorithm = "ML-DSA"
        category = "pqc_sig"
        confidence = 0.75
    strings:
        $dilithium_1 = "ML-DSA" nocase
        $dilithium_2 = "Dilithium" nocase
        $dilithium_3 = "dilithium" nocase
        $dilithium_4 = "Dilithium2" nocase
        $dilithium_5 = "Dilithium3" nocase
        $dilithium_6 = "Dilithium5" nocase
    condition:
        any of them
}

rule Crypto_SLH_DSA {
    meta:
        description = "SLH-DSA/SPHINCS+ constants and strings"
        algorithm = "SLH-DSA"
        category = "pqc_sig"
        confidence = 0.75
    strings:
        $sphincs_1 = "SLH-DSA" nocase
        $sphincs_2 = "SPHINCS+" nocase
        $sphincs_3 = "sphincs" nocase
    condition:
        any of them
}

rule Crypto_Falcon {
    meta:
        description = "Falcon constants and strings"
        algorithm = "Falcon"
        category = "pqc_sig"
        confidence = 0.75
    strings:
        $falcon_1 = "Falcon" nocase
        $falcon_2 = "falcon" nocase
        $falcon_3 = "Falcon-512" nocase
        $falcon_4 = "Falcon-1024" nocase
    condition:
        any of them
}

rule Crypto_OpenSSL {
    meta:
        description = "OpenSSL library strings"
        algorithm = "OpenSSL"
        category = "library"
        confidence = 0.5
    strings:
        $ossl_1 = "OpenSSL" nocase
        $ossl_2 = "libcrypto" nocase
        $ossl_3 = "libssl" nocase
    condition:
        any of them
}

rule Crypto_BoringSSL {
    meta:
        description = "BoringSSL library strings"
        algorithm = "BoringSSL"
        category = "library"
        confidence = 0.5
    strings:
        $boring_1 = "BoringSSL" nocase
        $boring_2 = "boringssl" nocase
    condition:
        any of them
}

rule Crypto_LibreSSL {
    meta:
        description = "LibreSSL library strings"
        algorithm = "LibreSSL"
        category = "library"
        confidence = 0.5
    strings:
        $libre_1 = "LibreSSL" nocase
        $libre_2 = "libressl" nocase
    condition:
        any of them
}

rule Crypto_Insecure_MD5 {
    meta:
        description = "MD5 constants (insecure)"
        algorithm = "MD5"
        category = "hash"
        confidence = 0.6
    strings:
        $md5_1 = "MD5" nocase
        $md5_2 = "md5" nocase
    condition:
        any of them
}

rule Crypto_Insecure_SHA1 {
    meta:
        description = "SHA-1 constants (insecure)"
        algorithm = "SHA-1"
        category = "hash"
        confidence = 0.6
    strings:
        $sha1_1 = "SHA-1" nocase
        $sha1_2 = "SHA1" nocase
        $sha1_3 = "sha1" nocase
    condition:
        any of them
}

rule Crypto_Insecure_DES {
    meta:
        description = "DES constants (insecure)"
        algorithm = "DES"
        category = "symmetric"
        confidence = 0.7
    strings:
        $des_1 = "DES" nocase
        $des_2 = "des_encrypt" nocase
        $des_3 = "des_decrypt" nocase
    condition:
        any of them
}

rule Crypto_Insecure_3DES {
    meta:
        description = "3DES constants (insecure)"
        algorithm = "3DES"
        category = "symmetric"
        confidence = 0.7
    strings:
        $tdes_1 = "3DES" nocase
        $tdes_2 = "DES3" nocase
        $tdes_3 = "DES-EDE3" nocase
        $tdes_4 = "triple_des" nocase
    condition:
        any of them
}

rule Crypto_Insecure_RC4 {
    meta:
        description = "RC4 constants (insecure)"
        algorithm = "RC4"
        category = "symmetric"
        confidence = 0.7
    strings:
        $rc4_1 = "RC4" nocase
        $rc4_2 = "rc4" nocase
        $rc4_3 = "ARC4" nocase
        $rc4_4 = "arcfour" nocase
    condition:
        any of them
}
"""


class YARAScanner(Scanner[ScannerFinding]):
    name = "binary-yara"
    version = "0.1.0"

    def __init__(self) -> None:
        self._yara_available = self._check_yara()
        self._rules_path: Optional[Path] = None

    def _check_yara(self) -> bool:
        try:
            import yara_x
            return True
        except ImportError:
            try:
                import yara
                return True
            except ImportError:
                return False

    def is_available(self) -> bool:
        return self._yara_available

    def get_tool_version(self) -> str:
        try:
            import yara_x
            return f"yara-x-{yara_x.__version__}"
        except ImportError:
            try:
                import yara
                return f"yara-{yara.__version__}"
            except ImportError:
                return "yara-unknown"

    def scan(self, target: Path | str, **kwargs) -> list[ScannerFinding]:
        if not self._yara_available:
            return []

        target_path = Path(target)
        if not target_path.is_file():
            return []

        self._ensure_rules()

        findings: list[ScannerFinding] = []

        try:
            import yara_x
            findings = self._scan_yara_x(target_path)
        except ImportError:
            try:
                import yara
                findings = self._scan_yara(target_path)
            except ImportError:
                pass
        except Exception:
            pass

        normalized = [normalize_finding(f) for f in findings]
        return normalized

    def _ensure_rules(self) -> None:
        if self._rules_path and self._rules_path.exists():
            return

        self._rules_path = Path(tempfile.gettempdir()) / "ecdat_yara_rules.yar"
        self._rules_path.write_text(YARA_RULES)

    def _scan_yara_x(self, target_path: Path) -> list[ScannerFinding]:
        import yara_x

        findings: list[ScannerFinding] = []

        compiler = yara_x.Compiler()
        compiler.add_source(str(self._rules_path))
        rules = compiler.build()

        scanner = yara_x.Scanner(rules)
        results = scanner.scan_file(str(target_path))

        for match in results.matching_rules:
            meta = match.metadata
            algorithm = meta.get("algorithm", "Unknown")
            category = meta.get("category", "unknown")
            confidence = float(meta.get("confidence", 0.5))

            canonical, original = normalize_algorithm(algorithm)

            if is_library_only(canonical) or category == "library":
                usage_state = UsageState.PROVIDED_ONLY
                confidence = min(confidence, 0.4)
            elif confidence >= 0.7:
                usage_state = UsageState.PROBABLE
            else:
                usage_state = UsageState.POSSIBLE

            matched_strings = []
            for pattern in match.patterns:
                for instance in pattern.instances:
                    matched_strings.append(instance.matched_data.decode("utf-8", errors="ignore")[:100])

            findings.append(ScannerFinding(
                canonical=canonical,
                original=original,
                usage_state=usage_state,
                confidence=confidence,
                evidence=[create_evidence_signal(
                    tool="binary-yara",
                    detail=f"YARA rule match: {match.identifier}",
                    confidence=confidence,
                    snippet="; ".join(matched_strings[:5]),
                )],
                location=Location(file=str(target_path), uri=f"binary-yara:{match.identifier}"),
                implementation=Implementation(library="unknown", provider="yara-x"),
                context=Context(exposure=Exposure.INTERNAL),
            ))

        return findings

    def _scan_yara(self, target_path: Path) -> list[ScannerFinding]:
        import yara

        findings: list[ScannerFinding] = []

        rules = yara.compile(filepath=str(self._rules_path))
        matches = rules.match(str(target_path))

        for match in matches:
            meta = match.meta
            algorithm = meta.get("algorithm", "Unknown")
            category = meta.get("category", "unknown")
            confidence = float(meta.get("confidence", 0.5))

            canonical, original = normalize_algorithm(algorithm)

            if is_library_only(canonical) or category == "library":
                usage_state = UsageState.PROVIDED_ONLY
                confidence = min(confidence, 0.4)
            elif confidence >= 0.7:
                usage_state = UsageState.PROBABLE
            else:
                usage_state = UsageState.POSSIBLE

            matched_strings = []
            for string_match in match.strings:
                matched_strings.append(string_match[2].decode("utf-8", errors="ignore")[:100])

            findings.append(ScannerFinding(
                canonical=canonical,
                original=original,
                usage_state=usage_state,
                confidence=confidence,
                evidence=[create_evidence_signal(
                    tool="binary-yara",
                    detail=f"YARA rule match: {match.rule}",
                    confidence=confidence,
                    snippet="; ".join(matched_strings[:5]),
                )],
                location=Location(file=str(target_path), uri=f"binary-yara:{match.rule}"),
                implementation=Implementation(library="unknown", provider="yara"),
                context=Context(exposure=Exposure.INTERNAL),
            ))

        return findings