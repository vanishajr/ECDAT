"""Registry-driven crypto API knowledge (Phase 4).

Architecture rule: "Registry-driven additions instead of code changes."
Each entry describes one observable crypto API call site. The engines in
:mod:`ecdat.scanners.source.c_parser` and the language routers in
:mod:`ecdat.scanners.source.scanner` interpret these tables; adding a new
library or API means adding rows here, not new scanner code.

Entry fields:
    id: stable row id (traceability).
    langs: language codes this row applies to (c, cpp, java, js, go,
        csharp, rust, py). ``py`` rows are informational: the Python AST
        path stays authoritative for Python.
    re: regex matching the call name (word-boundary anchored by convention).
    call: display name for evidence detail.
    canonical: fixed canonical algorithm, or None when resolved from an
        argument (see ``cipher_arg`` / ``parser``).
    op: OperationType member name (ENCRYPT, DECRYPT, SIGN, VERIFY,
        KEY_EXCHANGE, HASH, KDF, TLS, STORAGE, KEY_MANAGEMENT).
    library: provider/library attribution.
    confidence: direct-call confidence (0.0-1.0).
    cipher_arg: 0-based argument index holding a cipher constructor
        (OpenSSL EVP style); resolved via EVP_CIPHER_TABLE when the
        argument is a literal or a propagated constant.
    parser: extra semantic parser tag (jca-transformation, node-cipher,
        tls-method, int-arg:<index> for key sizes, curve-arg:<index>).
"""

from __future__ import annotations

import re

__all__ = [
    "EVP_CIPHER_TABLE",
    "API_PATTERNS",
    "patterns_for",
    "REGISTRY_VERSION",
    "EXACT_API_INDEX",
    "build_exact_index",
    "lookup_exact",
    "compile_matchers",
    "lex_prefilter",
    "get_matcher_stats",
    "match_type_for",
    "invalidate_matcher_caches",
]

#: Knowledge-registry version for Phase 1/13 matcher caching.
#: Matcher and prefilter caches are keyed by this version so stale
#: analysis is never returned after rules change.
REGISTRY_VERSION = "2026.09.19"

#: OpenSSL EVP cipher constructors -> (canonical, key_size, mode).
EVP_CIPHER_TABLE = {
    "EVP_aes_128_gcm": ("AES-128-GCM", 128, "GCM"),
    "EVP_aes_192_gcm": ("AES-192-GCM", 192, "GCM"),
    "EVP_aes_256_gcm": ("AES-256-GCM", 256, "GCM"),
    "EVP_aes_128_cbc": ("AES-128-CBC", 128, "CBC"),
    "EVP_aes_192_cbc": ("AES-192-CBC", 192, "CBC"),
    "EVP_aes_256_cbc": ("AES-256-CBC", 256, "CBC"),
    "EVP_aes_128_ecb": ("AES-128-ECB", 128, "ECB"),
    "EVP_aes_256_ecb": ("AES-256-ECB", 256, "ECB"),
    "EVP_aes_128_ctr": ("AES-128-CTR", 128, "CTR"),
    "EVP_aes_256_ctr": ("AES-256-CTR", 256, "CTR"),
    "EVP_chacha20": ("ChaCha20", None, None),
    "EVP_chacha20_poly1305": ("ChaCha20-Poly1305", 256, None),
    "EVP_des_ede3_cbc": ("3DES", 168, "CBC"),
    "EVP_des_cbc": ("DES", 56, "CBC"),
    "EVP_bf_cbc": ("Blowfish", 128, "CBC"),
    "EVP_sha224": ("SHA-224", None, None),
    "EVP_sha256": ("SHA-256", None, None),
    "EVP_sha384": ("SHA-384", None, None),
    "EVP_sha512": ("SHA-512", None, None),
    "EVP_sha512_224": ("SHA-512/224", None, None),
    "EVP_sha512_256": ("SHA-512/256", None, None),
    "EVP_sha3_256": ("SHA-3-256", None, None),
    "EVP_sha3_512": ("SHA-3-512", None, None),
    "EVP_md5": ("MD5", None, None),
    "EVP_sha1": ("SHA-1", None, None),
    "EVP_rc4": ("RC4", None, None),
    "EVP_rc4_40": ("RC4", 40, None),
    "EVP_rc2_cbc": ("RC2", None, "CBC"),
    "EVP_des_ecb": ("DES", 56, "ECB"),
    "EVP_des_ede_ecb": ("3DES", 112, "ECB"),
    "EVP_des_ede3_ecb": ("3DES", 168, "ECB"),
    "EVP_des_ede_cbc": ("3DES", 112, "CBC"),
    "EVP_bf_ecb": ("Blowfish", 128, "ECB"),
    "EVP_camellia_128_cbc": ("Camellia", 128, "CBC"),
    "EVP_camellia_256_cbc": ("Camellia", 256, "CBC"),
}

#: Curve-name normalisation across ecosystems.
CURVE_ALIASES = {
    "prime256v1": "P-256", "secp256r1": "P-256", "P-256": "P-256",
    "NID_X9_62_prime256v1": "P-256",
    "secp384r1": "P-384", "P-384": "P-384", "NID_secp384r1": "P-384",
    "secp521r1": "P-521", "P-521": "P-521", "NID_secp521r1": "P-521",
    "nistP256": "P-256", "nistP384": "P-384", "nistP521": "P-521",
}

API_PATTERNS: list[dict] = [
    # -- OpenSSL EVP high level (C/C++) ---------------------------------
    {"id": "ossl-evp-enc-init", "langs": ("c", "cpp"),
     "re": r"\bEVP_EncryptInit_ex2?\b", "call": "EVP_EncryptInit_ex",
     "canonical": None, "cipher_arg": 1, "op": "ENCRYPT",
     "library": "openssl", "confidence": 0.90},
    {"id": "ossl-evp-dec-init", "langs": ("c", "cpp"),
     "re": r"\bEVP_DecryptInit_ex2?\b", "call": "EVP_DecryptInit_ex",
     "canonical": None, "cipher_arg": 1, "op": "DECRYPT",
     "library": "openssl", "confidence": 0.90},
    {"id": "ossl-evp-enc-update", "langs": ("c", "cpp"),
     "re": r"\bEVP_EncryptUpdate\b", "call": "EVP_EncryptUpdate",
     "canonical": None, "cipher_arg": None, "op": "ENCRYPT",
     "library": "openssl", "confidence": 0.75},
    {"id": "ossl-evp-dec-update", "langs": ("c", "cpp"),
     "re": r"\bEVP_DecryptUpdate\b", "call": "EVP_DecryptUpdate",
     "canonical": None, "cipher_arg": None, "op": "DECRYPT",
     "library": "openssl", "confidence": 0.75},
    {"id": "ossl-evp-digest-init", "langs": ("c", "cpp"),
     "re": r"\bEVP_DigestInit_ex2?\b", "call": "EVP_DigestInit_ex",
     "canonical": None, "cipher_arg": 1, "op": "HASH",
     "library": "openssl", "confidence": 0.88},
    {"id": "ossl-evp-sign-init", "langs": ("c", "cpp"),
     "re": r"\bEVP_DigestSignInit\b", "call": "EVP_DigestSignInit",
     "canonical": None, "cipher_arg": 2, "op": "SIGN",
     "library": "openssl", "confidence": 0.88},
    {"id": "ossl-evp-verify-init", "langs": ("c", "cpp"),
     "re": r"\bEVP_DigestVerifyInit\b", "call": "EVP_DigestVerifyInit",
     "canonical": None, "cipher_arg": 2, "op": "VERIFY",
     "library": "openssl", "confidence": 0.88},
    {"id": "ossl-evp-pkey-new", "langs": ("c", "cpp"),
     "re": r"\bEVP_PKEY_new\b", "call": "EVP_PKEY_new",
     "canonical": "OpenSSL", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "openssl", "confidence": 0.65},
    {"id": "ossl-evp-pkey-rsa", "langs": ("c", "cpp"),
     "re": r"\bEVP_PKEY_(?:set1_)?RSA\b", "call": "EVP_PKEY_RSA",
     "canonical": "RSA", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "openssl", "confidence": 0.85},
    {"id": "ossl-evp-pkey-ec", "langs": ("c", "cpp"),
     "re": r"\bEVP_PKEY_(?:set1_)?EC_KEY\b", "call": "EVP_PKEY_EC",
     "canonical": "ECDSA", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "openssl", "confidence": 0.85},
    {"id": "ossl-evp-pkey-derive", "langs": ("c", "cpp"),
     "re": r"\bEVP_PKEY_derive(?:_init|_set_peer)?\b",
     "call": "EVP_PKEY_derive", "canonical": "ECDH", "cipher_arg": None,
     "op": "KEY_EXCHANGE", "library": "openssl", "confidence": 0.85},
    {"id": "ossl-evp-pkey-encrypt", "langs": ("c", "cpp"),
     "re": r"\bEVP_PKEY_(?:encrypt|decrypt|sign|verify|verify_recover)\b",
     "call": "EVP_PKEY_crypt", "canonical": "RSA", "cipher_arg": None,
     "op": "ENCRYPT", "library": "openssl", "confidence": 0.80},
    {"id": "ossl-rsa-generate", "langs": ("c", "cpp"),
     "re": r"\bRSA_generate_key_ex\b", "call": "RSA_generate_key_ex",
     "canonical": "RSA", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "openssl", "confidence": 0.90, "parser": "int-arg:1"},
    {"id": "ossl-rsa-crypt", "langs": ("c", "cpp"),
     "re": r"\bRSA_(?:public_encrypt|private_decrypt)\b",
     "call": "RSA_public_encrypt", "canonical": "RSA", "cipher_arg": None,
     "op": "ENCRYPT", "library": "openssl", "confidence": 0.90},
    {"id": "ossl-rsa-sign", "langs": ("c", "cpp"),
     "re": r"\bRSA_(?:sign|verify)\b", "call": "RSA_sign",
     "canonical": "RSA", "cipher_arg": None, "op": "SIGN",
     "library": "openssl", "confidence": 0.90},
    {"id": "ossl-ec-key", "langs": ("c", "cpp"),
     "re": r"\bEC_KEY_new_by_curve_name\b", "call": "EC_KEY_new_by_curve_name",
     "canonical": "ECDSA", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "openssl", "confidence": 0.88, "parser": "curve-arg:0"},
    {"id": "ossl-ecdh", "langs": ("c", "cpp"),
     "re": r"\b(?:ECDH_compute_key|EVP_PKEY_derive)\b",
     "call": "ECDH_compute_key", "canonical": "ECDH", "cipher_arg": None,
     "op": "KEY_EXCHANGE", "library": "openssl", "confidence": 0.88},
    {"id": "ossl-dh", "langs": ("c", "cpp"),
     "re": r"\bDH_compute_key\b", "call": "DH_compute_key",
     "canonical": "DH", "cipher_arg": None, "op": "KEY_EXCHANGE",
     "library": "openssl", "confidence": 0.88},
    {"id": "ossl-dsa", "langs": ("c", "cpp"),
     "re": r"\bDSA_(?:generate_key|do_sign|do_verify)\b", "call": "DSA_sign",
     "canonical": "DSA", "cipher_arg": None, "op": "SIGN",
     "library": "openssl", "confidence": 0.88},
    {"id": "ossl-hmac", "langs": ("c", "cpp"),
     "re": r"\bHMAC(?:_Init_ex|_Update|_Final)?\s*\(", "call": "HMAC_Init_ex",
     "canonical": "HMAC", "cipher_arg": None, "op": "HASH",
     "library": "openssl", "confidence": 0.85},
    {"id": "ossl-rand", "langs": ("c", "cpp"),
     "re": r"\bRAND_bytes\b", "call": "RAND_bytes",
     "canonical": "Random", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "openssl", "confidence": 0.80},
    {"id": "ossl-pbkdf2", "langs": ("c", "cpp"),
     "re": r"\bPKCS5_PBKDF2_HMAC\b", "call": "PKCS5_PBKDF2_HMAC",
     "canonical": "PBKDF2", "cipher_arg": None, "op": "KDF",
     "library": "openssl", "confidence": 0.88},
    {"id": "ossl-aes-key", "langs": ("c", "cpp"),
     "re": r"\bAES_set_(?:en|de)crypt_key\b", "call": "AES_set_encrypt_key",
     "canonical": "AES", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "openssl", "confidence": 0.85, "parser": "int-arg:1"},
    {"id": "ossl-des-key", "langs": ("c", "cpp"),
     "re": r"\bDES_set_key(?:_checked|_unchecked)?\b", "call": "DES_set_key",
     "canonical": "DES", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "openssl", "confidence": 0.88},
    {"id": "ossl-rc4", "langs": ("c", "cpp"),
     "re": r"\bRC4_set_key\b", "call": "RC4_set_key",
     "canonical": "RC4", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "openssl", "confidence": 0.88},
    {"id": "ossl-sha-init", "langs": ("c", "cpp"),
     "re": r"\bSHA(?P<bits>224|256|384|512)_Init\b", "call": "SHA256_Init",
     "canonical": "SHA-256", "cipher_arg": None, "op": "HASH",
     "library": "openssl", "confidence": 0.88, "parser": "sha-bits"},
    {"id": "ossl-md5-init", "langs": ("c", "cpp"),
     "re": r"\bMD5_Init\b", "call": "MD5_Init",
     "canonical": "MD5", "cipher_arg": None, "op": "HASH",
     "library": "openssl", "confidence": 0.88},
    # -- OpenSSL TLS (C/C++) ------------------------------------------------
    {"id": "ossl-cipher-fetch", "langs": ("c", "cpp"),
     "re": r"\bEVP_CIPHER_fetch\b", "call": "EVP_CIPHER_fetch",
     "canonical": None, "cipher_arg": None, "op": "ENCRYPT",
     "library": "openssl", "confidence": 0.90, "parser": "ossl-fetch-name"},
    {"id": "ossl-digest-fetch", "langs": ("c", "cpp"),
     "re": r"\bEVP_MD_fetch\b", "call": "EVP_MD_fetch",
     "canonical": None, "cipher_arg": None, "op": "HASH",
     "library": "openssl", "confidence": 0.90, "parser": "ossl-fetch-name"},
    {"id": "ossl-ssl-ctx-new", "langs": ("c", "cpp"),
     "re": r"\bSSL_CTX_new\b", "call": "SSL_CTX_new",
     "canonical": "TLS", "cipher_arg": None, "op": "TLS",
     "library": "openssl", "confidence": 0.88, "parser": "tls-method"},
    {"id": "ossl-ssl-connect", "langs": ("c", "cpp"),
     "re": r"\bSSL_(?:connect|accept)\b", "call": "SSL_connect",
     "canonical": "TLS", "cipher_arg": None, "op": "TLS",
     "library": "openssl", "confidence": 0.85},
    {"id": "ossl-ssl-ciphers", "langs": ("c", "cpp"),
     "re": r"\bSSL_CTX_set_cipher_list\b", "call": "SSL_CTX_set_cipher_list",
     "canonical": "TLS", "cipher_arg": None, "op": "TLS",
     "library": "openssl", "confidence": 0.85},
    {"id": "ossl-ssl-ciphersuites", "langs": ("c", "cpp"),
     "re": r"\bSSL_CTX_set_ciphersuites\b", "call": "SSL_CTX_set_ciphersuites",
     "canonical": "TLS", "cipher_arg": None, "op": "TLS",
     "library": "openssl", "confidence": 0.85},
    {"id": "ossl-ssl-proto", "langs": ("c", "cpp"),
     "re": r"\bSSL_CTX_set_(?:min|max)_proto_version\b",
     "call": "SSL_CTX_set_min_proto_version", "canonical": "TLS",
     "cipher_arg": None, "op": "TLS", "library": "openssl",
     "confidence": 0.88, "parser": "tls-version-const"},
    # -- libsodium (C/C++) --------------------------------------------------
    {"id": "sodium-aead-aes", "langs": ("c", "cpp"),
     "re": r"\bcrypto_aead_aes256gcm_(?:encrypt|decrypt)\b",
     "call": "crypto_aead_aes256gcm_encrypt", "canonical": "AES-256-GCM",
     "cipher_arg": None, "op": "ENCRYPT", "library": "libsodium",
     "confidence": 0.92},
    {"id": "sodium-aead-chacha", "langs": ("c", "cpp"),
     "re": r"\bcrypto_aead_chacha20poly1305_ietf_(?:encrypt|decrypt)\b",
     "call": "crypto_aead_chacha20poly1305_encrypt",
     "canonical": "ChaCha20-Poly1305", "cipher_arg": None, "op": "ENCRYPT",
     "library": "libsodium", "confidence": 0.92},
    {"id": "sodium-box", "langs": ("c", "cpp"),
     "re": r"\bcrypto_box_(?:easy|seal|open)\b", "call": "crypto_box_easy",
     "canonical": "XSalsa20-Poly1305", "cipher_arg": None, "op": "ENCRYPT",
     "library": "libsodium", "confidence": 0.88},
    {"id": "sodium-secretbox", "langs": ("c", "cpp"),
     "re": r"\bcrypto_secretbox_(?:easy|open_easy)\b",
     "call": "crypto_secretbox_easy", "canonical": "XSalsa20-Poly1305",
     "cipher_arg": None, "op": "ENCRYPT", "library": "libsodium",
     "confidence": 0.88},
    {"id": "sodium-sign", "langs": ("c", "cpp"),
     "re": r"\bcrypto_sign(?:_detached|_open|_ed25519)?\b",
     "call": "crypto_sign", "canonical": "Ed25519", "cipher_arg": None,
     "op": "SIGN", "library": "libsodium", "confidence": 0.90},
    {"id": "sodium-kx", "langs": ("c", "cpp"),
     "re": r"\bcrypto_kx_(?:client|server)_session_keys\b",
     "call": "crypto_kx_client_session_keys", "canonical": "X25519",
     "cipher_arg": None, "op": "KEY_EXCHANGE", "library": "libsodium",
     "confidence": 0.90},
    {"id": "sodium-pwhash", "langs": ("c", "cpp"),
     "re": r"\bcrypto_pwhash(?:_str|_str_verify)?\b", "call": "crypto_pwhash",
     "canonical": "Argon2", "cipher_arg": None, "op": "KDF",
     "library": "libsodium", "confidence": 0.88},
    {"id": "sodium-hash", "langs": ("c", "cpp"),
     "re": r"\bcrypto_generichash\b", "call": "crypto_generichash",
     "canonical": "BLAKE2b", "cipher_arg": None, "op": "HASH",
     "library": "libsodium", "confidence": 0.88},
    {"id": "sodium-rand", "langs": ("c", "cpp"),
     "re": r"\brandombytes_buf\b", "call": "randombytes_buf",
     "canonical": "Random", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "libsodium", "confidence": 0.80},
    # -- JCA/JCE (Java) ------------------------------------------------------
    {"id": "jca-cipher", "langs": ("java",),
     "re": r"\bCipher\s*\.\s*getInstance\b", "call": "Cipher.getInstance",
     "canonical": "AES", "cipher_arg": None, "op": "ENCRYPT",
     "library": "jca", "confidence": 0.90, "parser": "jca-transformation"},
    {"id": "jca-digest", "langs": ("java",),
     "re": r"\bMessageDigest\s*\.\s*getInstance\b",
     "call": "MessageDigest.getInstance", "canonical": "SHA-256",
     "cipher_arg": None, "op": "HASH", "library": "jca",
     "confidence": 0.90, "parser": "jca-name"},
    {"id": "jca-mac", "langs": ("java",),
     "re": r"\bMac\s*\.\s*getInstance\b", "call": "Mac.getInstance",
     "canonical": "HMAC", "cipher_arg": None, "op": "HASH",
     "library": "jca", "confidence": 0.90, "parser": "jca-name"},
    {"id": "jca-keyagreement", "langs": ("java",),
     "re": r"\bKeyAgreement\s*\.\s*getInstance\b",
     "call": "KeyAgreement.getInstance", "canonical": "ECDH",
     "cipher_arg": None, "op": "KEY_EXCHANGE", "library": "jca",
     "confidence": 0.90, "parser": "jca-name"},
    {"id": "jca-keypair", "langs": ("java",),
     "re": r"\bKeyPairGenerator\s*\.\s*getInstance\b",
     "call": "KeyPairGenerator.getInstance", "canonical": "RSA",
     "cipher_arg": None, "op": "KEY_MANAGEMENT", "library": "jca",
     "confidence": 0.88, "parser": "jca-name"},
    {"id": "jca-signature", "langs": ("java",),
     "re": r"\bSignature\s*\.\s*getInstance\b", "call": "Signature.getInstance",
     "canonical": "ECDSA", "cipher_arg": None, "op": "SIGN",
     "library": "jca", "confidence": 0.90, "parser": "jca-signature"},
    {"id": "jca-keyfactory", "langs": ("java",),
     "re": r"\b(?:SecretKeyFactory|KeyFactory)\s*\.\s*getInstance\b",
     "call": "SecretKeyFactory.getInstance", "canonical": "PBKDF2",
     "cipher_arg": None, "op": "KDF", "library": "jca",
     "confidence": 0.85, "parser": "jca-name"},
    {"id": "jca-ssl", "langs": ("java",),
     "re": r"\bSSLContext\s*\.\s*getInstance\b", "call": "SSLContext.getInstance",
     "canonical": "TLS", "cipher_arg": None, "op": "TLS",
     "library": "jca", "confidence": 0.88, "parser": "jca-name"},
    {"id": "bc-provider", "langs": ("java",),
     "re": r"\bBouncyCastleProvider\s*\(\s*\)", "call": "BouncyCastleProvider",
     "canonical": "BouncyCastle", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "bouncycastle", "confidence": 0.60},
    # -- Node crypto (JavaScript/TypeScript) ---------------------------------
    {"id": "node-cipher", "langs": ("js",),
     "re": r"\bcreateCipheriv\s*\(", "call": "crypto.createCipheriv",
     "canonical": "AES", "cipher_arg": None, "op": "ENCRYPT",
     "library": "node-crypto", "confidence": 0.90, "parser": "node-cipher"},
    {"id": "node-hash", "langs": ("js",),
     "re": r"\bcreateHash\s*\(", "call": "crypto.createHash",
     "canonical": "SHA-256", "cipher_arg": None, "op": "HASH",
     "library": "node-crypto", "confidence": 0.90, "parser": "node-name"},
    {"id": "node-hmac", "langs": ("js",),
     "re": r"\bcreateHmac\s*\(", "call": "crypto.createHmac",
     "canonical": "HMAC", "cipher_arg": None, "op": "HASH",
     "library": "node-crypto", "confidence": 0.90, "parser": "node-name"},
    {"id": "node-keypair", "langs": ("js",),
     "re": r"\bgenerateKeyPairSync\s*\(", "call": "generateKeyPair",
     "canonical": "RSA", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "node-crypto", "confidence": 0.88, "parser": "node-keytype"},
    {"id": "node-ecdh", "langs": ("js",),
     "re": r"\bcreateECDH\s*\(", "call": "crypto.createECDH",
     "canonical": "ECDH", "cipher_arg": None, "op": "KEY_EXCHANGE",
     "library": "node-crypto", "confidence": 0.90, "parser": "node-curve"},
    {"id": "node-pbkdf2", "langs": ("js",),
     "re": r"\bpbkdf2Sync\s*\(", "call": "crypto.pbkdf2Sync",
     "canonical": "PBKDF2", "cipher_arg": None, "op": "KDF",
     "library": "node-crypto", "confidence": 0.88},
    {"id": "node-scrypt", "langs": ("js",),
     "re": r"\bscryptSync\s*\(", "call": "crypto.scryptSync",
     "canonical": "scrypt", "cipher_arg": None, "op": "KDF",
     "library": "node-crypto", "confidence": 0.88},
    # -- WebCrypto (JavaScript/TypeScript) ------------------------------------
    {"id": "webcrypto-op", "langs": ("js",),
     "re": r"\bsubtle\s*\.\s*(encrypt|decrypt|sign|verify)\s*\(",
     "call": "subtle.encrypt", "canonical": "AES", "cipher_arg": None,
     "op": "ENCRYPT", "library": "webcrypto", "confidence": 0.88,
     "parser": "webcrypto-op"},
    {"id": "webcrypto-digest", "langs": ("js",),
     "re": r"\bsubtle\s*\.\s*digest\s*\(", "call": "subtle.digest",
     "canonical": "SHA-256", "cipher_arg": None, "op": "HASH",
     "library": "webcrypto", "confidence": 0.88, "parser": "webcrypto-name"},
    {"id": "webcrypto-derive", "langs": ("js",),
     "re": r"\bsubtle\s*\.\s*derive(?:Key|Bits)\s*\(",
     "call": "subtle.deriveKey", "canonical": "ECDH", "cipher_arg": None,
     "op": "KEY_EXCHANGE", "library": "webcrypto", "confidence": 0.88,
     "parser": "webcrypto-name"},
    # -- Go crypto/* ----------------------------------------------------------
    {"id": "go-aes", "langs": ("go",),
     "re": r"\baes\s*\.\s*NewCipher\s*\(", "call": "aes.NewCipher",
     "canonical": "AES", "cipher_arg": None, "op": "ENCRYPT",
     "library": "go-crypto", "confidence": 0.90},
    {"id": "go-gcm", "langs": ("go",),
     "re": r"\bcipher\s*\.\s*NewGCM(?:WithNonceSize)?\s*\(",
     "call": "cipher.NewGCM", "canonical": "AES-GCM",
     "key_size": None, "mode": "GCM", "cipher_arg": None,
     "op": "ENCRYPT", "library": "go-crypto", "confidence": 0.88},
    {"id": "go-rsa-gen", "langs": ("go",),
     "re": r"\brsa\s*\.\s*GenerateKey\s*\(", "call": "rsa.GenerateKey",
     "canonical": "RSA", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "go-crypto", "confidence": 0.90, "parser": "int-arg:1"},
    {"id": "go-rsa-oaep", "langs": ("go",),
     "re": r"\brsa\s*\.\s*(?:EncryptOAEP|DecryptOAEP)\s*\(",
     "call": "rsa.EncryptOAEP", "canonical": "RSA", "cipher_arg": None,
     "op": "ENCRYPT", "library": "go-crypto", "confidence": 0.90},
    {"id": "go-rsa-pss", "langs": ("go",),
     "re": r"\brsa\s*\.\s*(?:SignPSS|VerifyPSS)\s*\(",
     "call": "rsa.SignPSS", "canonical": "RSA", "cipher_arg": None,
     "op": "SIGN", "library": "go-crypto", "confidence": 0.90},
    {"id": "go-ecdsa", "langs": ("go",),
     "re": r"\becdsa\s*\.\s*GenerateKey\s*\(", "call": "ecdsa.GenerateKey",
     "canonical": "ECDSA", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "go-crypto", "confidence": 0.90, "parser": "go-curve"},
    {"id": "go-ecdh", "langs": ("go",),
     "re": r"\becdh\s*\.\s*(?:P256|P384|P521|X25519)\b",
     "call": "ecdh.P256", "canonical": "ECDH", "cipher_arg": None,
     "op": "KEY_EXCHANGE", "library": "go-crypto", "confidence": 0.90,
     "parser": "go-ecdh-curve"},
    {"id": "go-ed25519", "langs": ("go",),
     "re": r"\bed25519\s*\.\s*(?:GenerateKey|Sign)\s*\(",
     "call": "ed25519.GenerateKey", "canonical": "Ed25519",
     "cipher_arg": None, "op": "SIGN", "library": "go-crypto",
     "confidence": 0.90},
    {"id": "go-hash", "langs": ("go",),
     "re": r"\bsha256\s*\.\s*(?:New|Sum256)\s*\(", "call": "sha256.New",
     "canonical": "SHA-256", "cipher_arg": None, "op": "HASH",
     "library": "go-crypto", "confidence": 0.90},
    {"id": "go-sha512", "langs": ("go",),
     "re": r"\bsha512\s*\.\s*(?:New|Sum512)\s*\(", "call": "sha512.New",
     "canonical": "SHA-512", "cipher_arg": None, "op": "HASH",
     "library": "go-crypto", "confidence": 0.90},
    {"id": "go-hmac", "langs": ("go",),
     "re": r"\bhmac\s*\.\s*New\s*\(", "call": "hmac.New",
     "canonical": "HMAC", "cipher_arg": None, "op": "HASH",
     "library": "go-crypto", "confidence": 0.88},
    {"id": "go-tls", "langs": ("go",),
     "re": r"\btls\s*\.\s*(?:Listen|Dial|LoadX509KeyPair)\b",
     "call": "tls.LoadX509KeyPair", "canonical": "TLS",
     "cipher_arg": None, "op": "TLS", "library": "go-crypto",
     "confidence": 0.85},
    {"id": "go-x509", "langs": ("go",),
     "re": r"\bx509\s*\.\s*CreateCertificate\s*\(", "call": "x509.CreateCertificate",
     "canonical": "X.509", "cipher_arg": None, "op": "STORAGE",
     "library": "go-crypto", "confidence": 0.85},
    # -- .NET cryptography (C#) -----------------------------------------------
    {"id": "dotnet-aes", "langs": ("csharp",),
     "re": r"\bAes\s*\.\s*Create\s*\(", "call": "Aes.Create",
     "canonical": "AES", "cipher_arg": None, "op": "ENCRYPT",
     "library": "dotnet", "confidence": 0.88},
    {"id": "dotnet-rsa", "langs": ("csharp",),
     "re": r"\bRSA\s*\.\s*Create\s*\(", "call": "RSA.Create",
     "canonical": "RSA", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "dotnet", "confidence": 0.88, "parser": "int-arg:0"},
    {"id": "dotnet-ecdsa", "langs": ("csharp",),
     "re": r"\bECDsa\s*\.\s*Create\s*\(", "call": "ECDsa.Create",
     "canonical": "ECDSA", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "dotnet", "confidence": 0.88, "parser": "dotnet-curve"},
    {"id": "dotnet-ecdh", "langs": ("csharp",),
     "re": r"\bECDiffieHellman\s*\.\s*Create\s*\(",
     "call": "ECDiffieHellman.Create", "canonical": "ECDH",
     "cipher_arg": None, "op": "KEY_EXCHANGE", "library": "dotnet",
     "confidence": 0.88},
    {"id": "dotnet-hash", "langs": ("csharp",),
     "re": r"\bSHA(?P<bits>256|384|512)\s*\.\s*Create\s*\(",
     "call": "SHA256.Create", "canonical": "SHA-256",
     "cipher_arg": None, "op": "HASH", "library": "dotnet",
     "confidence": 0.88, "parser": "sha-bits"},
    {"id": "dotnet-hmac", "langs": ("csharp",),
     "re": r"\bHMACSHA(?P<bits>256|512)\s*\(",
     "call": "HMACSHA256", "canonical": "HMAC", "cipher_arg": None,
     "op": "HASH", "library": "dotnet", "confidence": 0.88},
    {"id": "dotnet-pbkdf2", "langs": ("csharp",),
     "re": r"\bRfc2898DeriveBytes(?:\s*\.\s*Pbkdf2)?\s*\(",
     "call": "Rfc2898DeriveBytes",
     "canonical": "PBKDF2", "cipher_arg": None, "op": "KDF",
     "library": "dotnet", "confidence": 0.88},
    # -- RustCrypto / common Rust crates ---------------------------------------
    {"id": "rust-aesgcm", "langs": ("rust",),
     "re": r"\bAes(?:128|256)Gcm\s*::\s*new(?:_from_slice)?\s*\(",
     "call": "Aes256Gcm::new",
     "canonical": "AES-256-GCM", "cipher_arg": None, "op": "ENCRYPT",
     "library": "rustcrypto", "confidence": 0.90, "parser": "rust-aesgcm"},
    {"id": "rust-chacha", "langs": ("rust",),
     "re": r"\bChaCha20Poly1305\s*::\s*new\s*\(", "call": "ChaCha20Poly1305::new",
     "canonical": "ChaCha20-Poly1305", "cipher_arg": None, "op": "ENCRYPT",
     "library": "rustcrypto", "confidence": 0.90},
    {"id": "rust-rsa", "langs": ("rust",),
     "re": r"\bRsaPrivateKey\s*::\s*new\s*\(", "call": "RsaPrivateKey::new",
     "canonical": "RSA", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "rustcrypto", "confidence": 0.88, "parser": "rust-bits"},
    {"id": "rust-ed25519", "langs": ("rust",),
     "re": r"\bSigningKey\s*::\s*(?:generate|from_bytes)\s*\(",
     "call": "SigningKey::generate", "canonical": "Ed25519",
     "cipher_arg": None, "op": "SIGN", "library": "ed25519-dalek",
     "confidence": 0.88},
    {"id": "rust-p256", "langs": ("rust",),
     "re": r"\bSecretKey\s*::\s*random\s*\(", "call": "SecretKey::random",
     "canonical": "ECDSA", "cipher_arg": None, "op": "KEY_MANAGEMENT",
     "library": "p256", "confidence": 0.80, "parser": "rust-curve-hint"},
    {"id": "rust-sha2", "langs": ("rust",),
     "re": r"\bSha(?P<bits>256|384|512)\s*::\s*(?:new|digest)\s*\(",
     "call": "Sha256::new", "canonical": "SHA-256", "cipher_arg": None,
     "op": "HASH", "library": "sha2", "confidence": 0.88,
     "parser": "sha-bits"},
    {"id": "rust-hkdf", "langs": ("rust",),
     "re": r"\bHkdf\s*::\s*new\s*\(", "call": "Hkdf::new",
     "canonical": "HKDF", "cipher_arg": None, "op": "KDF",
     "library": "hkdf", "confidence": 0.88},
    {"id": "rust-argon2", "langs": ("rust",),
     "re": r"\bArgon2\s*::\s*(?:default|new)\s*\(", "call": "Argon2::default",
     "canonical": "Argon2", "cipher_arg": None, "op": "KDF",
     "library": "argon2", "confidence": 0.88},
    {"id": "rust-x25519", "langs": ("rust",),
     "re": r"\bStaticSecret\s*::\s*random_from_rng\s*\(",
     "call": "StaticSecret::random_from_rng", "canonical": "X25519",
     "cipher_arg": None, "op": "KEY_EXCHANGE", "library": "x25519-dalek",
     "confidence": 0.88},
]


def patterns_for(lang: str) -> list[dict]:
    """Return knowledge rows for one language code (deterministic order)."""
    lang = str(lang or "").strip().lower()
    return [row for row in API_PATTERNS if lang in row["langs"]]


def _evp_ctor_rows() -> list[dict]:
    """Direct references to EVP cipher/digest constructors (OpenSSL).

    ``EVP_aes_256_gcm()`` and friends are semantic evidence on their own
    (the roadmap names ``EVP_aes_*`` explicitly); the operation follows
    the primitive family, resolved with the cipher table.
    """
    rows: list[dict] = []
    for ctor, (canonical, _key, _mode) in sorted(EVP_CIPHER_TABLE.items()):
        if ctor.startswith("EVP_sha") or ctor in ("EVP_md5", "EVP_sha1"):
            op = "HASH"
        elif "hmac" in ctor:
            op = "HASH"
        else:
            op = "ENCRYPT"
        rows.append({
            "id": f"ossl-evp-ctor-{ctor.lower()}", "langs": ("c", "cpp"),
            "re": r"\b" + ctor + r"\b", "call": ctor,
            "canonical": canonical, "key_size": _key, "mode": _mode,
            "cipher_arg": None, "op": op,
            "library": "openssl", "confidence": 0.88,
        })
    return rows


API_PATTERNS.extend(_evp_ctor_rows())


# ---------------------------------------------------------------------------
# Phase 1 — cheaper candidate detection (additive, backward compatible).
#
# Exact symbol lookup first, regex only when actually required, one
# combined lexical prefilter, matchers compiled once per
# (language, REGISTRY_VERSION). Exact lookup is verified against the
# same compiled regexes so it produces the same semantic result as the
# regex fallback (first-row-wins order of patterns_for()).
# ---------------------------------------------------------------------------

#: Parsers whose semantics depend on a string literal argument.
_STRING_PARAM_PARSERS = frozenset({
    "jca-transformation", "jca-name", "jca-signature",
    "node-cipher", "node-name", "node-curve", "node-keytype",
    "webcrypto-op", "webcrypto-name",
})

#: Per-language exact token -> rows (built lazily, in patterns_for order).
EXACT_API_INDEX: dict[str, dict[str, list[dict]]] = {}

_MATCHER_CACHE: dict[tuple[str, str, int], list[tuple[dict, "re.Pattern[str]"]]] = {}
_PREFILTER_CACHE: dict[tuple[str, str, int], "re.Pattern[str]"] = {}
_COMPILE_COUNT = 0
_PREFILTER_COMPILE_COUNT = 0


def _strip_call_suffix(pattern: str) -> str:
    """Remove trailing call anchor (``\\b`` or ``\\s*(``...) from a pattern."""
    p = pattern.strip()
    idx = p.rfind("\\s*\\(")
    if idx != -1:
        suffix = p[idx:]
        # Only a call suffix: backslashes, s/*, parens, whitespace, \b.
        if re.fullmatch(r"(?:\\s\*|\\b|\\\(|\\\)|\(|\)|\s)*", suffix):
            p = p[:idx]
    if p.endswith(r"\b"):
        p = p[: -len(r"\b")]
    return p


def _expand_alternations(expr: str, limit: int = 64) -> list[str] | None:
    """Expand ``(a|b)`` groups and trailing ``X?`` optionals.

    Returns None when the expression still holds regex constructs that
    cannot be enumerated as concrete symbol names.
    """
    results = [expr]
    # Expand parenthesised groups (innermost first via loop).
    while True:
        progressed = False
        next_results: list[str] = []
        for item in results:
            open_idx = item.find("(")
            if open_idx == -1:
                next_results.append(item)
                continue
            # Find matching close paren (no nesting left unhandled:
            # process innermost by taking the LAST open paren).
            open_idx = item.rfind("(")
            close_idx = item.find(")", open_idx)
            if close_idx == -1:
                return None
            inner = item[open_idx + 1: close_idx]
            after = item[close_idx + 1:]
            optional = after.startswith("?")
            rest = after[1:] if optional else after
            # Named-group prefix like ?P<bits> lives inside inner.
            if inner.startswith("?P<"):
                gt = inner.find(">")
                if gt == -1:
                    return None
                inner = inner[gt + 1:]
            if "|" in inner:
                alts = inner.split("|")
            else:
                alts = [inner]
            for alt in alts:
                next_results.append(item[:open_idx] + alt + rest)
            if optional:
                # The empty alternative (group absent).
                next_results.append(item[:open_idx] + rest)
            progressed = True
            if len(next_results) > limit:
                return None
        results = next_results
        if not progressed:
            break
        if len(results) > limit:
            return None
    # Expand single-character optionals such as ``ex2?``.
    final: list[str] = []
    for item in results:
        m = re.search(r"([A-Za-z0-9_])\?", item)
        if m:
            ch = m.group(1)
            start = m.start(0)
            final.append(item[:start] + rest_of(item, start))
            final.append(item[:start] + ch + rest_of(item, start))
        else:
            final.append(item)
        if len(final) > limit:
            return None
    # Validate: only concrete symbol characters remain.
    cleaned: list[str] = []
    for item in final:
        if re.search(r"[\[\]{}*+?^$|()\\]", item):
            return None
        if not re.fullmatch(r"[A-Za-z_][\w\.:]*", item):
            return None
        cleaned.append(item)
    # Deduplicate, deterministic order.
    seen: set[str] = set()
    ordered: list[str] = []
    for name in cleaned:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return sorted(ordered)


def rest_of(item: str, start: int) -> str:
    """Remainder of ``item`` after a two-char ``X?`` at ``start``."""
    return item[start + 2:]


def _extract_exact_names(pattern: str) -> list[str] | None:
    """Enumerate concrete symbol names for a row regex, or None.

    Normalises ``\\b``, ``\\.``/``\\s*`` dotted and ``::`` separators
    and trailing call parens, then expands finite alternations and
    optionals. Returns None for genuinely dynamic patterns.
    """
    try:
        p = str(pattern or "")
    except Exception:
        return None
    if not p:
        return None
    if p.startswith(r"\b"):
        p = p[len(r"\b"):]
    p = _strip_call_suffix(p)
    # Normalise separators to their literal form.
    p = p.replace(r"\s*\.\s*", ".")
    p = p.replace(r"\s*::\s*", "::")
    p = p.replace(r"\.", ".")
    p = p.replace("(?:", "(")
    p = re.sub(r"\(\?P<\w+>", "(", p)
    p = p.replace(" ", "")
    if not p:
        return None
    return _expand_alternations(p)


def match_type_for(row: dict) -> str:
    """Derive a Phase 1 match type for one knowledge row.

    One of ``constructor`` (EVP ctor evidence), ``string-parameter``
    (algorithm comes from a string literal), ``exact`` (single
    concrete symbol), ``prefix`` (finite optional-variant family) or
    ``regex`` (dynamic pattern, regex fallback required).
    """
    try:
        rid = str(row.get("id", "") or "")
    except Exception:
        rid = ""
    if rid.startswith("ossl-evp-ctor-"):
        return "constructor"
    try:
        parser = str(row.get("parser", "") or "")
    except Exception:
        parser = ""
    if parser in _STRING_PARAM_PARSERS:
        return "string-parameter"
    names = _extract_exact_names(str(row.get("re", "") or ""))
    if names is None:
        return "regex"
    if len(names) == 1:
        return "exact"
    return "prefix"


def _assign_match_types() -> None:
    for row in API_PATTERNS:
        try:
            row["match_type"] = match_type_for(row)
        except Exception:
            row["match_type"] = "regex"


def build_exact_index() -> dict[str, dict[str, list[dict]]]:
    """Build (and install) the per-language exact-token index.

    Each token maps to rows in :func:`patterns_for` order so exact
    lookup reproduces the regex fallback's first-row-wins semantics.
    """
    global EXACT_API_INDEX
    index: dict[str, dict[str, list[dict]]] = {}
    order = {str(r.get("id", "")): i for i, r in enumerate(API_PATTERNS)}
    for row in API_PATTERNS:
        names = _extract_exact_names(str(row.get("re", "") or ""))
        if not names:
            continue
        try:
            langs = tuple(row.get("langs", ()) or ())
        except Exception:
            continue
        for lang in langs:
            lang_key = str(lang or "").strip().lower()
            if not lang_key:
                continue
            bucket = index.setdefault(lang_key, {})
            for token in names:
                bucket.setdefault(token, [])
                if all(existing.get("id") != row.get("id")
                       for existing in bucket[token]):
                    bucket[token].append(row)
    for bucket in index.values():
        for token, rows in bucket.items():
            rows.sort(key=lambda r: order.get(str(r.get("id", "")), 1 << 30))
    EXACT_API_INDEX = index
    return index


def _rows_for(lang: str) -> list[dict]:
    lang_key = str(lang or "").strip().lower()
    return [row for row in API_PATTERNS if lang_key in row.get("langs", ())]


def compile_matchers(lang: str) -> list[tuple[dict, "re.Pattern[str]"]]:
    """Return cached ``(row, compiled_regex)`` pairs for one language.

    Compiled once per ``(language, REGISTRY_VERSION, row count)``;
    repeated calls return the same list object (single compilation).
    """
    global _COMPILE_COUNT
    lang_key = str(lang or "").strip().lower()
    rows = _rows_for(lang_key)
    key = (lang_key, REGISTRY_VERSION, len(rows))
    hit = _MATCHER_CACHE.get(key)
    if hit is not None:
        return hit
    compiled: list[tuple[dict, "re.Pattern[str]"]] = []
    for row in rows:
        try:
            rx = re.compile(str(row.get("re", "")))
        except re.error:
            continue
        compiled.append((row, rx))
    _MATCHER_CACHE[key] = compiled
    _COMPILE_COUNT += 1
    return compiled


def lookup_exact(name: str, lang: str) -> list[dict]:
    """Exact token lookup for a call-site name (verified, ordered).

    Tries the full name plus dotted/``::`` suffixes (``crypto.subtle.
    encrypt`` also finds ``subtle.encrypt``), keeps
    :func:`patterns_for` order, and verifies every candidate with its
    cached compiled regex against ``name + "("`` — the same probe the
    scanner's regex fallback uses. Returns ``[]`` when nothing matches
    (caller falls back to the regex rows).
    """
    if not name or not lang:
        return []
    lang_key = str(lang or "").strip().lower()
    probe_name = str(name)
    index = EXACT_API_INDEX or build_exact_index()
    bucket = index.get(lang_key, {})
    if not bucket:
        return []
    variants: list[str] = [probe_name]
    # Suffix variants preserving original separators: "foo.A::new"
    # yields "A::new" and "new" so both "." and "::" tokens match.
    for match in re.finditer(r"(?:\.|::)", probe_name):
        suffix = probe_name[match.end():]
        if suffix and suffix not in variants:
            variants.append(suffix)
    # Bare base segment (after the last separator run).
    base = re.split(r"(?:\.|::)", probe_name)[-1]
    if base and base not in variants:
        variants.append(base)
    candidates: list[dict] = []
    seen: set[str] = set()
    for variant in variants:
        for row in bucket.get(variant, []):
            rid = str(row.get("id", ""))
            if rid and rid not in seen:
                seen.add(rid)
                candidates.append(row)
    if not candidates:
        return []
    order = {str(r.get("id", "")): i for i, r in enumerate(_rows_for(lang_key))}
    candidates.sort(key=lambda r: order.get(str(r.get("id", "")), 1 << 30))
    compiled_map = {str(r.get("id", "")): rx for r, rx in compile_matchers(lang_key)}
    probe = probe_name + "("
    verified: list[dict] = []
    for row in candidates:
        rx = compiled_map.get(str(row.get("id", "")))
        if rx is None:
            continue
        try:
            if rx.search(probe):
                verified.append(row)
        except re.error:
            continue
    return verified


def lex_prefilter(text: str, lang: str) -> bool:
    """Cheap single-regex triage: True when crypto APIs may be present.

    One combined regex per ``(language, REGISTRY_VERSION)`` over all
    row patterns. Blank/masked regions never match by construction
    (callers pass masked source); False simply skips call extraction.
    """
    lang_key = str(lang or "").strip().lower()
    if not text:
        return False
    rows = _rows_for(lang_key)
    if not rows:
        return False
    global _PREFILTER_COMPILE_COUNT
    key = (lang_key, REGISTRY_VERSION, len(rows))
    rx = _PREFILTER_CACHE.get(key)
    if rx is None:
        combo = "|".join(f"(?:{row.get('re', '')})" for row in rows)
        try:
            rx = re.compile(combo)
        except re.error:
            # Fall back to alternation of exact tokens.
            tokens: list[str] = []
            for row in rows:
                for token in (_extract_exact_names(str(row.get("re", ""))) or []):
                    tokens.append(re.escape(token))
            rx = re.compile("|".join(sorted(set(tokens))) or "(?!)")
        _PREFILTER_CACHE[key] = rx
        _PREFILTER_COMPILE_COUNT += 1
    try:
        return rx.search(text) is not None
    except re.error:
        return True


def get_matcher_stats() -> dict:
    """Matcher/prefilter telemetry (compile-once verification)."""
    lang_set = sorted({str(l).lower() for r in API_PATTERNS
                       for l in (r.get("langs", ()) or ())})
    type_counts: dict[str, int] = {}
    for row in API_PATTERNS:
        mt = str(row.get("match_type", "") or "unknown")
        type_counts[mt] = type_counts.get(mt, 0) + 1
    exact_tokens = sum(len(bucket) for bucket in EXACT_API_INDEX.values())
    return {
        "registry_version": REGISTRY_VERSION,
        "compile_calls": _COMPILE_COUNT,
        "prefilter_compiles": _PREFILTER_COMPILE_COUNT,
        "cached_matchers": sorted(f"{lang}@{ver}:{n}" for (lang, ver, n)
                                  in _MATCHER_CACHE),
        "cached_prefilters": sorted(f"{lang}@{ver}:{n}" for (lang, ver, n)
                                    in _PREFILTER_CACHE),
        "languages": lang_set,
        "rows": len(API_PATTERNS),
        "exact_tokens": exact_tokens,
        "exact_langs": sorted(EXACT_API_INDEX),
        "match_types": type_counts,
    }


def invalidate_matcher_caches() -> None:
    """Drop compiled matcher/prefilter caches (tests, registry edits)."""
    global _COMPILE_COUNT, _PREFILTER_COMPILE_COUNT
    _MATCHER_CACHE.clear()
    _PREFILTER_CACHE.clear()
    _COMPILE_COUNT = 0
    _PREFILTER_COMPILE_COUNT = 0


_assign_match_types()
build_exact_index()
