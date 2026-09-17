"""Shared crypto package knowledge (Phase 5).

Single source of truth for dependency-to-crypto mapping, previously
inlined in ``dependency/scanner.py`` (and expected, but missing, by the
Syft integration). Three views over one vocabulary:

- ``CRYPTO_PACKAGES``: flat ``{package_key: info}`` for manifest/import
  matching (moved verbatim from DependencyScanner, plus native C/C++
  libraries: wolfSSL, mbedTLS, libsodium, Crypto++, Botan, GnuTLS, NSS,
  BouncyCastle).
- ``CRYPTO_CAPABILITIES``: library canonical -> provided algorithms.
  A dependency finding stays ONE ProvidedOnly finding; the capability
  list rides in context notes (``provides=...``) for graph enrichment
  (Phase 9) instead of exploding into per-algorithm findings.
- ``SYFT_CRYPTO_PACKAGES``: ``{ecosystem: {name: info}}`` view consumed
  by the Syft integration (references the same info dicts, no copies).
"""

from __future__ import annotations

__all__ = [
    "CRYPTO_PACKAGES",
    "CRYPTO_CAPABILITIES",
    "SYFT_CRYPTO_PACKAGES",
    "capabilities_for",
]

CRYPTO_PACKAGES = {
    "cryptography": {"canonical": "cryptography", "category": "library", "confidence": 0.6},
    "pycryptodome": {"canonical": "cryptography", "category": "library", "confidence": 0.6},
    "pycryptodomex": {"canonical": "cryptography", "category": "library", "confidence": 0.6},
    "pyopenssl": {"canonical": "OpenSSL", "category": "library", "confidence": 0.6},
    "openssl": {"canonical": "OpenSSL", "category": "library", "confidence": 0.6},
    "libcrypto": {"canonical": "OpenSSL", "category": "library", "confidence": 0.6},
    "libssl": {"canonical": "OpenSSL", "category": "library", "confidence": 0.6},
    "boringssl": {"canonical": "BoringSSL", "category": "library", "confidence": 0.6},
    "libressl": {"canonical": "LibreSSL", "category": "library", "confidence": 0.6},
    "bcrypt": {"canonical": "bcrypt", "category": "kdf", "confidence": 0.55},
    "argon2": {"canonical": "Argon2", "category": "kdf", "confidence": 0.55},
    "argon2-cffi": {"canonical": "Argon2", "category": "kdf", "confidence": 0.55},
    "passlib": {"canonical": "PBKDF2", "category": "kdf", "confidence": 0.55},
    "scrypt": {"canonical": "scrypt", "category": "kdf", "confidence": 0.55},
    "hkdf": {"canonical": "HKDF", "category": "kdf", "confidence": 0.55},
    "pqcrypto": {"canonical": "ML-KEM", "category": "pqc_kem", "confidence": 0.55},
    "liboqs": {"canonical": "ML-KEM", "category": "pqc_kem", "confidence": 0.55},
    "oqs": {"canonical": "ML-KEM", "category": "pqc_kem", "confidence": 0.55},
    "cryptography-hazmat": {"canonical": "cryptography", "category": "library", "confidence": 0.6},
    "paramiko": {"canonical": "SSH", "category": "protocol", "confidence": 0.55},
    "ssh": {"canonical": "SSH", "category": "protocol", "confidence": 0.55},
    "requests": {"canonical": "TLS1.2", "category": "protocol", "confidence": 0.4},
    "urllib3": {"canonical": "TLS1.2", "category": "protocol", "confidence": 0.4},
    "aiohttp": {"canonical": "TLS1.2", "category": "protocol", "confidence": 0.4},
    "httpx": {"canonical": "TLS1.2", "category": "protocol", "confidence": 0.4},
    "ssl": {"canonical": "TLS1.2", "category": "protocol", "confidence": 0.3},
    "certifi": {"canonical": "TLS1.2", "category": "protocol", "confidence": 0.3},
    "pyjwt": {"canonical": "pyjwt", "category": "library", "confidence": 0.5},
    "jose": {"canonical": "jose", "category": "library", "confidence": 0.5},
    "python-jose": {"canonical": "python-jose", "category": "library", "confidence": 0.5},
    "authlib": {"canonical": "authlib", "category": "library", "confidence": 0.5},
    "cryptography-vectors": {"canonical": "cryptography", "category": "library", "confidence": 0.3},
    "crypto": {"canonical": "crypto", "category": "library", "confidence": 0.5},
    "crypto-js": {"canonical": "crypto-js", "category": "library", "confidence": 0.5},
    "jsonwebtoken": {"canonical": "jsonwebtoken", "category": "library", "confidence": 0.5},
    # -- native C/C++ ecosystems (Phase 5) ---------------------------------
    "wolfssl": {"canonical": "wolfSSL", "category": "library", "confidence": 0.6},
    "mbed" + "tls": {"canonical": "mbedTLS", "category": "library", "confidence": 0.6},
    "mbedcrypto": {"canonical": "mbedTLS", "category": "library", "confidence": 0.6},
    "mbedx509": {"canonical": "mbedTLS", "category": "library", "confidence": 0.6},
    "libsodium": {"canonical": "libsodium", "category": "library", "confidence": 0.6},
    "sodium": {"canonical": "libsodium", "category": "library", "confidence": 0.6},
    "libsodium-wrappers": {"canonical": "libsodium", "category": "library", "confidence": 0.55},
    "cryptopp": {"canonical": "CryptoPP", "category": "library", "confidence": 0.6},
    "crypto++": {"canonical": "CryptoPP", "category": "library", "confidence": 0.6},
    "botan": {"canonical": "Botan", "category": "library", "confidence": 0.6},
    "gnutls": {"canonical": "GnuTLS", "category": "library", "confidence": 0.6},
    "nss": {"canonical": "NSS", "category": "library", "confidence": 0.6},
    "bouncycastle": {"canonical": "BouncyCastle", "category": "library", "confidence": 0.6},
    "bcprov-jdk": {"canonical": "BouncyCastle", "category": "library", "confidence": 0.6},
    "bcpkix-jdk": {"canonical": "BouncyCastle", "category": "library", "confidence": 0.6},
    "tink": {"canonical": "Tink", "category": "library", "confidence": 0.6},
}

#: Library canonical -> algorithms it can provide (capability, not use).
CRYPTO_CAPABILITIES = {
    "OpenSSL": ("RSA", "DSA", "DH", "ECDH", "ECDSA", "Ed25519", "X25519",
                "AES", "ChaCha20-Poly1305", "DES", "3DES", "MD5", "SHA-1",
                "SHA-256", "TLS"),
    "BoringSSL": ("RSA", "ECDH", "ECDSA", "X25519", "Ed25519", "AES",
                  "ChaCha20-Poly1305", "SHA-256", "TLS"),
    "LibreSSL": ("RSA", "DSA", "DH", "ECDH", "ECDSA", "AES",
                 "ChaCha20-Poly1305", "SHA-256", "TLS"),
    "cryptography": ("RSA", "DSA", "DH", "ECDH", "ECDSA", "Ed25519",
                     "X25519", "AES", "ChaCha20-Poly1305", "MD5", "SHA-1",
                     "SHA-256", "PBKDF2", "HKDF", "scrypt"),
    "pycryptodome": ("RSA", "DSA", "ECC", "AES", "DES", "3DES", "ARC4",
                     "ChaCha20", "MD5", "SHA-1", "SHA-256", "PBKDF2"),
    "libsodium": ("X25519", "Ed25519", "ChaCha20-Poly1305",
                  "XSalsa20-Poly1305", "BLAKE2b", "Argon2"),
    "wolfSSL": ("RSA", "ECDH", "ECDSA", "AES", "ChaCha20-Poly1305",
                "SHA-256", "TLS"),
    "mbedTLS": ("RSA", "ECDH", "ECDSA", "AES", "SHA-256", "TLS"),
    "Botan": ("RSA", "ECDH", "ECDSA", "AES", "SHA-256", "TLS"),
    "CryptoPP": ("RSA", "DSA", "ECDH", "ECDSA", "AES", "SHA-256"),
    "GnuTLS": ("RSA", "ECDH", "ECDSA", "AES", "TLS"),
    "NSS": ("RSA", "ECDH", "ECDSA", "AES", "SHA-256", "TLS"),
    "BouncyCastle": ("RSA", "DSA", "DH", "ECDH", "ECDSA", "Ed25519",
                     "AES", "SHA-256", "TLS"),
    "Tink": ("AES", "ChaCha20-Poly1305", "ECDSA", "Ed25519", "HKDF"),
}

#: Ecosystem-nested view for the Syft integration (same info dicts).
SYFT_CRYPTO_PACKAGES = {
    "pypi": {k: v for k, v in CRYPTO_PACKAGES.items()},
    "npm": {k: v for k, v in CRYPTO_PACKAGES.items()
            if k in ("crypto", "crypto-js", "jsonwebtoken", "jose",
                     "libsodium-wrappers", "openssl")},
    "cargo": {k: v for k, v in CRYPTO_PACKAGES.items()
              if k in ("openssl",)},
    "go": {k: v for k, v in CRYPTO_PACKAGES.items()
           if k in ("openssl",)},
    "maven": {k: v for k, v in CRYPTO_PACKAGES.items()
              if k in ("bouncycastle", "bcprov-jdk", "bcpkix-jdk")},
    "gradle": {k: v for k, v in CRYPTO_PACKAGES.items()
               if k in ("bouncycastle", "bcprov-jdk", "bcpkix-jdk")},
    "rubygems": {k: v for k, v in CRYPTO_PACKAGES.items()},
    "composer": {k: v for k, v in CRYPTO_PACKAGES.items()},
    "apk": {"openssl": CRYPTO_PACKAGES["openssl"],
            "libcrypto": CRYPTO_PACKAGES["libcrypto"],
            "libssl": CRYPTO_PACKAGES["libssl"],
            "libsodium": CRYPTO_PACKAGES["libsodium"],
            "gnutls": CRYPTO_PACKAGES["gnutls"]},
    "dpkg": {"openssl": CRYPTO_PACKAGES["openssl"],
             "libssl": CRYPTO_PACKAGES["libssl"],
             "libcrypto": CRYPTO_PACKAGES["libcrypto"],
             "libsodium": CRYPTO_PACKAGES["libsodium"],
             "gnutls": CRYPTO_PACKAGES["gnutls"]},
    "rpm": {"openssl": CRYPTO_PACKAGES["openssl"],
            "libsodium": CRYPTO_PACKAGES["libsodium"]},
}


def capabilities_for(name: str | None) -> tuple[str, ...]:
    """Provided algorithms for a package key or canonical name."""
    if not name:
        return ()
    key = str(name).strip().lower()
    info = CRYPTO_PACKAGES.get(key)
    candidates = [key]
    if info:
        candidates.append(str(info.get("canonical", "")).strip().lower())
    for candidate in candidates:
        for canonical, algos in CRYPTO_CAPABILITIES.items():
            if candidate == canonical.lower():
                return algos
    return ()
