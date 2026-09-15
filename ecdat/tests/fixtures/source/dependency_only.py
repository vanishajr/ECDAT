# File with only imports - no actual crypto usage
import cryptography
import OpenSSL
import bcrypt
import argon2
import hashlib
import secrets

# These are just imports, no actual usage
cryptography.hazmat.primitives.ciphers.aead.AESGCM
OpenSSL.crypto
bcrypt.hashpw
argon2.PasswordHasher
hashlib.sha256
secrets.token_bytes

# But no function calls or actual operations
def dummy_function():
    pass