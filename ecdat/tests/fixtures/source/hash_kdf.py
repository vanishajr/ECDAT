# Hash functions and KDFs
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import bcrypt
import argon2

def hash_sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hash_sha384(data: bytes) -> bytes:
    return hashlib.sha384(data).digest()

def hash_sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()

def hash_sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def hash_blake2b(data: bytes) -> bytes:
    return hashlib.blake2b(data).digest()

def hash_with_cryptography(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def pbkdf2_derive(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password)

def hkdf_derive(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)

def scrypt_derive(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        n=16384,
        r=8,
        p=1,
    )
    return kdf.derive(password)

def bcrypt_hash(password: bytes) -> bytes:
    return bcrypt.hashpw(password, bcrypt.gensalt())

def argon2_hash(password: bytes) -> bytes:
    ph = argon2.PasswordHasher()
    return ph.hash(password.decode()).encode()