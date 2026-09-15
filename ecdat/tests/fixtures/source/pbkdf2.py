from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import hashlib
import hmac

def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int = 100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)

def pbkdf2_hmac_sha512(password: bytes, salt: bytes, iterations: int = 100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)

def manual_pbkdf2(password: bytes, salt: bytes, iterations: int = 100000):
    return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen=32)