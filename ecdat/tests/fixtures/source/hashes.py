import hashlib
import hmac

def sha256_hash(data: bytes):
    return hashlib.sha256(data).digest()

def sha384_hash(data: bytes):
    return hashlib.sha384(data).digest()

def sha512_hash(data: bytes):
    return hashlib.sha512(data).digest()

def hmac_sha256(key: bytes, data: bytes):
    return hmac.new(key, data, hashlib.sha256).digest()

def hmac_sha512(key: bytes, data: bytes):
    return hmac.new(key, data, hashlib.sha512).digest()