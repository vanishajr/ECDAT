# File with duplicate AES-GCM calls in same function - should deduplicate
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_twice(key, nonce, data):
    result1 = AESGCM(key).encrypt(nonce, data, None)
    result2 = AESGCM(key).encrypt(nonce, data, None)
    return result1, result2