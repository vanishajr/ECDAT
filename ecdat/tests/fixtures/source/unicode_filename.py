# File with unicode in content
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_测试(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)