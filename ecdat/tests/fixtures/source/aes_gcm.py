from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_data(key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes = None):
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, associated_data)

def decrypt_data(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = None):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)