# Aliases and wrapper functions
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as AES_GCM
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey as RSA_PrivateKey
from cryptography.hazmat.primitives import hashes as crypto_hashes

# Wrapper functions
def my_encrypt(data_key: bytes, payload: bytes, aad: bytes) -> bytes:
    import os
    nonce = os.urandom(12)
    cipher = AES_GCM(data_key)
    return nonce + cipher.encrypt(nonce, payload, aad)

def my_hash(data: bytes) -> bytes:
    digest = crypto_hashes.Hash(crypto_hashes.SHA256())
    digest.update(data)
    return digest.finalize()

class CryptoWrapper:
    def __init__(self, key: bytes):
        self.cipher = AES_GCM(key)

    def encrypt(self, payload: bytes, aad: bytes) -> bytes:
        import os
        nonce = os.urandom(12)
        return nonce + self.cipher.encrypt(nonce, payload, aad)

    def decrypt(self, ciphertext: bytes, aad: bytes) -> bytes:
        nonce = ciphertext[:12]
        return self.cipher.decrypt(nonce, ciphertext[12:], aad)