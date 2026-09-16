from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as AESGCM_Aliased
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as HKDF_Aliased

# Wrapper functions
def my_encrypt(key: bytes, nonce: bytes, plaintext: bytes):
    cipher = AESGCM_Aliased(key)
    return cipher.encrypt(nonce, plaintext, None)

def my_decrypt(key: bytes, nonce: bytes, ciphertext: bytes):
    cipher = AESGCM_Aliased(key)
    return cipher.decrypt(nonce, ciphertext, None)

def my_hash(data: bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def my_kdf(key_material: bytes, salt: bytes, info: bytes):
    hkdf = HKDF_Aliased(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(key_material)

# Using low-level API
def low_level_aes_encrypt(key: bytes, iv: bytes, plaintext: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

# Class that wraps crypto
class CryptoWrapper:
    def __init__(self, key: bytes):
        self._key = key
        self._cipher = AESGCM_Aliased(key)

    def encrypt(self, nonce: bytes, data: bytes):
        return self._cipher.encrypt(nonce, data, None)

    def decrypt(self, nonce: bytes, data: bytes):
        return self._cipher.decrypt(nonce, data, None)