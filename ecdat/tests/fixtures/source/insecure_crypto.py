import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa

def insecure_md5(data: bytes):
    return hashlib.md5(data).digest()

def insecure_sha1(data: bytes):
    return hashlib.sha1(data).digest()

def insecure_des_ecb(key: bytes, data: bytes):
    cipher = Cipher(algorithms.DES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def insecure_3des(key: bytes, data: bytes):
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(b"01234567"))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def weak_rsa_1024():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    return private_key