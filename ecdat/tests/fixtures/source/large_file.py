# Large file with many crypto calls - for performance testing
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def func_0(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)

def func_1(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)

def func_2(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)

def func_3(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)

def func_4(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)

def func_5(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)

def func_6(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)

def func_7(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)

def func_8(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)

def func_9(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None)

def rsa_func_0():
    return rsa.generate_private_key(65537, 2048)

def rsa_func_1():
    return rsa.generate_private_key(65537, 2048)

def ec_func_0():
    return ec.generate_private_key(ec.SECP256R1())

def ec_func_1():
    return ec.generate_private_key(ec.SECP256R1())

def hash_func_0(data):
    return hashes.Hash(hashes.SHA256()).update(data).finalize()

def hash_func_1(data):
    return hashes.Hash(hashes.SHA384()).update(data).finalize()

def kdf_func_0(password, salt):
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, 100000).derive(password)

def hkdf_func_0(ikm, salt, info):
    return HKDF(hashes.SHA256(), 32, salt, info).derive(ikm)