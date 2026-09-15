from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def multi_crypto_usage():
    key = b"0123456789abcdef0123456789abcdef"
    nonce = b"0123456789ab"

    cipher = AESGCM(key)
    ct = cipher.encrypt(nonce, b"secret", None)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signature = private_key.sign(b"message", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"salt", iterations=100000)
    derived = kdf.derive(b"password")

    return ct, signature, derived

from cryptography.hazmat.primitives.asymmetric import padding