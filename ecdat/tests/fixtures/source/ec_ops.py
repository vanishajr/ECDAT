# ECDSA and ECDH operations
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_ec_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def ecdsa_sign(private_key, message: bytes) -> bytes:
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

def ecdsa_verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def ecdh_key_exchange(private_key, peer_public_key) -> bytes:
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key