# X25519 and Ed25519 operations
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def generate_x25519_key_pair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def x25519_key_exchange(private_key, peer_public_key) -> bytes:
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

def generate_ed25519_key_pair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def ed25519_sign(private_key, message: bytes) -> bytes:
    signature = private_key.sign(message)
    return signature

def ed25519_verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        return False