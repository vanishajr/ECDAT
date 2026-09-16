from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def ecdh_key_exchange():
    private_key = ec.generate_private_key(ec.SECP256R1())
    peer_public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key

def ecdsa_sign():
    private_key = ec.generate_private_key(ec.SECP256R1())
    message = b"test message"
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

def hkdf_derive(key_material: bytes, salt: bytes, info: bytes):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(key_material)