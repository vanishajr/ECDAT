# File with syntax error - should fallback to regex
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, nonce, data):
    return AESGCM(key).encrypt(nonce, data, None

# Missing closing parenthesis - syntax error
EOF