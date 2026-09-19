import hashlib

def digest(data): return hashlib.sha256(data).digest()
