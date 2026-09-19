import hashlib

def checksum(data: bytes):
    return hashlib.md5(data).hexdigest()
