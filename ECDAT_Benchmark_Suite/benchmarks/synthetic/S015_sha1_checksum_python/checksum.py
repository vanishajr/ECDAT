import hashlib

def object_id(data): return hashlib.sha1(data).hexdigest()
