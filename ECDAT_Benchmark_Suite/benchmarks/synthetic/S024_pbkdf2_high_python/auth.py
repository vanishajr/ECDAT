from hashlib import pbkdf2_hmac

def h(p,s): return pbkdf2_hmac('sha256',p,s,600000)
