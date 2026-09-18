from argon2 import PasswordHasher
ph=PasswordHasher()
def h(p): return ph.hash(p)
