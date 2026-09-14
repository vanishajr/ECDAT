import ast

code = """
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
"""

tree = ast.parse(code)
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef):
        print(f'Function: {node.name}, lines {node.lineno}-{node.end_lineno}')
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                print(f'  Call at line {child.lineno}: {ast.dump(child.func)}')