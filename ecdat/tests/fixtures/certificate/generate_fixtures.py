from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
import os
from pathlib import Path

output_dir = Path(__file__).parent
output_dir.mkdir(parents=True, exist_ok=True)

# Generate RSA key
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_pem = rsa_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
(output_dir / "rsa_key.pem").write_bytes(rsa_pem)

# Generate ECDSA key
ec_key = ec.generate_private_key(ec.SECP256R1())
ec_pem = ec_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
(output_dir / "ec_key.pem").write_bytes(ec_pem)

# Generate Ed25519 key
ed_key = ed25519.Ed25519PrivateKey.generate()
ed_pem = ed_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
(output_dir / "ed25519_key.pem").write_bytes(ed_pem)

# Generate self-signed certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'CA'),
    x509.NameAttribute(NameOID.LOCALITY_NAME, 'San Francisco'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test Org'),
    x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com'),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    rsa_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName('test.example.com')]),
    critical=False,
).sign(rsa_key, hashes.SHA256())

cert_pem = cert.public_bytes(serialization.Encoding.PEM)
(output_dir / "test_cert.pem").write_bytes(cert_pem)

# DER format
(output_dir / "test_cert.der").write_bytes(cert.public_bytes(serialization.Encoding.DER))

# Public key only
(output_dir / "rsa_pubkey.pem").write_bytes(rsa_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
))

# PKCS12
try:
    pkcs12 = serialization.pkcs12.serialize_key_and_certificates(
        name=b"test",
        key=rsa_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.NoEncryption()
    )
    (output_dir / "test.p12").write_bytes(pkcs12)
except AttributeError:
    pass  # PKCS12 not available in this version

print("Certificate fixtures created")