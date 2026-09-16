# TLS/SSL configuration
import ssl
import socket
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_x509_certificate

def create_ssl_context():
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    return context

def load_cert_and_key(cert_path: str, key_path: str):
    with open(cert_path, "rb") as f:
        cert = load_pem_x509_certificate(f.read())
    with open(key_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)
    return cert, private_key

def create_tls_connection(host: str, port: int = 443):
    context = create_ssl_context()
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=True)