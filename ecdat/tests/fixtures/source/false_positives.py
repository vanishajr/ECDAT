# This file contains comments and strings that mention crypto but don't actually use it

# TODO: Implement AES-256-GCM encryption later
# FIXME: Remove RSA key generation
# NOTE: We use SHA-256 for hashing

def process_data(data: str) -> str:
    """
    This function processes data.
    It mentions AES-GCM and RSA in the docstring but doesn't use them.
    """
    # Configuration string that looks like crypto but isn't
    config = "algorithm=AES-256-GCM;mode=GCM;key_size=256"

    # Variable names that look like crypto
    aes_key = "not-a-real-key"
    rsa_public_key = "not-a-real-key-either"
    sha256_hash = "fake-hash-value"

    # String constants
    cipher_suite = "TLS_AES_256_GCM_SHA384"
    certificate_pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"

    return data.upper()

# Legacy code reference
# old_code = "from Crypto.Cipher import AES"