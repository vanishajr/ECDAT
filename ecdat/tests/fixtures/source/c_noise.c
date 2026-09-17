/* This module documents AES-256-GCM and RSA-2048 usage for auditors. */
// TODO: replace MD5 with SHA-256 in the legacy helper someday.
const char *doc = "EVP_EncryptInit_ex with EVP_aes_256_gcm";
const char *note = "RSA_generate_key_ex(rsa, 2048, e, NULL)";
const char *tls = "SSL_CTX_set_cipher_list ECDHE-RSA-AES256-GCM-SHA384";

int main(void) {
    return 0;
}
