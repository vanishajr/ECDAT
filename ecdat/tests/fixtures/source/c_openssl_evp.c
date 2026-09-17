#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

/* AES-256-GCM bulk encryption (seeded ground truth: Encrypt AES-256-GCM). */
int app_encrypt(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                const unsigned char *iv) {
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
        return 0;
    return 1;
}

int app_decrypt(EVP_CIPHER_CTX *ctx) {
    return EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL);
}

int app_sign(EVP_MD_CTX *mdctx, EVP_PKEY *pkey) {
    if (!EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey))
        return 0;
    return 1;
}

int app_verify(EVP_MD_CTX *mdctx, EVP_PKEY *pkey) {
    return EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
}

int app_gen_rsa(void) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    if (!RSA_generate_key_ex(rsa, 2048, e, NULL))
        return 0;
    return 1;
}

int app_ecdh(EC_KEY *peer) {
    unsigned char secret[32];
    return ECDH_compute_key(secret, sizeof(secret),
                            EC_KEY_get0_public_key(peer), NULL, NULL);
}

SSL_CTX *app_tls(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384");
    return ctx;
}

int app_tls_client(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    return ctx != NULL;
}

int app_rand(unsigned char *buf) {
    return RAND_bytes(buf, 32);
}

int app_hmac(const unsigned char *key, const unsigned char *data) {
    unsigned char out[32];
    unsigned int len = 0;
    return HMAC(EVP_sha256(), key, 32, data, 64, out, &len) ? 1 : 0;
}
