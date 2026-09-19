#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

/* Demo: modern AEAD encryption with OpenSSL EVP.
 * Expected: AES-256-GCM encrypt operation (Confirmed). */
int aes_gcm_encrypt(const unsigned char *key, const unsigned char *iv,
                    const unsigned char *in, int in_len,
                    unsigned char *out, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, out_len = 0;
    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), 0, 0, 0) != 1) return -1;
    if (EVP_EncryptInit_ex(ctx, 0, 0, key, iv) != 1) return -1;
    if (EVP_EncryptUpdate(ctx, out, &len, in, in_len) != 1) return -1;
    out_len = len;
    if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1) return -1;
    out_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) return -1;
    EVP_CIPHER_CTX_free(ctx);
    return out_len;
}

int main(void) {
    unsigned char key[32], iv[12], tag[16];
    static const unsigned char msg[] = "demo message";
    unsigned char out[64];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
    int n = aes_gcm_encrypt(key, iv, msg, (int)strlen((const char *)msg), out, tag);
    printf("encrypted %d bytes\n", n);
    return n < 0;
}
