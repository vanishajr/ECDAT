#include <openssl/evp.h>

#define APP_CIPHER EVP_aes_128_cbc

static int raw_encrypt(EVP_CIPHER_CTX *ctx) {
    return EVP_EncryptInit_ex(ctx, APP_CIPHER, NULL, NULL, NULL);
}

int app_api_encrypt(EVP_CIPHER_CTX *ctx) {
    return raw_encrypt(ctx);
}

int unrelated_helper(int x) {
    return x + 1;
}
