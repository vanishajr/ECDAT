/* Phase 6 seeded fixture: dynamically linked OpenSSL use + constants.
 * Built by test_binary_stages.py (gcc -lcrypto). Never committed as a
 * binary: compiled fresh into tmp so fixtures stay source-only. */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

/* AES S-box prefix (static-implementation signal, also in .rodata). */
static const unsigned char aes_sbox_prefix[7] =
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f};

static const char *oid_rsa = "1.2.840.113549.1.1.1";

int seal_gcm(const unsigned char *key, const unsigned char *iv,
             const unsigned char *in, unsigned long in_len,
             unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
        return -1;
    if (!EVP_EncryptUpdate(ctx, out, &len, in, (int)in_len))
        return -1;
    printf("sbox %02x oid %s\n", aes_sbox_prefix[0], oid_rsa);
    EVP_CIPHER_CTX_free(ctx);
    return len;
}

int hash_it(const unsigned char *in, unsigned long in_len,
            unsigned char *out) {
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, in, in_len);
    SHA256_Final(out, &sha);
    return 0;
}

int gen_iv(unsigned char *iv) {
    return RAND_bytes(iv, 12);
}

int main(void) {
    unsigned char key[32], iv[12], in[16], out[64], digest[32];
    memset(key, 1, sizeof(key));
    memset(iv, 2, sizeof(iv));
    memset(in, 3, sizeof(in));
    printf("sealed %d\n", seal_gcm(key, iv, in, sizeof(in), out));
    printf("hashed %d rand %d\n", hash_it(in, sizeof(in), digest),
           gen_iv(iv));
    return 0;
}
