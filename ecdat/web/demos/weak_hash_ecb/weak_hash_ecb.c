#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

/* Demo: legacy crypto — MD5/SHA-1 digests and AES-ECB.
 * Expected: MD5 + SHA-1 findings (deprecated) and an AES-ECB
 * misuse finding. */
int main(void) {
    unsigned char md5[MD5_DIGEST_LENGTH], sha1[SHA_DIGEST_LENGTH];
    static const unsigned char msg[] = "password";
    MD5(msg, strlen((const char *)msg), md5);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mctx, EVP_sha1(), 0);
    EVP_DigestUpdate(mctx, msg, strlen((const char *)msg));
    EVP_DigestFinal_ex(mctx, sha1, 0);
    EVP_MD_CTX_free(mctx);

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    unsigned char key[16] = {0};
    unsigned char out[64];
    int len = 0;
    EVP_EncryptInit_ex(cctx, EVP_aes_128_ecb(), 0, key, 0);
    EVP_EncryptUpdate(cctx, out, &len, msg, sizeof(msg));
    EVP_CIPHER_CTX_free(cctx);
    printf("md5=%02x sha1=%02x ecb=%d\n", md5[0], sha1[0], len);
    return 0;
}
