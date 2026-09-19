#include <openssl/evp.h>
int main(){EVP_CIPHER_CTX*c=EVP_CIPHER_CTX_new();unsigned char k[32]={0},iv[12]={0};
EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),0,k,iv);EVP_CIPHER_CTX_free(c);return 0;}