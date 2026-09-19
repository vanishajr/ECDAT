#include <openssl/evp.h>
void encrypt(EVP_CIPHER_CTX*c,const unsigned char*k,const unsigned char*iv){EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),0,k,iv);}