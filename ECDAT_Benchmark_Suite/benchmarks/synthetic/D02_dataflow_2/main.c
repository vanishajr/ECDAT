#include <openssl/evp.h>
void f(EVP_CIPHER_CTX*c,const unsigned char*k,const unsigned char*iv){const EVP_CIPHER*x=EVP_aes_256_gcm();EVP_EncryptInit_ex(c,x,0,k,iv);}