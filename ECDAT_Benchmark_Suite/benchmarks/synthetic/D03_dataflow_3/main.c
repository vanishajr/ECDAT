#include <openssl/evp.h>
void f(EVP_CIPHER_CTX*c,const unsigned char*k,const unsigned char*iv){const EVP_CIPHER*a=EVP_aes_256_gcm();const EVP_CIPHER*b=a;EVP_EncryptInit_ex(c,b,0,k,iv);}