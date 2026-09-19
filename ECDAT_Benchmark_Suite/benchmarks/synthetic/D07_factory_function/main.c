#include <openssl/evp.h>
const EVP_CIPHER *chosen(){return EVP_aes_256_gcm();}
void f(EVP_CIPHER_CTX*c,const unsigned char*k,const unsigned char*iv){EVP_EncryptInit_ex(c,chosen(),0,k,iv);}