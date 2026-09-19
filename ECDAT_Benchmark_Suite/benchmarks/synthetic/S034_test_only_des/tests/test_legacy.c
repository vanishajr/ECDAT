#include <openssl/evp.h>
int test(EVP_CIPHER_CTX *ctx,const unsigned char*k,const unsigned char*iv){
  return EVP_EncryptInit_ex(ctx,EVP_des_cbc(),0,k,iv);
}