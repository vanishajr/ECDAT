#include <openssl/evp.h>
int f(EVP_CIPHER_CTX *ctx,const unsigned char *k,const unsigned char *iv){
  return EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), 0, k, iv);
}