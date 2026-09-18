#include <openssl/evp.h>
int f(EVP_CIPHER_CTX *ctx,const unsigned char *k){
  return EVP_EncryptInit_ex(ctx, EVP_rc4(), 0, k, 0);
}