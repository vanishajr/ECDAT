#include <openssl/evp.h>
#include <stdlib.h>
void f(){ const char *name=getenv("CIPHER"); EVP_CIPHER_fetch(0,name,0); }