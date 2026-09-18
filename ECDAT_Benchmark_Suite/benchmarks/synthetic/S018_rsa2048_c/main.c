#include <openssl/rsa.h>
int f(RSA *rsa, BIGNUM *e){ return RSA_generate_key_ex(rsa, 2048, e, 0); }
