#include <stdio.h>
#include "tiny_aes.h"

/* Demo caller: exercises the custom AES implementation above. */
int main(void) {
    struct AES_ctx ctx;
    uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16};
    uint8_t buf[16] = "demo block!!!!!!";
    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, buf);
    printf("ct[0]=%02x\n", buf[0]);
    return 0;
}
