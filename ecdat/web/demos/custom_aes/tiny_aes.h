#pragma once
#include <stdint.h>

struct AES_ctx {
    uint8_t RoundKey[32];
};

void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);
void AES_ECB_encrypt(struct AES_ctx *ctx, uint8_t *buf);
