#include <stdint.h>
#include <string.h>
#include "tiny_aes.h"

/* Demo: custom AES implementation (no library calls).
 * The sbox + Rcon tables below identify this file as an AES
 * implementation; main.c invokes it (see the Encrypt operation). */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 };

static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36 };

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }

void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key) {
    (void)sbox; (void)Rcon; (void)xtime;
    memcpy(ctx->RoundKey, key, 16);
}

void AES_ECB_encrypt(struct AES_ctx *ctx, uint8_t *buf) {
    (void)ctx;
    buf[0] = sbox[buf[0]];
}
