#include "aes.h"
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* AES forward S-box                                                    */
/* ------------------------------------------------------------------ */
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* ------------------------------------------------------------------ */
/* AES inverse S-box                                                    */
/* ------------------------------------------------------------------ */
static const uint8_t inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/*
 * Rcon values for AES-256 key schedule.
 * Indices 1-7 are used (i/8 for i = 8,16,24,32,40,48,56).
 */
static const uint8_t rcon[8] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40
};

/* ------------------------------------------------------------------ */
/* GF(2^8) multiply                                                     */
/* ------------------------------------------------------------------ */
static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t carry = a & 0x80;
        a <<= 1;
        if (carry) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

/* ------------------------------------------------------------------ */
/* AES-256 key expansion (Nk=8, Nr=14, 60 words = 240 bytes)           */
/* ------------------------------------------------------------------ */
static void key_expansion(const uint8_t *key, uint8_t *rk)
{
    memcpy(rk, key, 32);

    for (int i = 8; i < 60; i++) {
        uint8_t temp[4];
        memcpy(temp, rk + (i - 1) * 4, 4);

        if (i % 8 == 0) {
            /* RotWord + SubWord + Rcon */
            uint8_t t   = sbox[temp[1]];
            temp[1]     = sbox[temp[2]];
            temp[2]     = sbox[temp[3]];
            temp[3]     = sbox[temp[0]];
            temp[0]     = t ^ rcon[i / 8];
        } else if (i % 8 == 4) {
            /* SubWord only */
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }

        for (int j = 0; j < 4; j++)
            rk[i * 4 + j] = rk[(i - 8) * 4 + j] ^ temp[j];
    }
}

/* ------------------------------------------------------------------ */
/* Round operations                                                     */
/*                                                                      */
/* State layout: column-major flat array of 16 bytes.                  */
/*   state[c*4 + r]  =>  row r, column c                               */
/*                                                                      */
/* Row r elements are at indices: r, r+4, r+8, r+12                   */
/* ------------------------------------------------------------------ */

static void add_round_key(uint8_t *state, const uint8_t *rk, int round)
{
    for (int i = 0; i < 16; i++)
        state[i] ^= rk[round * 16 + i];
}

static void sub_bytes(uint8_t *state)
{
    for (int i = 0; i < 16; i++)
        state[i] = sbox[state[i]];
}

static void inv_sub_bytes(uint8_t *state)
{
    for (int i = 0; i < 16; i++)
        state[i] = inv_sbox[state[i]];
}

static void shift_rows(uint8_t *s)
{
    uint8_t t;
    /* Row 1: cyclic left shift by 1 */
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    /* Row 2: cyclic left shift by 2 */
    t = s[2];  s[2]  = s[10]; s[10] = t;
    t = s[6];  s[6]  = s[14]; s[14] = t;
    /* Row 3: cyclic left shift by 3 (= right shift by 1) */
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static void inv_shift_rows(uint8_t *s)
{
    uint8_t t;
    /* Row 1: cyclic right shift by 1 */
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    /* Row 2: cyclic right shift by 2 (same as left by 2) */
    t = s[2];  s[2]  = s[10]; s[10] = t;
    t = s[6];  s[6]  = s[14]; s[14] = t;
    /* Row 3: cyclic right shift by 3 (= left shift by 1) */
    t = s[3];  s[3]  = s[7];  s[7]  = s[11]; s[11] = s[15]; s[15] = t;
}

static void mix_columns(uint8_t *s)
{
    for (int c = 0; c < 4; c++) {
        uint8_t *col = s + c * 4;
        uint8_t s0 = col[0], s1 = col[1], s2 = col[2], s3 = col[3];
        col[0] = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2            ^ s3;
        col[1] = s0            ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3;
        col[2] = s0            ^ s1             ^ gmul(0x02, s2) ^ gmul(0x03, s3);
        col[3] = gmul(0x03, s0) ^ s1            ^ s2             ^ gmul(0x02, s3);
    }
}

static void inv_mix_columns(uint8_t *s)
{
    for (int c = 0; c < 4; c++) {
        uint8_t *col = s + c * 4;
        uint8_t s0 = col[0], s1 = col[1], s2 = col[2], s3 = col[3];
        col[0] = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3);
        col[1] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3);
        col[2] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3);
        col[3] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3);
    }
}

/* ------------------------------------------------------------------ */
/* Single-block encrypt / decrypt (in-place, 16 bytes)                 */
/* ------------------------------------------------------------------ */
static void aes256_encrypt_block(const uint8_t *rk, uint8_t *block)
{
    uint8_t state[16];
    memcpy(state, block, 16);

    add_round_key(state, rk, 0);

    for (int round = 1; round < 14; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, rk, round);
    }

    /* Final round — no MixColumns */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, rk, 14);

    memcpy(block, state, 16);
}

static void aes256_decrypt_block(const uint8_t *rk, uint8_t *block)
{
    uint8_t state[16];
    memcpy(state, block, 16);

    add_round_key(state, rk, 14);

    for (int round = 13; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, rk, round);
        inv_mix_columns(state);
    }

    /* Final round — no InvMixColumns */
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, rk, 0);

    memcpy(block, state, 16);
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

void aes_init(aes_ctx_t *ctx, const uint8_t *key, const uint8_t *iv)
{
    key_expansion(key, ctx->round_key);
    memcpy(ctx->iv, iv, AES_IV_SIZE);
}

uint8_t *aes_cbc_encrypt(aes_ctx_t *ctx,
                         const uint8_t *plain, size_t plain_len,
                         size_t *out_len)
{
    /* PKCS#7: pad_len is 1..16, always adds at least one byte */
    size_t pad     = AES_BLOCK_SIZE - (plain_len % AES_BLOCK_SIZE);
    *out_len       = plain_len + pad;

    uint8_t *out = malloc(*out_len);
    if (!out) return NULL;

    memcpy(out, plain, plain_len);
    for (size_t i = plain_len; i < *out_len; i++)
        out[i] = (uint8_t)pad;

    uint8_t prev[AES_BLOCK_SIZE];
    memcpy(prev, ctx->iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < *out_len; i += AES_BLOCK_SIZE) {
        for (int j = 0; j < AES_BLOCK_SIZE; j++)
            out[i + j] ^= prev[j];
        aes256_encrypt_block(ctx->round_key, out + i);
        memcpy(prev, out + i, AES_BLOCK_SIZE);
    }

    return out;
}

uint8_t *aes_cbc_decrypt(aes_ctx_t *ctx,
                         const uint8_t *cipher, size_t cipher_len,
                         size_t *out_len)
{
    if (cipher_len == 0 || cipher_len % AES_BLOCK_SIZE != 0)
        return NULL;

    uint8_t *out = malloc(cipher_len);
    if (!out) return NULL;

    uint8_t prev[AES_BLOCK_SIZE];
    uint8_t cur[AES_BLOCK_SIZE];
    memcpy(prev, ctx->iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < cipher_len; i += AES_BLOCK_SIZE) {
        memcpy(cur,      cipher + i, AES_BLOCK_SIZE);
        memcpy(out + i,  cipher + i, AES_BLOCK_SIZE);
        aes256_decrypt_block(ctx->round_key, out + i);
        for (int j = 0; j < AES_BLOCK_SIZE; j++)
            out[i + j] ^= prev[j];
        memcpy(prev, cur, AES_BLOCK_SIZE);
    }

    /* Validate and strip PKCS#7 padding */
    uint8_t pad = out[cipher_len - 1];
    if (pad == 0 || pad > AES_BLOCK_SIZE) {
        free(out);
        return NULL;
    }
    for (size_t i = cipher_len - pad; i < cipher_len; i++) {
        if (out[i] != pad) {
            free(out);
            return NULL;
        }
    }
    *out_len = cipher_len - pad;

    return out;
}
