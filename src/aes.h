#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_KEY_SIZE    32   /* 256 bits */
#define AES_IV_SIZE     16   /* 128 bits */
#define AES_BLOCK_SIZE  16   /* 128 bits */

/*
 * AES-256-CBC context.
 * round_key: 60 words * 4 bytes = 240 bytes (15 round keys)
 * iv:        16-byte initialisation vector
 */
typedef struct {
    uint8_t round_key[240];
    uint8_t iv[AES_IV_SIZE];
} aes_ctx_t;

/*
 * Initialise context with a 32-byte key and 16-byte IV.
 * Expands the key schedule internally.
 */
void aes_init(aes_ctx_t *ctx, const uint8_t *key, const uint8_t *iv);

/*
 * Encrypt plain[0..plain_len) using AES-256-CBC.
 * PKCS#7 padding is applied automatically.
 * Returns a malloc'd buffer of *out_len bytes (caller must free).
 * Returns NULL on allocation failure.
 */
uint8_t *aes_cbc_encrypt(aes_ctx_t *ctx,
                         const uint8_t *plain, size_t plain_len,
                         size_t *out_len);

/*
 * Decrypt cipher[0..cipher_len) using AES-256-CBC.
 * PKCS#7 padding is stripped automatically.
 * cipher_len must be a non-zero multiple of AES_BLOCK_SIZE.
 * Returns a malloc'd buffer of *out_len bytes (caller must free).
 * Returns NULL on error (bad length, bad padding, allocation failure).
 */
uint8_t *aes_cbc_decrypt(aes_ctx_t *ctx,
                         const uint8_t *cipher, size_t cipher_len,
                         size_t *out_len);

#endif /* AES_H */
