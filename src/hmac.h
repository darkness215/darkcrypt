/*
 * hmac.h — HMAC-SHA256 verification for darkcrypt payload integrity (F8)
 *
 * Self-contained SHA-256 + HMAC-SHA256 (RFC 2104 / FIPS 180-4). Used by
 * the loader to verify the 32-byte tag appended to the ciphertext by
 * encode2aes before decrypting, so a tampered/sinkholed payload is
 * rejected without executing garbage. No external crypto dependency.
 */
#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stddef.h>

/* Compute HMAC-SHA256(key, msg) and write the 32-byte tag to out[32].
 * Returns 0 on success, non-zero on bad args. */
int hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t out[32]);

/* Constant-time compare of two 32-byte tags. Returns 0 if equal. */
int hmac_verify(const uint8_t *tag_a, const uint8_t *tag_b);

#endif /* HMAC_H */