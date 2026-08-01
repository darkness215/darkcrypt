/*
 * cng.h -- AES-256-CBC decryption via the Windows CNG (bcrypt.dll) API
 *
 * Replaces the hand-rolled AES S-box implementation (aes.c) so that no AES
 * lookup tables appear in the binary. CNG uses the OS-native AES
 * implementation; bcrypt.dll is resolved at runtime by hash (no static
 * import) and the algorithm/property strings are XOR-encoded.
 */

#ifndef CNG_H
#define CNG_H

#include <stdint.h>
#include <stddef.h>
#include <windows.h>   /* N5: HMODULE for cng_get_bcrypt_base() */

/* Decrypt AES-256-CBC ciphertext (PKCS#7) via Windows CNG.
 * key: 32 bytes, iv: 16 bytes. Returns malloc'd plaintext (caller frees),
 * *out_len set. Returns NULL on failure. The S-box never appears in the
 * binary because CNG uses the OS implementation. */
uint8_t *cng_decrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *cipher, size_t cipher_len, size_t *out_len);

/* N5: resolve and cache the bcrypt.dll base address so cng.c and cng_hmac.c
 * share a single LoadLibraryA + decode/zero cycle instead of duplicating the
 * resolution path. Returns the cached HMODULE (resolved lazily on first call
 * via PEB-walked LoadLibraryA + XOR-decoded "bcrypt.dll"), or NULL on failure. */
HMODULE cng_get_bcrypt_base(void);

#endif /* CNG_H */