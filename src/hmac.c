/*
 * hmac.c — HMAC-SHA256 verification for darkcrypt payload integrity (F8)
 *
 * Self-contained SHA-256 (FIPS 180-4) + HMAC-SHA256 (RFC 2104). Matches
 * the tag emitted by encode2aes.c so the loader can verify ciphertext
 * integrity before decryption. No external crypto dependency, no S-box
 * signature (SHA-256 uses 64-bit round constants, not a 256-byte table).
 */
#include "hmac.h"

/* R2: the self-contained SHA-256 + HMAC-SHA256 implementation below is now
 * used ONLY by the Linux encoder (encode2aes.c) and the portable keyderive.c
 * HKDF path on Linux. On Windows the loader links cng_hmac.c instead, which
 * delegates HMAC-SHA256 to the OS CNG provider (BCrypt* with the HMAC flag) —
 * so the 256-byte K256 round-constant table and the SHA-256 IV never appear in
 * the loader binary. Guard the whole crypto body with #ifndef _WIN32 so a
 * Windows build of this translation unit produces an empty object (the symbols
 * hmac_sha256 / hmac_verify are provided by cng_hmac.c). */
#ifndef _WIN32

#include <string.h>

/* ---- SHA-256 round constants (64 of them) ---- */
static const uint32_t K256[64] = {
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

#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)  (ROTR32(x,2)  ^ ROTR32(x,13) ^ ROTR32(x,22))
#define EP1(x)  (ROTR32(x,6)  ^ ROTR32(x,11) ^ ROTR32(x,25))
#define SIG0(x) (ROTR32(x,7)  ^ ROTR32(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ ((x) >> 10))

typedef struct {
    uint32_t h[8];
    uint8_t  buf[64];
    uint64_t len;   /* total bytes processed */
    int      buflen;
} sha256_ctx;

static void sha256_init(sha256_ctx *c)
{
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->len = 0; c->buflen = 0;
}

static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64], a,b,cc,d,e,f,g,h, t1,t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|
               ((uint32_t)p[i*4+2]<<8)|((uint32_t)p[i*4+3]);
    for (i = 16; i < 64; i++)
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];
    a=c->h[0]; b=c->h[1]; cc=c->h[2]; d=c->h[3];
    e=c->h[4]; f=c->h[5]; g=c->h[6]; h=c->h[7];
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + K256[i] + w[i];
        t2 = EP0(a) + MAJ(a,b,cc);
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len)
{
    c->len += len;
    while (len > 0) {
        int n = 64 - c->buflen;
        if ((size_t)n > len) n = (int)len;
        memcpy(c->buf + c->buflen, data, n);
        c->buflen += n; data += n; len -= n;
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bitlen = c->len * 8;
    c->buf[c->buflen++] = 0x80;
    if (c->buflen > 56) {
        while (c->buflen < 64) c->buf[c->buflen++] = 0;
        sha256_block(c, c->buf);
        c->buflen = 0;
    }
    while (c->buflen < 56) c->buf[c->buflen++] = 0;
    for (int i = 7; i >= 0; i--)
        c->buf[c->buflen++] = (uint8_t)(bitlen >> (i*8));
    sha256_block(c, c->buf);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}

/* ---- HMAC-SHA256 (RFC 2104) ---- */
int hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t out[32])
{
    if (!key || !msg || !out) return 1;
    uint8_t k0[64];
    memset(k0, 0, 64);
    if (key_len > 64) {
        sha256_ctx kc; sha256_init(&kc);
        sha256_update(&kc, key, key_len);
        sha256_final(&kc, k0);   /* hash -> first 32 bytes of k0 */
    } else {
        memcpy(k0, key, key_len);
    }
    uint8_t ipad[64], opad[64], inner[32];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, msg_len);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
    /* wipe temporaries (inner is only 32 bytes, so split the loop) */
    volatile uint8_t *v = k0;
    for (int i = 0; i < 64; i++) v[i]=0;
    volatile uint8_t *vi = ipad, *vo = opad, *vin = inner;
    for (int i = 0; i < 64; i++) { vi[i]=0; vo[i]=0; }
    for (int i = 0; i < 32; i++) vin[i]=0;
    return 0;
}

int hmac_verify(const uint8_t *a, const uint8_t *b)
{
    uint8_t r = 0;
    for (int i = 0; i < 32; i++) r |= a[i] ^ b[i];
    return r;  /* 0 == equal */
}

#endif /* !_WIN32 — self-contained SHA-256/HMAC is Linux-encoder-only */