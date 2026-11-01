/* tg_sha.c - SHA-1 and SHA-256 (FIPS 180-4), byte-wise I/O, no globals. */
#include "tg_crypto.h"

void tg_memcpy(void *d, const void *s, uint32_t n)
{
    uint8_t *dp = d;
    const uint8_t *sp = s;
    while (n--) *dp++ = *sp++;
}

void tg_memset(void *d, int c, uint32_t n)
{
    uint8_t *dp = d;
    while (n--) *dp++ = (uint8_t)c;
}

void tg_wipe(void *p, uint32_t n)
{
    volatile uint8_t *b = p;
    while (n--) *b++ = 0;
}

static uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static uint32_t ld_be(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static void st_be(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

/* ---- shared buffering: both hashes use 64-byte blocks and a 64-bit big-endian bit length ---- */
typedef void (*block_fn)(uint32_t *h, const uint8_t *blk);

static void md_update(uint32_t *h, uint32_t *len_lo, uint32_t *len_hi, uint8_t *buf, uint32_t *used,
                      block_fn fn, const void *data, uint32_t len)
{
    const uint8_t *p = data;
    uint32_t lo = *len_lo + len;
    if (lo < *len_lo) (*len_hi)++;
    *len_lo = lo;
    while (len) {
        uint32_t n = 64 - *used;
        if (n > len) n = len;
        tg_memcpy(buf + *used, p, n);
        *used += n; p += n; len -= n;
        if (*used == 64) { fn(h, buf); *used = 0; }
    }
}

static void md_final(uint32_t *h, uint32_t len_lo, uint32_t len_hi, uint8_t *buf, uint32_t used, block_fn fn)
{
    uint32_t bits_hi = len_hi << 3 | len_lo >> 29, bits_lo = len_lo << 3;
    buf[used++] = 0x80;
    if (used > 56) {
        tg_memset(buf + used, 0, 64 - used);
        fn(h, buf);
        used = 0;
    }
    tg_memset(buf + used, 0, 56 - used);
    st_be(buf + 56, bits_hi);
    st_be(buf + 60, bits_lo);
    fn(h, buf);
}

/* ---- SHA-1 ---- */
static void sha1_block(uint32_t *h, const uint8_t *blk)
{
    uint32_t w[80], a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 16; i++) w[i] = ld_be(blk + 4 * i);
    for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d);           k = 0x5a827999u; }
        else if (i < 40) { f = b ^ c ^ d;                    k = 0x6ed9eba1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);  k = 0x8f1bbcdcu; }
        else             { f = b ^ c ^ d;                    k = 0xca62c1d6u; }
        uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void tg_sha1_init(tg_sha1_t *c)
{
    c->h[0] = 0x67452301u; c->h[1] = 0xefcdab89u; c->h[2] = 0x98badcfeu; c->h[3] = 0x10325476u; c->h[4] = 0xc3d2e1f0u;
    c->len_lo = c->len_hi = c->used = 0;
}

void tg_sha1_update(tg_sha1_t *c, const void *data, uint32_t len)
{ md_update(c->h, &c->len_lo, &c->len_hi, c->buf, &c->used, sha1_block, data, len); }

void tg_sha1_final(tg_sha1_t *c, uint8_t out[20])
{
    md_final(c->h, c->len_lo, c->len_hi, c->buf, c->used, sha1_block);
    for (int i = 0; i < 5; i++) st_be(out + 4 * i, c->h[i]);
}

void tg_sha1(const void *data, uint32_t len, uint8_t out[20])
{
    tg_sha1_t c;
    tg_sha1_init(&c);
    tg_sha1_update(&c, data, len);
    tg_sha1_final(&c, out);
}

/* ---- SHA-256 ---- */
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static void sha256_block(uint32_t *h, const uint8_t *blk)
{
    uint32_t w[64], s[8];
    for (int i = 0; i < 16; i++) w[i] = ld_be(blk + 4 * i);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    for (int i = 0; i < 8; i++) s[i] = h[i];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ror(s[4], 6) ^ ror(s[4], 11) ^ ror(s[4], 25);
        uint32_t ch = (s[4] & s[5]) ^ (~s[4] & s[6]);
        uint32_t t1 = s[7] + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ror(s[0], 2) ^ ror(s[0], 13) ^ ror(s[0], 22);
        uint32_t mj = (s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]);
        s[7] = s[6]; s[6] = s[5]; s[5] = s[4]; s[4] = s[3] + t1;
        s[3] = s[2]; s[2] = s[1]; s[1] = s[0]; s[0] = t1 + S0 + mj;
    }
    for (int i = 0; i < 8; i++) h[i] += s[i];
}

void tg_sha256_init(tg_sha256_t *c)
{
    c->h[0] = 0x6a09e667u; c->h[1] = 0xbb67ae85u; c->h[2] = 0x3c6ef372u; c->h[3] = 0xa54ff53au;
    c->h[4] = 0x510e527fu; c->h[5] = 0x9b05688cu; c->h[6] = 0x1f83d9abu; c->h[7] = 0x5be0cd19u;
    c->len_lo = c->len_hi = c->used = 0;
}

void tg_sha256_update(tg_sha256_t *c, const void *data, uint32_t len)
{ md_update(c->h, &c->len_lo, &c->len_hi, c->buf, &c->used, sha256_block, data, len); }

void tg_sha256_final(tg_sha256_t *c, uint8_t out[32])
{
    md_final(c->h, c->len_lo, c->len_hi, c->buf, c->used, sha256_block);
    for (int i = 0; i < 8; i++) st_be(out + 4 * i, c->h[i]);
}

void tg_sha256(const void *data, uint32_t len, uint8_t out[32])
{
    tg_sha256_t c;
    tg_sha256_init(&c);
    tg_sha256_update(&c, data, len);
    tg_sha256_final(&c, out);
}
