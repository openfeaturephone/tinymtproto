/* tg_tl.c - TL wire primitives and the hash-pool RNG. */
#include "tg_proto.h"

uint32_t tg_rd32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
void tg_wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

/* ---- writer ---- */
void tg_tlw_init(tg_tlw_t *w, uint8_t *buf, uint32_t cap) { w->p = buf; w->cap = cap; w->len = 0; w->err = 0; }

void tg_tlw_raw(tg_tlw_t *w, const void *data, uint32_t len)
{
    if (w->err || len > w->cap - w->len) { w->err = 1; return; }
    tg_memcpy(w->p + w->len, data, len);
    w->len += len;
}

void tg_tlw_u32(tg_tlw_t *w, uint32_t v)
{
    uint8_t b[4];
    tg_wr32(b, v);
    tg_tlw_raw(w, b, 4);
}

void tg_tlw_u64(tg_tlw_t *w, uint32_t lo, uint32_t hi) { tg_tlw_u32(w, lo); tg_tlw_u32(w, hi); }

void tg_tlw_bytes(tg_tlw_t *w, const void *data, uint32_t len)
{
    static const uint8_t zeros[4] = { 0, 0, 0, 0 };
    uint32_t head;
    if (len <= 253) {
        uint8_t l = (uint8_t)len;
        tg_tlw_raw(w, &l, 1);
        head = 1;
    } else {
        tg_tlw_u32(w, 0xfe | len << 8);
        head = 4;
    }
    tg_tlw_raw(w, data, len);
    tg_tlw_raw(w, zeros, (4 - (head + len) % 4) % 4);
}

/* ---- reader ---- */
void tg_tlr_init(tg_tlr_t *r, const uint8_t *buf, uint32_t len) { r->p = buf; r->len = len; r->pos = 0; r->err = 0; }

static const uint8_t *take(tg_tlr_t *r, uint32_t n)
{
    if (r->err || n > r->len - r->pos) { r->err = 1; return 0; }
    const uint8_t *p = r->p + r->pos;
    r->pos += n;
    return p;
}

uint32_t tg_tlr_u32(tg_tlr_t *r)
{
    const uint8_t *p = take(r, 4);
    return p ? tg_rd32(p) : 0;
}

void tg_tlr_u64(tg_tlr_t *r, uint32_t *lo, uint32_t *hi) { *lo = tg_tlr_u32(r); *hi = tg_tlr_u32(r); }

void tg_tlr_raw(tg_tlr_t *r, void *out, uint32_t len)
{
    const uint8_t *p = take(r, len);
    if (p) tg_memcpy(out, p, len);
    else tg_memset(out, 0, len);
}

const uint8_t *tg_tlr_bytes(tg_tlr_t *r, uint32_t *len)
{
    const uint8_t *h = take(r, 1);
    uint32_t n, head = 1;
    *len = 0;
    if (!h) return 0;
    n = h[0];
    if (n == 254) {
        const uint8_t *x = take(r, 3);
        if (!x) return 0;
        n = (uint32_t)x[0] | (uint32_t)x[1] << 8 | (uint32_t)x[2] << 16;
        head = 4;
    } else if (n == 255) {
        r->err = 1;
        return 0;
    }
    const uint8_t *d = take(r, n);
    if (!d) return 0;
    take(r, (4 - (head + n) % 4) % 4);
    *len = n;
    return r->err ? 0 : d;
}

/* ---- RNG ---- */
void tg_rng_init(tg_rng_t *r) { tg_memset(r, 0, sizeof *r); }

void tg_rng_add(tg_rng_t *r, const void *data, uint32_t len)
{
    tg_sha256_t c;
    tg_sha256_init(&c);
    tg_sha256_update(&c, r->pool, 32);
    tg_sha256_update(&c, data, len);
    tg_sha256_final(&c, r->pool);
    r->added += len;
}

void tg_rng_bytes(tg_rng_t *r, void *out, uint32_t len)
{
    uint8_t *o = out, blk[32], ctr[4];
    tg_sha256_t c;
    while (len) {
        tg_wr32(ctr, r->ctr++);
        tg_sha256_init(&c);
        tg_sha256_update(&c, r->pool, 32);
        tg_sha256_update(&c, ctr, 4);
        tg_sha256_final(&c, blk);
        uint32_t n = len < 32 ? len : 32;
        tg_memcpy(o, blk, n);
        o += n;
        len -= n;
    }
    static const uint8_t next[4] = { 'n', 'e', 'x', 't' };
    tg_rng_add(r, next, 4);
    r->added -= 4;
    tg_wipe(blk, sizeof blk);
}
