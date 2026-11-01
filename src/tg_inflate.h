/* tg_inflate.h - gzip (RFC 1952) / raw DEFLATE (RFC 1951) decoder for gzip_packed replies.
 * Altered from puff.c by Mark Adler (zlib contrib; notice in tg_inflate.c): canonical Huffman decoding from
 * per-length counts, no lookup tables. Made resumable: tg_inflate_step does about `budget` symbols
 * (or stored bytes) per call, so a big reply can be spread over many timer ticks.
 *
 * The output goes straight into one caller buffer that holds the whole result, so back-references
 * read from it and no separate 32 KB window is needed. Size it from the gzip trailer:
 *   n = tg_gzip_isize(in, len);  out = alloc(n);  tg_inflate_start(z, in, len, out, n);
 *   while (!(r = tg_inflate_step(z, 256))) { next tick }      r == 1: done, z->out_len bytes
 * The input must stay in place until done. CRC-32 and ISIZE are checked at the end. */
#ifndef TG_INFLATE_H
#define TG_INFLATE_H

#include "tg_crypto.h"

enum {
    TG_ZERR_HEADER = -1,     /* not gzip, unknown method or flags */
    TG_ZERR_DATA = -2,       /* invalid DEFLATE stream */
    TG_ZERR_SPACE = -3,      /* output larger than out_cap */
    TG_ZERR_INPUT = -4,      /* input ended early */
    TG_ZERR_CHECK = -5,      /* CRC-32 or ISIZE mismatch */
};

typedef struct {
    const uint8_t *in;
    uint32_t in_len, in_pos;
    uint32_t bitbuf, bitcnt;
    uint8_t *out;
    uint32_t out_cap, out_len;
    uint32_t crc, crc_pos;
    uint32_t stored_left;
    int state, last, err, raw;
    uint16_t lcount[16], lsym[288];   /* literal/length code */
    uint16_t dcount[16], dsym[30];    /* distance code */
} tg_inflate_t;

uint32_t tg_gzip_isize(const uint8_t *in, uint32_t len);   /* uncompressed size from the trailer, 0 if too short */
void tg_inflate_start(tg_inflate_t *z, const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t out_cap);
void tg_inflate_start_raw(tg_inflate_t *z, const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t out_cap);
/* 1 done, 0 call again, < 0 TG_ZERR_* (sticky) */
int tg_inflate_step(tg_inflate_t *z, uint32_t budget);

#endif
