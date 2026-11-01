/* tg_inflate.c - resumable gzip/DEFLATE decoder. See tg_inflate.h.
 *
 * Altered from puff.c (zlib contrib/puff, version 2.3): construct(), decode(), the fixed/dynamic
 * table setup and the length/distance tables follow puff closely and comments name the puff
 * function. Altered: made resumable with a step budget, gzip header/trailer and CRC-32 added,
 * output is one caller buffer. This is not the original software. puff's notice:
 *
 *   Copyright (C) 2002-2013 Mark Adler, all rights reserved
 *   version 2.3, 21 Jan 2013
 *
 *   This software is provided 'as-is', without any express or implied
 *   warranty.  In no event will the author be held liable for any damages
 *   arising from the use of this software.
 *
 *   Permission is granted to anyone to use this software for any purpose,
 *   including commercial applications, and to alter it and redistribute it
 *   freely, subject to the following restrictions:
 *
 *   1. The origin of this software must not be misrepresented; you must not
 *      claim that you wrote the original software. If you use this software
 *      in a product, an acknowledgment in the product documentation would be
 *      appreciated but is not required.
 *   2. Altered source versions must be plainly marked as such, and must not be
 *      misrepresented as being the original software.
 *   3. This notice may not be removed or altered from any source distribution.
 *
 *   Mark Adler    madler@alumni.caltech.edu
 */
#include "tg_inflate.h"

enum { S_GZIP, S_BLOCK, S_STORED, S_CODES, S_TRAILER, S_DONE, S_ERROR };

static const uint16_t LBASE[29] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                                    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
static const uint8_t LEXT[29] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                                  3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
static const uint16_t DBASE[30] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385,
                                    513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
static const uint8_t DEXT[30] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7,
                                  8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
static const uint8_t CL_ORDER[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
/* CRC-32 (reflected 0xedb88320), one nibble at a time */
static const uint32_t CRC_NIB[16] = {
    0x00000000u, 0x1db71064u, 0x3b6e20c8u, 0x26d930acu, 0x76dc4190u, 0x6b6b51f4u, 0x4db26158u, 0x5005713cu,
    0xedb88320u, 0xf00f9344u, 0xd6d6a3e8u, 0xcb61b38cu, 0x9b64c2b0u, 0x86d3d2d4u, 0xa00ae278u, 0xbdbdf21cu,
};

static int fail(tg_inflate_t *z, int err)
{
    if (!z->err)
        z->err = err;
    z->state = S_ERROR;
    return z->err;
}

/* puff: bits. Missing input sets TG_ZERR_INPUT and reads as zeros. */
static uint32_t bits(tg_inflate_t *z, uint32_t need)
{
    uint32_t v = z->bitbuf;
    while (z->bitcnt < need) {
        if (z->in_pos >= z->in_len) {
            fail(z, TG_ZERR_INPUT);
            return 0;
        }
        v |= (uint32_t)z->in[z->in_pos++] << z->bitcnt;
        z->bitcnt += 8;
    }
    z->bitbuf = v >> need;
    z->bitcnt -= need;
    return v & ((1u << need) - 1);
}

static void byte_align(tg_inflate_t *z)
{
    z->bitbuf = 0;
    z->bitcnt = 0;
}

static uint32_t in_byte(tg_inflate_t *z)
{
    if (z->in_pos >= z->in_len) {
        fail(z, TG_ZERR_INPUT);
        return 0;
    }
    return z->in[z->in_pos++];
}

/* puff: decode (canonical code, one bit at a time). -1 = no such code. */
static int decode(tg_inflate_t *z, const uint16_t *count, const uint16_t *symbol)
{
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= 15; len++) {
        code |= (int)bits(z, 1);
        int c = count[len];
        if (code - c < first)
            return symbol[index + (code - first)];
        index += c;
        first += c;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

/* puff: construct. Returns 0 complete, > 0 incomplete, < 0 over-subscribed. */
static int construct(uint16_t *count, uint16_t *symbol, const uint8_t *length, int n)
{
    uint16_t offs[16];
    int left = 1;
    for (int len = 0; len <= 15; len++)
        count[len] = 0;
    for (int s = 0; s < n; s++)
        count[length[s]]++;
    if (count[0] == n)
        return 0;
    for (int len = 1; len <= 15; len++) {
        left <<= 1;
        left -= count[len];
        if (left < 0)
            return left;
    }
    offs[1] = 0;
    for (int len = 1; len < 15; len++)
        offs[len + 1] = (uint16_t)(offs[len] + count[len]);
    for (int s = 0; s < n; s++)
        if (length[s])
            symbol[offs[length[s]]++] = (uint16_t)s;
    return left;
}

/* puff: fixed */
static void fixed_tables(tg_inflate_t *z)
{
    uint8_t len[288];
    int s;
    for (s = 0; s < 144; s++) len[s] = 8;
    for (; s < 256; s++) len[s] = 9;
    for (; s < 280; s++) len[s] = 7;
    for (; s < 288; s++) len[s] = 8;
    construct(z->lcount, z->lsym, len, 288);
    for (s = 0; s < 30; s++) len[s] = 5;
    construct(z->dcount, z->dsym, len, 30);
}

/* puff: dynamic (header only; the codes are decoded by S_CODES) */
static int dynamic_tables(tg_inflate_t *z)
{
    uint8_t len[320];
    int nlen = (int)bits(z, 5) + 257, ndist = (int)bits(z, 5) + 1, ncode = (int)bits(z, 4) + 4, i, err;
    if (z->err)
        return z->err;
    if (nlen > 286 || ndist > 30)
        return TG_ZERR_DATA;
    for (i = 0; i < 19; i++)
        len[CL_ORDER[i]] = i < ncode ? (uint8_t)bits(z, 3) : 0;
    if (construct(z->lcount, z->lsym, len, 19) != 0)    /* code-length code must be complete */
        return z->err ? z->err : TG_ZERR_DATA;
    for (i = 0; i < nlen + ndist;) {
        int sym = decode(z, z->lcount, z->lsym), rep;
        uint8_t v = 0;
        if (z->err)
            return z->err;
        if (sym < 0)
            return TG_ZERR_DATA;
        if (sym < 16) {
            len[i++] = (uint8_t)sym;
            continue;
        }
        if (sym == 16) {
            if (!i)
                return TG_ZERR_DATA;
            v = len[i - 1];
            rep = 3 + (int)bits(z, 2);
        } else if (sym == 17) {
            rep = 3 + (int)bits(z, 3);
        } else {
            rep = 11 + (int)bits(z, 7);
        }
        if (i + rep > nlen + ndist)
            return TG_ZERR_DATA;
        while (rep--)
            len[i++] = v;
    }
    if (z->err)
        return z->err;
    if (!len[256])                                       /* no end-of-block code */
        return TG_ZERR_DATA;
    err = construct(z->lcount, z->lsym, len, nlen);
    if (err < 0 || (err > 0 && nlen - z->lcount[0] != 1))
        return TG_ZERR_DATA;
    err = construct(z->dcount, z->dsym, len + nlen, ndist);
    if (err < 0 || (err > 0 && ndist - z->dcount[0] != 1))
        return TG_ZERR_DATA;
    return 0;
}

/* RFC 1952 member header */
static int gzip_header(tg_inflate_t *z)
{
    uint32_t flg, i, n;
    if (in_byte(z) != 0x1f || in_byte(z) != 0x8b || in_byte(z) != 8)
        return z->err ? z->err : TG_ZERR_HEADER;
    flg = in_byte(z);
    if (flg & 0xe0)
        return TG_ZERR_HEADER;
    for (i = 0; i < 6; i++)                              /* mtime, xfl, os */
        in_byte(z);
    if (flg & 4) {                                       /* FEXTRA */
        n = in_byte(z);
        n |= in_byte(z) << 8;
        while (n-- && !z->err)
            in_byte(z);
    }
    if (flg & 8)                                         /* FNAME */
        while (in_byte(z) && !z->err) {}
    if (flg & 16)                                        /* FCOMMENT */
        while (in_byte(z) && !z->err) {}
    if (flg & 2) {                                       /* FHCRC */
        in_byte(z);
        in_byte(z);
    }
    return z->err;
}

static void crc_update(tg_inflate_t *z)
{
    uint32_t c = ~z->crc;
    for (; z->crc_pos < z->out_len; z->crc_pos++) {
        c ^= z->out[z->crc_pos];
        c = (c >> 4) ^ CRC_NIB[c & 15];
        c = (c >> 4) ^ CRC_NIB[c & 15];
    }
    z->crc = ~c;
}

uint32_t tg_gzip_isize(const uint8_t *in, uint32_t len)
{
    if (len < 18)
        return 0;
    return (uint32_t)in[len - 4] | (uint32_t)in[len - 3] << 8 | (uint32_t)in[len - 2] << 16 | (uint32_t)in[len - 1] << 24;
}

void tg_inflate_start(tg_inflate_t *z, const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t out_cap)
{
    tg_memset(z, 0, sizeof *z);
    z->in = in;
    z->in_len = in_len;
    z->out = out;
    z->out_cap = out_cap;
    z->state = S_GZIP;
}

void tg_inflate_start_raw(tg_inflate_t *z, const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t out_cap)
{
    tg_inflate_start(z, in, in_len, out, out_cap);
    z->raw = 1;
    z->state = S_BLOCK;
}

/* puff: codes, one symbol per unit of budget */
static int codes(tg_inflate_t *z, uint32_t *budget)
{
    while (*budget) {
        int sym = decode(z, z->lcount, z->lsym);
        uint32_t len, dist;
        (*budget)--;
        if (z->err)
            return z->err;
        if (sym < 0)
            return TG_ZERR_DATA;
        if (sym < 256) {
            if (z->out_len >= z->out_cap)
                return TG_ZERR_SPACE;
            z->out[z->out_len++] = (uint8_t)sym;
            continue;
        }
        if (sym == 256) {
            z->state = z->last ? S_TRAILER : S_BLOCK;
            return 0;
        }
        sym -= 257;
        if (sym >= 29)
            return TG_ZERR_DATA;
        len = LBASE[sym] + bits(z, LEXT[sym]);
        sym = decode(z, z->dcount, z->dsym);
        if (z->err)
            return z->err;
        if (sym < 0 || sym >= 30)
            return TG_ZERR_DATA;
        dist = DBASE[sym] + bits(z, DEXT[sym]);
        if (z->err)
            return z->err;
        if (dist > z->out_len)
            return TG_ZERR_DATA;
        if (len > z->out_cap - z->out_len)
            return TG_ZERR_SPACE;
        while (len--) {
            z->out[z->out_len] = z->out[z->out_len - dist];
            z->out_len++;
        }
    }
    return 0;
}

int tg_inflate_step(tg_inflate_t *z, uint32_t budget)
{
    int r = 0;
    if (!budget)
        budget = 1;
    while (budget && !r) {
        switch (z->state) {
        case S_GZIP:
            r = gzip_header(z);
            z->state = S_BLOCK;
            break;
        case S_BLOCK: {                                  /* puff: puff, block header */
            uint32_t type;
            z->last = (int)bits(z, 1);
            type = bits(z, 2);
            if (z->err)
                return fail(z, z->err);
            if (type == 0) {                             /* puff: stored */
                uint32_t n;
                byte_align(z);
                n = in_byte(z);
                n |= in_byte(z) << 8;
                if ((in_byte(z) ^ 0xff) != (n & 0xff) || (in_byte(z) ^ 0xff) != n >> 8)
                    return fail(z, z->err ? z->err : TG_ZERR_DATA);
                z->stored_left = n;
                z->state = S_STORED;
            } else if (type == 1) {
                fixed_tables(z);
                z->state = S_CODES;
            } else if (type == 2) {
                r = dynamic_tables(z);
                z->state = S_CODES;
            } else {
                r = TG_ZERR_DATA;
            }
            budget--;
            break;
        }
        case S_STORED:
            while (budget && z->stored_left) {
                if (z->in_pos >= z->in_len)
                    return fail(z, TG_ZERR_INPUT);
                if (z->out_len >= z->out_cap)
                    return fail(z, TG_ZERR_SPACE);
                z->out[z->out_len++] = z->in[z->in_pos++];
                z->stored_left--;
                budget--;
            }
            if (!z->stored_left)
                z->state = z->last ? S_TRAILER : S_BLOCK;
            break;
        case S_CODES:
            r = codes(z, &budget);
            break;
        case S_TRAILER: {
            uint32_t crc = 0, size = 0;
            crc_update(z);
            if (z->raw) {
                z->state = S_DONE;
                return 1;
            }
            byte_align(z);
            for (int i = 0; i < 4; i++) crc |= in_byte(z) << (8 * i);
            for (int i = 0; i < 4; i++) size |= in_byte(z) << (8 * i);
            if (z->err)
                return fail(z, z->err);
            if (crc != z->crc || size != z->out_len)
                return fail(z, TG_ZERR_CHECK);
            z->state = S_DONE;
            return 1;
        }
        case S_DONE:
            return 1;
        default:
            return z->err ? z->err : TG_ZERR_DATA;
        }
    }
    if (r)
        return fail(z, r);
    crc_update(z);                                       /* spread the CRC over the steps */
    return 0;
}
