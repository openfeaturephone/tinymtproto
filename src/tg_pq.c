/* tg_pq.c - factor the 64-bit pq of resPQ (Pollard rho, Floyd cycle, batched gcd).
 * No division instructions: the SD build links no compiler runtime (__aeabi_uldivmod). */
#include "tg_crypto.h"

static uint64_t addmod(uint64_t x, uint64_t y, uint64_t m)
{
    uint64_t s = x + y;                     /* x, y < m: subtract once on overflow or s >= m */
    if (s < x || s >= m) s -= m;
    return s;
}

static uint64_t mulmod(uint64_t a, uint64_t b, uint64_t m)
{
    uint64_t r = 0;
    for (int i = 63; i >= 0; i--) {
        r = addmod(r, r, m);
        if ((b >> i) & 1) r = addmod(r, a, m);
    }
    return r;
}

static uint64_t gcd(uint64_t a, uint64_t b)
{
    int shift = 0;
    if (!a) return b;
    if (!b) return a;
    while (!((a | b) & 1)) { a >>= 1; b >>= 1; shift++; }
    while (!(a & 1)) a >>= 1;
    do {
        while (!(b & 1)) b >>= 1;
        if (a > b) { uint64_t t = a; a = b; b = t; }
        b -= a;
    } while (b);
    return a << shift;
}

static uint64_t udiv(uint64_t n, uint64_t d)
{
    uint64_t q = 0, r = 0;
    for (int i = 63; i >= 0; i--) {
        r = r << 1 | ((n >> i) & 1);
        if (r >= d) { r -= d; q |= (uint64_t)1 << i; }
    }
    return q;
}

static void restart(tg_pq_t *c)
{
    c->x = c->y = 2;
    c->q = 1;
    c->iter = 0;
}

void tg_pq_start(tg_pq_t *c, uint64_t pq)
{
    c->n = pq;
    c->c = 1;
    c->done = 0;
    c->p_out = c->q_out = 0;
    restart(c);
    if (pq < 4) c->done = 1;                /* nothing to factor: report failure */
    else if (!(pq & 1)) {
        uint64_t q = pq >> 1;
        c->done = 1;
        if (q >> 32 == 0) { c->p_out = 2; c->q_out = (uint32_t)q; }
    }
}

int tg_pq_step(tg_pq_t *c, uint32_t budget)
{
    uint64_t n = c->n;
    while (!c->done && budget--) {
        c->x = addmod(mulmod(c->x, c->x, n), c->c, n);
        c->y = addmod(mulmod(c->y, c->y, n), c->c, n);
        c->y = addmod(mulmod(c->y, c->y, n), c->c, n);
        uint64_t d = c->x > c->y ? c->x - c->y : c->y - c->x;
        c->q = mulmod(c->q, d, n);
        if (++c->iter % 32 && c->q)
            continue;
        uint64_t g = gcd(c->q, n);
        if (g > 1 && g < n) {
            uint64_t o = udiv(n, g);
            uint64_t lo = g < o ? g : o, hi = g < o ? o : g;
            if (!(hi >> 32)) { c->p_out = (uint32_t)lo; c->q_out = (uint32_t)hi; }
            c->done = 1;
        } else if (g == n || !c->q) {       /* overshot or degenerate: new polynomial */
            if (++c->c > 64) c->done = 1;
            else restart(c);
        }
    }
    return c->done;
}
