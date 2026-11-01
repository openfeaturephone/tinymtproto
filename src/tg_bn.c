/* tg_bn.c - modular exponentiation for RSA-2048 and DH-2048 (Montgomery CIOS, 4-bit fixed windows).
 * Steppable so the caller's event loop never blocks: a full 2048-bit exponent is ~2600 Montgomery products. */
#include "tg_crypto.h"

static void from_be(uint32_t *x, uint32_t nl, const uint8_t *b, uint32_t len)
{
    tg_memset(x, 0, nl * 4);
    for (uint32_t i = 0; i < len; i++) {
        uint32_t k = len - 1 - i;           /* byte k from the least significant end */
        if (k / 4 < nl)
            x[k / 4] |= (uint32_t)b[i] << (8 * (k & 3));
    }
}

static int ge(const uint32_t *a, const uint32_t *b, uint32_t nl)
{
    for (uint32_t i = nl; i-- > 0;)
        if (a[i] != b[i]) return a[i] > b[i];
    return 1;
}

static uint32_t sub_in(uint32_t *a, const uint32_t *b, uint32_t nl)
{
    uint32_t borrow = 0;
    for (uint32_t i = 0; i < nl; i++) {
        uint64_t d = (uint64_t)a[i] - b[i] - borrow;
        a[i] = (uint32_t)d;
        borrow = (uint32_t)(d >> 32) & 1;
    }
    return borrow;
}

/* r = a * b * R^-1 mod n; r may alias a or b */
static void mont(tg_modexp_t *c, uint32_t *r, const uint32_t *a, const uint32_t *b)
{
    uint32_t nl = c->nl, *t = c->t;
    tg_memset(t, 0, (nl + 2) * 4);
    for (uint32_t i = 0; i < nl; i++) {
        uint64_t C = 0;
        uint32_t bi = b[i];
        for (uint32_t j = 0; j < nl; j++) {
            C = (uint64_t)t[j] + (uint64_t)a[j] * bi + (C >> 32);
            t[j] = (uint32_t)C;
        }
        C = (uint64_t)t[nl] + (C >> 32);
        t[nl] = (uint32_t)C;
        t[nl + 1] = (uint32_t)(C >> 32);

        uint32_t m = t[0] * c->n0;
        C = (uint64_t)t[0] + (uint64_t)m * c->n[0];
        for (uint32_t j = 1; j < nl; j++) {
            C = (uint64_t)t[j] + (uint64_t)m * c->n[j] + (C >> 32);
            t[j - 1] = (uint32_t)C;
        }
        C = (uint64_t)t[nl] + (C >> 32);
        t[nl - 1] = (uint32_t)C;
        t[nl] = t[nl + 1] + (uint32_t)(C >> 32);
    }
    if (t[nl] || ge(t, c->n, nl))
        sub_in(t, c->n, nl);
    tg_memcpy(r, t, nl * 4);
}

int tg_modexp_start(tg_modexp_t *c, const uint8_t *base, uint32_t base_len,
                    const uint8_t *exp, uint32_t exp_len, const uint8_t *mod, uint32_t mod_len)
{
    while (mod_len && mod[0] == 0) { mod++; mod_len--; }
    while (base_len && base[0] == 0) { base++; base_len--; }
    if (!mod_len || mod_len > TG_BN_LIMBS * 4 || !(mod[mod_len - 1] & 1) ||
        exp_len > sizeof c->exp)
        return -1;
    c->nl = (mod_len + 3) / 4;
    c->mod_len = mod_len;
    if (base_len > c->nl * 4)
        return -1;
    from_be(c->n, c->nl, mod, mod_len);
    from_be(c->tab[1], c->nl, base, base_len);
    tg_memcpy(c->exp, exp, exp_len);
    c->exp_len = exp_len;

    uint32_t inv = c->n[0];                 /* Newton: 3, 6, 12, 24, 48 correct bits */
    for (int i = 0; i < 4; i++) inv *= 2 - c->n[0] * inv;
    c->n0 = (uint32_t)0 - inv;

    tg_memset(c->rr, 0, sizeof c->rr);
    c->rr[0] = 1;
    c->stage = 0;
    c->prog = 0;
    c->nib = 0;
    return 0;
}

int tg_modexp_step(tg_modexp_t *c, uint32_t budget)
{
    uint32_t nl = c->nl;
    if (!budget) budget = 1;
    while (budget) {
        switch (c->stage) {
        case 0: {                           /* rr = 2^(64*nl) mod n by doubling, 64 doublings per unit */
            for (int k = 0; k < 64 && c->prog < 64 * nl; k++, c->prog++) {
                uint32_t carry = 0;
                for (uint32_t i = 0; i < nl; i++) {
                    uint32_t v = c->rr[i];
                    c->rr[i] = v << 1 | carry;
                    carry = v >> 31;
                }
                if (carry || ge(c->rr, c->n, nl))
                    sub_in(c->rr, c->n, nl);
            }
            budget--;
            if (c->prog == 64 * nl) { c->stage = 1; c->prog = 0; }
            break;
        }
        case 1:                             /* window table in Montgomery form */
            if (c->prog == 0) {
                uint32_t *one = c->acc;
                tg_memset(one, 0, nl * 4);
                one[0] = 1;
                mont(c, c->tab[0], one, c->rr);           /* R mod n */
                mont(c, c->tab[1], c->tab[1], c->rr);     /* base * R mod n */
                c->prog = 2;
            } else {
                mont(c, c->tab[c->prog], c->tab[c->prog - 1], c->tab[1]);
                c->prog++;
            }
            budget--;
            if (c->prog == 16) {
                tg_memcpy(c->acc, c->tab[0], nl * 4);
                c->stage = 2;
                c->nib = 0;
            }
            break;
        case 2:
            if (c->nib == c->exp_len * 2) {
                uint32_t *one = c->tab[2];                /* table no longer needed */
                tg_memset(one, 0, nl * 4);
                one[0] = 1;
                mont(c, c->acc, c->acc, one);             /* leave Montgomery form */
                c->stage = 3;
                return 1;
            } else {
                uint8_t b = c->exp[c->nib / 2];
                uint32_t w = (c->nib & 1) ? (b & 15u) : (uint32_t)(b >> 4);
                if (c->nib) for (int k = 0; k < 4; k++) mont(c, c->acc, c->acc, c->acc);
                mont(c, c->acc, c->acc, c->tab[w]);
                c->nib++;
                budget = budget > 5 ? budget - 5 : 0;
            }
            break;
        default:
            return 1;
        }
    }
    return c->stage == 3;
}

void tg_modexp_result(const tg_modexp_t *c, uint8_t *out)
{
    for (uint32_t i = 0; i < c->mod_len; i++) {
        uint32_t k = c->mod_len - 1 - i;
        out[i] = (uint8_t)(c->acc[k / 4] >> (8 * (k & 3)));
    }
}

int tg_be_cmp(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++)
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}

uint32_t tg_be_sub(uint8_t *r, const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint32_t borrow = 0;
    for (uint32_t i = len; i-- > 0;) {
        uint32_t d = (uint32_t)a[i] - b[i] - borrow;
        r[i] = (uint8_t)d;
        borrow = (d >> 8) & 1;
    }
    return borrow;
}
