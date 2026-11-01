/* tg_tlwalk.c - schema-driven TL walker; see tg_tlwalk.h and gen_tl.py for the table format. */
#include "tg_tlwalk.h"

#define ROOT_OBJ 0xffffu        /* "descriptor" of a bare boxed object: the root, or a root vector's elements */

static int find(uint32_t cid)
{
    int lo = 0, hi = TL_N_CONS - 1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        if (TL_IDS[mid] == cid)
            return mid;
        if (TL_IDS[mid] < cid)
            lo = mid + 1;
        else
            hi = mid - 1;
    }
    return -1;
}

int tg_tl_known(uint32_t cid)
{
    return find(cid) >= 0;
}

/* bytes taken by the field descriptor at off (a vector's includes its element descriptor) */
static uint32_t desc_len(uint32_t off)
{
    uint8_t b = TL_DESC[off];
    uint32_t n = (b & 0x80) ? 2 : 1;
    if ((b & 15) == TG_TT_VECTOR || (b & 15) == TG_TT_BVECTOR)
        n += desc_len(off + n);
    return n;
}

static int fail(tg_tlwalk_t *w, int err, uint32_t arg)
{
    w->err = err;
    w->err_arg = arg;
    return TG_WE_ERROR;
}

static int push(tg_tlwalk_t *w, uint32_t cid, int is_vec, uint32_t left, uint32_t desc, int field)
{
    tg_twf_t *f;
    if (w->sp >= TG_TW_DEPTH)
        return fail(w, TG_WERR_DEPTH, cid);
    f = &w->st[w->sp++];
    f->cid = cid;
    f->is_vec = (uint8_t)is_vec;
    f->left = left;
    f->desc = (uint16_t)desc;
    f->field = (int16_t)field;
    f->flags = f->flags2 = 0;
    return 0;
}

/* read the value described at off (ROOT_OBJ: a boxed object) as field `field` of `owner` */
static int value(tg_tlwalk_t *w, uint32_t off, uint32_t owner, int field, int in_vec)
{
    tg_tlr_t *r = &w->r;
    uint8_t b = off == ROOT_OBJ ? TG_TT_OBJ : TL_DESC[off];
    uint32_t x, n;
    int t = b & 15, idx;
    w->type = t;
    w->cid = owner;
    w->field = field;
    w->in_vec = in_vec;
    w->val = r->p + r->pos;
    w->v32 = 0;
    w->v64 = 0;
    switch (t) {
    case TG_TT_INT:
    case TG_TT_LONG:
    case TG_TT_DOUBLE:
    case TG_TT_INT128:
    case TG_TT_INT256:
        n = t == TG_TT_INT ? 4 : t == TG_TT_INT128 ? 16 : t == TG_TT_INT256 ? 32 : 8;
        if (n > r->len - r->pos)
            return fail(w, TG_WERR_TRUNC, n);
        w->v32 = tg_rd32(w->val);
        if (n >= 8)
            w->v64 = (uint64_t)tg_rd32(w->val + 4) << 32 | w->v32;
        r->pos += n;
        w->len = n;
        return TG_WE_FIELD;
    case TG_TT_STRING:
    case TG_TT_BYTES:
        w->val = tg_tlr_bytes(r, &w->len);
        if (r->err)
            return fail(w, TG_WERR_TRUNC, 0);
        return TG_WE_FIELD;
    case TG_TT_BOOL:
        x = tg_tlr_u32(r);
        if (r->err)
            return fail(w, TG_WERR_TRUNC, 4);
        if (x != TL_boolTrue && x != TL_boolFalse)
            return fail(w, TG_WERR_FORMAT, x);
        w->v32 = x == TL_boolTrue;
        w->len = 4;
        return TG_WE_FIELD;
    case TG_TT_TRUE:
        w->v32 = 1;
        w->len = 0;
        return TG_WE_FIELD;
    case TG_TT_FLAGS:
        x = tg_tlr_u32(r);
        if (r->err)
            return fail(w, TG_WERR_TRUNC, 4);
        if (b & 0x20)
            w->st[w->sp - 1].flags2 = x;
        else
            w->st[w->sp - 1].flags = x;
        w->v32 = x;
        w->len = 4;
        return TG_WE_FIELD;
    case TG_TT_OBJ:
        x = tg_tlr_u32(r);
        if (r->err)
            return fail(w, TG_WERR_TRUNC, 4);
        idx = find(x);
        if (idx < 0)
            return fail(w, TG_WERR_UNKNOWN, x);
        if (push(w, x, 0, TL_DESC[TL_OFF[idx]], TL_OFF[idx] + 1u, -1))
            return TG_WE_ERROR;
        w->pcid = owner;
        w->pfield = field;
        w->cid = x;
        w->field = -1;
        return TG_WE_OBJ;
    case TG_TT_VECTOR:
    case TG_TT_BVECTOR:
        if (t == TG_TT_VECTOR && tg_tlr_u32(r) != TL_vector)
            return fail(w, r->err ? TG_WERR_TRUNC : TG_WERR_FORMAT, 0);
        n = tg_tlr_u32(r);
        if (r->err)
            return fail(w, TG_WERR_TRUNC, 4);
        if (n > (r->len - r->pos) / 4)                   /* every element takes 4 bytes or more */
            return fail(w, TG_WERR_FORMAT, n);
        if (push(w, owner, 1, n, off + ((b & 0x80) ? 2u : 1u), field))
            return TG_WE_ERROR;
        w->count = n;
        return TG_WE_VEC;
    default:
        return fail(w, TG_WERR_FORMAT, b);
    }
}

void tg_tlwalk_start(tg_tlwalk_t *w, const uint8_t *buf, uint32_t len)
{
    tg_memset(w, 0, sizeof *w);
    tg_tlr_init(&w->r, buf, len);
}

int tg_tlwalk_next(tg_tlwalk_t *w)
{
    if (w->err)
        return TG_WE_ERROR;
    if (!w->started) {
        w->started = 1;
        if (w->r.len >= 4 && tg_rd32(w->r.p) == TL_vector) {
            uint32_t n;
            tg_tlr_u32(&w->r);
            n = tg_tlr_u32(&w->r);
            if (w->r.err)
                return fail(w, TG_WERR_TRUNC, 4);
            if (n > (w->r.len - w->r.pos) / 4)
                return fail(w, TG_WERR_FORMAT, n);
            if (push(w, 0, 1, n, ROOT_OBJ, -1))
                return TG_WE_ERROR;
            w->cid = 0;
            w->field = -1;
            w->count = n;
            return TG_WE_VEC;
        }
        return value(w, ROOT_OBJ, 0, -1, 0);
    }
    for (;;) {
        tg_twf_t *f;
        uint32_t off;
        uint8_t b;
        if (!w->sp)
            return TG_WE_END;
        f = &w->st[w->sp - 1];
        if (!f->left) {
            w->sp--;
            w->cid = f->cid;
            w->field = f->field;
            w->pcid = w->sp ? w->st[w->sp - 1].cid : 0;
            w->pfield = w->sp ? w->st[w->sp - 1].field : -1;
            return f->is_vec ? TG_WE_VEC_END : TG_WE_OBJ_END;
        }
        f->left--;
        if (f->is_vec)
            return value(w, f->desc, f->cid, f->field, 1);
        off = f->desc;
        b = TL_DESC[off];
        f->desc = (uint16_t)(off + desc_len(off));
        f->field++;
        if (b & 0x80) {
            uint32_t word = (b & 0x40) ? f->flags2 : f->flags;
            if (!((word >> TL_DESC[off + 1]) & 1))
                continue;                                /* absent conditional field */
        }
        return value(w, off, f->cid, f->field, 0);
    }
}

int tg_tlwalk_skip(tg_tlwalk_t *w)
{
    int base = w->sp - 1, e;
    while (w->sp > base) {
        e = tg_tlwalk_next(w);
        if (e == TG_WE_ERROR || e == TG_WE_END)
            return e;
    }
    return TG_WE_END;
}
