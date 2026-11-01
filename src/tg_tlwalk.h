/* tg_tlwalk.h - walk any Telegram API object (layer TL_LAYER) with the generated schema tables
 * (tools/gen_tl.py -> tg_schema.c). A pull iterator with an explicit stack, no recursion, no allocation:
 *
 *   tg_tlwalk_start(w, body, len);                 body = an rpc_result / update object (boxed)
 *   while ((e = tg_tlwalk_next(w)) > TG_WE_END) {
 *       TG_WE_OBJ:   w->cid entered, sitting in field w->field of w->pcid (field -1: the root)
 *       TG_WE_FIELD: field w->field (TLF_x_y) of object w->cid, w->type, value in w->v32 / w->v64 /
 *                    w->val + w->len (string, bytes, raw numbers); w->in_vec: an element of a vector field
 *       TG_WE_VEC:   vector field w->field of w->cid with w->count elements
 *       TG_WE_OBJ_END / TG_WE_VEC_END
 *   }   e == TG_WE_END: done;  e == TG_WE_ERROR: w->err (TG_WERR_*), w->err_arg
 * tg_tlwalk_skip after TG_WE_OBJ / TG_WE_VEC skips that whole object or vector. Absent conditional
 * fields produce no event. A root that is a Vector is walked as a vector of objects. */
#ifndef TG_TLWALK_H
#define TG_TLWALK_H

#include "tg_proto.h"
#include "tg_schema.h"

enum { TG_TT_INT, TG_TT_LONG, TG_TT_DOUBLE, TG_TT_STRING, TG_TT_BYTES, TG_TT_BOOL, TG_TT_TRUE, TG_TT_FLAGS,
       TG_TT_OBJ, TG_TT_VECTOR, TG_TT_BVECTOR, TG_TT_INT128, TG_TT_INT256 };
enum { TG_WE_ERROR = -1, TG_WE_END = 0, TG_WE_OBJ, TG_WE_OBJ_END, TG_WE_FIELD, TG_WE_VEC, TG_WE_VEC_END };
enum { TG_WERR_TRUNC = 1, TG_WERR_UNKNOWN /* err_arg = constructor id */, TG_WERR_DEPTH, TG_WERR_FORMAT };

#define TG_TW_DEPTH 24

typedef struct {
    uint32_t cid;           /* object: its constructor; vector: the object holding the vector field */
    uint32_t flags, flags2;
    uint32_t left;          /* object: fields left; vector: elements left */
    uint16_t desc;          /* object: next field descriptor; vector: element descriptor */
    int16_t field;          /* object: field being read; vector: the vector's field index */
    uint8_t is_vec;
} tg_twf_t;

typedef struct {
    tg_tlr_t r;
    tg_twf_t st[TG_TW_DEPTH];
    int sp, started, err;
    uint32_t err_arg;
    /* current event */
    int type, field, in_vec, pfield;
    uint32_t cid, pcid, count, v32;
    uint64_t v64;
    const uint8_t *val;
    uint32_t len;
} tg_tlwalk_t;

void tg_tlwalk_start(tg_tlwalk_t *w, const uint8_t *buf, uint32_t len);
int tg_tlwalk_next(tg_tlwalk_t *w);
int tg_tlwalk_skip(tg_tlwalk_t *w);              /* returns TG_WE_END or TG_WE_ERROR */
int tg_tl_known(uint32_t cid);                    /* constructor in the schema? */

#endif
