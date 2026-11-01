/* tg_proto.h - RNG, TL serialisation and the MTProto auth key exchange (no I/O, no globals).
 *
 * Derived from TDLib, Copyright Aliaksei Levin, Arseny Smirnov 2014-2026, distributed under the
 * Boost Software License 1.0 (LICENSE_1_0.txt). Changes: C port for small freestanding targets;
 * see THIRD_PARTY.md. */
#ifndef TG_PROTO_H
#define TG_PROTO_H

#include "tg_crypto.h"

/* ---- RNG: SHA-256 hash pool. Feed it every bit of entropy you have (tg_rng_add); output blocks
 * are SHA256(pool || counter) and the pool is re-hashed after each request (backtracking
 * resistance). It is only as good as what was added: give it real entropy from the host. */
typedef struct { uint8_t pool[32]; uint32_t ctr; uint32_t added; } tg_rng_t;
void tg_rng_init(tg_rng_t *r);
void tg_rng_add(tg_rng_t *r, const void *data, uint32_t len);
void tg_rng_bytes(tg_rng_t *r, void *out, uint32_t len);

/* ---- TL writer / reader over caller buffers. Errors are sticky (err != 0) so a whole object
 * can be written or parsed and checked once at the end. Integers are little-endian. */
typedef struct { uint8_t *p; uint32_t cap, len; int err; } tg_tlw_t;
typedef struct { const uint8_t *p; uint32_t len, pos; int err; } tg_tlr_t;
void tg_tlw_init(tg_tlw_t *w, uint8_t *buf, uint32_t cap);
void tg_tlw_u32(tg_tlw_t *w, uint32_t v);
void tg_tlw_u64(tg_tlw_t *w, uint32_t lo, uint32_t hi);
void tg_tlw_raw(tg_tlw_t *w, const void *data, uint32_t len);
void tg_tlw_bytes(tg_tlw_t *w, const void *data, uint32_t len);     /* TL "bytes"/"string" */
void tg_tlr_init(tg_tlr_t *r, const uint8_t *buf, uint32_t len);
uint32_t tg_tlr_u32(tg_tlr_t *r);
void tg_tlr_u64(tg_tlr_t *r, uint32_t *lo, uint32_t *hi);
void tg_tlr_raw(tg_tlr_t *r, void *out, uint32_t len);
const uint8_t *tg_tlr_bytes(tg_tlr_t *r, uint32_t *len);            /* points into the buffer */
uint32_t tg_rd32(const uint8_t *p);
void tg_wr32(uint8_t *p, uint32_t v);

/* ---- auth key exchange, ported from TDLib td/mtproto/Handshake.cpp (AuthKeyHandshake, Mode::Main),
 * DhHandshake.cpp and RSA.cpp (Boost Software License 1.0). As in TDLib, dh_gen_retry and
 * dh_gen_fail end the attempt (start again with a new tg_auth_start). ----
 * Usage, from a timer:
 *   tg_auth_start(a, dc, unixtime) once (feed a->rng first), then loop:
 *     st = tg_auth_poll(a, unixtime, budget)
 *     TG_AUTH_SEND:  transmit a->out[0..out_len) as one transport packet, then tg_auth_sent(a)
 *     TG_AUTH_WAIT:  when a packet arrives, tg_auth_input(a, pkt, len)
 *     TG_AUTH_BUSY:  heavy work pending (factoring, RSA, DH): poll again on the next tick
 *     TG_AUTH_DONE:  a->auth_key, a->auth_key_id, a->server_salt, a->time_offset are valid
 *     TG_AUTH_ERROR: a->error says why (TG_AERR_*), a->error_arg has detail */
enum { TG_AUTH_BUSY, TG_AUTH_SEND, TG_AUTH_WAIT, TG_AUTH_DONE, TG_AUTH_ERROR };
enum {
    TG_AERR_NONE, TG_AERR_TRANSPORT /* arg = negative transport code, e.g. -404 */, TG_AERR_PARSE,
    TG_AERR_NONCE, TG_AERR_NO_KEY, TG_AERR_PQ, TG_AERR_DH_FAIL /* server_DH_params_fail */,
    TG_AERR_HASH, TG_AERR_DH_PRIME, TG_AERR_DH_RANGE, TG_AERR_GEN /* dh_gen_fail / new nonce hash */,
    TG_AERR_RETRY /* dh_gen_retry */, TG_AERR_STATE, TG_AERR_SIZE,
};

typedef struct {
    int state, error;
    int32_t error_arg;
    int dc;                          /* sent in p_q_inner_data_dc: DC id, +10000 for test DCs */
    uint32_t now, msg_seq;
    int32_t time_offset;             /* server_time - local time, from server_DH_inner_data */
    tg_rng_t rng;
    uint8_t nonce[16], server_nonce[16], new_nonce[32];
    uint32_t pq_lo, pq_hi, p, q;
    uint8_t tmp_key[32], tmp_iv[32];
    uint32_t g;
    uint8_t g_a[256], b[256], g_b[256];
    uint8_t auth_key[256];
    uint8_t auth_key_id[8], server_salt[8];
    uint8_t rsa_in[256];             /* key_aes_encrypted, the RSA input */
    uint8_t scratch[352];            /* inner data being padded / hashed / encrypted */
    tg_pq_t pq;
    tg_modexp_t me;
    uint8_t out[640];
    uint32_t out_len;
    uint8_t in[1024];                /* last packet, kept until processed */
    uint32_t in_len;
} tg_auth_t;

void tg_auth_start(tg_auth_t *a, int dc, uint32_t unixtime);
int tg_auth_poll(tg_auth_t *a, uint32_t unixtime, uint32_t budget);
void tg_auth_sent(tg_auth_t *a);
void tg_auth_input(tg_auth_t *a, const uint8_t *pkt, uint32_t len);

#endif
