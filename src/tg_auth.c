/* tg_auth.c - MTProto auth key exchange, ported from TDLib td/mtproto/Handshake.cpp (AuthKeyHandshake,
 * Mode::Main), DhHandshake.cpp, RSA.cpp and Transport.cpp (Boost Software License 1.0). Comments name
 * the TDLib function. The heavy parts (pq factoring, the RSA modexp, g^b and g_a^b) each get a state
 * and run budget-limited across tg_auth_poll calls; see tg_proto.h for the calling contract.
 *
 * Derived from TDLib, Copyright Aliaksei Levin, Arseny Smirnov 2014-2026, distributed under the
 * Boost Software License 1.0 (LICENSE_1_0.txt). Changes: C port for small freestanding targets;
 * see THIRD_PARTY.md. */
#include "tg_mtp.h"
#include "tg_keys.h"

#define ID_REQ_PQ_MULTI          0xbe7e8ef1u
#define ID_RES_PQ                0x05162463u
#define ID_VECTOR                0x1cb5c415u
#define ID_P_Q_INNER_DATA_DC     0xa9f55f95u
#define ID_REQ_DH_PARAMS         0xd712e4beu
#define ID_SERVER_DH_PARAMS_OK   0xd0e8075cu
#define ID_SERVER_DH_PARAMS_FAIL 0x79cb045du
#define ID_SERVER_DH_INNER_DATA  0xb5890dbau
#define ID_CLIENT_DH_INNER_DATA  0x6643b654u
#define ID_SET_CLIENT_DH_PARAMS  0xf5045f1fu
#define ID_DH_GEN_OK             0x3bcbf734u
#define ID_DH_GEN_RETRY          0x46dc1fb9u
#define ID_DH_GEN_FAIL           0xa69dae02u

/* Each SEND_x is followed by WAIT_x (tg_auth_sent) and then the state that handles the reply
 * (tg_auth_input): both just step to state + 1. */
enum {
    S_IDLE,
    S_SEND_PQ, S_WAIT_PQ, S_RES_PQ, S_FACTOR, S_INNER, S_RSA_PAD, S_RSA,
    S_SEND_DH, S_WAIT_DH, S_DH_PARAMS, S_GB, S_KEY,
    S_SEND_CLIENT, S_WAIT_GEN, S_GEN,
    S_DONE, S_ERROR,
};

/* error_arg for TG_AERR_PARSE / TG_AERR_NONCE: which message */
enum { M_RES_PQ = 1, M_DH_PARAMS, M_DH_INNER, M_DH_GEN };

static void wipe_secrets(tg_auth_t *a)
{
    tg_wipe(a->new_nonce, sizeof a->new_nonce);
    tg_wipe(a->tmp_key, sizeof a->tmp_key);
    tg_wipe(a->tmp_iv, sizeof a->tmp_iv);
    tg_wipe(a->b, sizeof a->b);
    tg_wipe(a->rsa_in, sizeof a->rsa_in);
    tg_wipe(a->scratch, sizeof a->scratch);
    tg_wipe(&a->me, sizeof a->me);
}

static int fail(tg_auth_t *a, int err, int32_t arg)
{
    wipe_secrets(a);
    tg_wipe(a->auth_key, sizeof a->auth_key);
    a->error = err;
    a->error_arg = arg;
    a->state = S_ERROR;
    return TG_AUTH_ERROR;
}

/* Transport.cpp write_no_crypto + NoCryptoImpl::do_store: auth_key_id 0, msg_id, length, body.
 * TDLib sends msg_id 0 and random padding here; we send a real msg_id (server time << 32, low word a
 * counter, divisible by 4) and no padding, which keeps set_client_DH_params inside out[]. */
static void msg_begin(tg_auth_t *a, tg_tlw_t *w)
{
    tg_tlw_init(w, a->out, sizeof a->out);
    tg_tlw_u64(w, 0, 0);
    a->msg_seq++;
    tg_tlw_u64(w, a->msg_seq << 2, a->now + (uint32_t)a->time_offset);
    tg_tlw_u32(w, 0);                               /* message_data_length, set by msg_end */
}

static int msg_end(tg_auth_t *a, tg_tlw_t *w, int next)
{
    if (w->err)
        return fail(a, TG_AERR_SIZE, (int32_t)next);
    tg_wr32(a->out + 16, w->len - 20);
    a->out_len = w->len;
    a->state = next;
    return TG_AUTH_SEND;
}

/* Transport.cpp read_no_crypto. A 4-byte packet is a transport error code (e.g. -404).
 * Returns 0 with r over the body, or TG_AUTH_ERROR. */
static int msg_open(tg_auth_t *a, tg_tlr_t *r)
{
    uint32_t n = a->in_len, z = 0, len, i;
    if (n == 4)
        return fail(a, TG_AERR_TRANSPORT, (int32_t)tg_rd32(a->in));
    if (n < 20)
        return fail(a, TG_AERR_PARSE, (int32_t)n);
    for (i = 0; i < 8; i++)
        z |= a->in[i];
    len = tg_rd32(a->in + 16);
    if (z || len > n - 20)
        return fail(a, TG_AERR_PARSE, (int32_t)n);
    tg_tlr_init(r, a->in + 20, len);
    return 0;
}

/* PublicRsaKeySharedMain::create(is_test): test DCs are sent as dc + 10000 (media DCs negative) and
 * have their own RSA key */
static int test_dc(const tg_auth_t *a)
{
    return a->dc >= 10000 || a->dc <= -10000;
}

static const uint8_t *rsa_n(const tg_auth_t *a)
{
    return test_dc(a) ? TG_RSA_TEST_N : TG_RSA_N;
}

static void rsa_fp(const tg_auth_t *a, uint32_t *lo, uint32_t *hi)
{
    *lo = test_dc(a) ? TG_RSA_TEST_FP_LO : TG_RSA_FP_LO;
    *hi = test_dc(a) ? TG_RSA_TEST_FP_HI : TG_RSA_FP_HI;
}

/* reads nonce + server_nonce; returns nonzero if either differs (check r->err first) */
static int nonces_bad(const tg_auth_t *a, tg_tlr_t *r)
{
    uint8_t n[16], s[16];
    tg_tlr_raw(r, n, 16);
    tg_tlr_raw(r, s, 16);
    return tg_be_cmp(n, a->nonce, 16) || tg_be_cmp(s, a->server_nonce, 16);
}

/* a small number as a TL string, like BigNum::to_binary: big-endian, no leading zero bytes */
static void tlw_be64(tg_tlw_t *w, uint32_t lo, uint32_t hi)
{
    uint8_t b[8];
    uint32_t i = 0;
    for (int k = 0; k < 4; k++) {
        b[k] = (uint8_t)(hi >> (24 - 8 * k));
        b[4 + k] = (uint8_t)(lo >> (24 - 8 * k));
    }
    while (i < 7 && !b[i])
        i++;
    tg_tlw_bytes(w, b + i, 8 - i);
}

/* DhHandshake::dh_check: 2^(2048-64) <= x <= dh_prime - 2^(2048-64), x 256 bytes big-endian */
static int dh_range_ok(tg_auth_t *a, const uint8_t *x)
{
    uint8_t *lim = a->scratch;
    tg_memset(lim, 0, 256);
    lim[7] = 1;                                     /* 2^1984 */
    if (tg_be_cmp(x, lim, 256) < 0)
        return 0;
    tg_be_sub(lim, TG_DH_P, lim, 256);
    return tg_be_cmp(x, lim, 256) <= 0;
}

/* Handshake.cpp on_res_pq, first part: parse resPQ, pick our key, start factoring pq */
static int on_res_pq(tg_auth_t *a)
{
    tg_tlr_t r;
    uint8_t nonce[16];
    const uint8_t *pq;
    uint32_t len, cnt, lo, hi, fp_lo, fp_hi, i, found = 0;
    if (msg_open(a, &r))
        return TG_AUTH_ERROR;
    if (tg_tlr_u32(&r) != ID_RES_PQ)
        return fail(a, TG_AERR_PARSE, M_RES_PQ);
    tg_tlr_raw(&r, nonce, 16);
    tg_tlr_raw(&r, a->server_nonce, 16);
    pq = tg_tlr_bytes(&r, &len);
    if (tg_tlr_u32(&r) != ID_VECTOR)
        r.err = 1;
    cnt = tg_tlr_u32(&r);
    rsa_fp(a, &fp_lo, &fp_hi);
    for (i = 0; i < cnt && !r.err; i++) {           /* each entry takes 8 bytes: bounded by the packet */
        tg_tlr_u64(&r, &lo, &hi);
        if (!r.err && lo == fp_lo && hi == fp_hi)
            found = 1;
    }
    if (r.err || !pq || !len || len > 8)
        return fail(a, TG_AERR_PARSE, M_RES_PQ);
    if (tg_be_cmp(nonce, a->nonce, 16))
        return fail(a, TG_AERR_NONCE, M_RES_PQ);
    if (!found)                                     /* PublicRsaKeyInterface::get_rsa_key */
        return fail(a, TG_AERR_NO_KEY, (int32_t)cnt);
    lo = hi = 0;
    for (i = 0; i < len; i++) {
        hi = hi << 8 | lo >> 24;
        lo = lo << 8 | pq[i];
    }
    a->pq_lo = lo;
    a->pq_hi = hi;
    tg_pq_start(&a->pq, (uint64_t)hi << 32 | lo);  /* pq_factorize */
    a->state = S_FACTOR;
    return TG_AUTH_BUSY;
}

/* Handshake.cpp on_res_pq: p_q_inner_data_dc, padded with random bytes to 192 */
static int inner_data(tg_auth_t *a)
{
    tg_tlw_t w;
    tg_rng_bytes(&a->rng, a->new_nonce, 32);
    tg_tlw_init(&w, a->scratch, 144);               /* TDLib: "Too big data" above 144 */
    tg_tlw_u32(&w, ID_P_Q_INNER_DATA_DC);
    tlw_be64(&w, a->pq_lo, a->pq_hi);
    tlw_be64(&w, a->p, 0);
    tlw_be64(&w, a->q, 0);
    tg_tlw_raw(&w, a->nonce, 16);
    tg_tlw_raw(&w, a->server_nonce, 16);
    tg_tlw_raw(&w, a->new_nonce, 32);
    tg_tlw_u32(&w, (uint32_t)a->dc);
    if (w.err)
        return fail(a, TG_AERR_SIZE, S_INNER);
    tg_rng_bytes(&a->rng, a->scratch + w.len, 192 - w.len);
    a->state = S_RSA_PAD;
    return TG_AUTH_BUSY;
}

static void reverse(uint8_t *p, uint32_t n)
{
    for (uint32_t i = 0, j = n - 1; i < j; i++, j--) {
        uint8_t t = p[i];
        p[i] = p[j];
        p[j] = t;
    }
}

/* Handshake.cpp on_res_pq, the RSA_PAD loop, one try per poll; RSA.cpp encrypt: an input >= n
 * is rejected and the loop tries a new temporary key. On success starts x^e mod n. */
static int rsa_pad(tg_auth_t *a)
{
    static const uint8_t e[3] = { 0x01, 0x00, 0x01 };
    uint8_t *data = a->scratch, *key = a->tmp_key, hash[32];
    tg_sha256_t h;
    uint32_t i;
    int ok;
    tg_rng_bytes(&a->rng, key, 32);
    /* data_with_hash := reverse(data) + SHA256(temp_key + data) */
    tg_sha256_init(&h);
    tg_sha256_update(&h, key, 32);
    tg_sha256_update(&h, data, 192);
    tg_sha256_final(&h, data + 192);
    reverse(data, 192);
    /* aes_encrypted := AES256_IGE(data_with_hash, temp_key, iv 0) */
    tg_memset(a->tmp_iv, 0, 32);
    tg_aes_ige_encrypt(key, a->tmp_iv, data, a->rsa_in + 32, 224);
    reverse(data, 192);                             /* back to data, for another try */
    /* temp_key_xor := temp_key XOR SHA256(aes_encrypted) */
    tg_sha256(a->rsa_in + 32, 224, hash);
    for (i = 0; i < 32; i++)
        a->rsa_in[i] = key[i] ^ hash[i];
    tg_wipe(key, 32);
    tg_wipe(hash, sizeof hash);
    tg_wipe(&h, sizeof h);
    ok = tg_be_cmp(a->rsa_in, rsa_n(a), 256) < 0;
    if (!ok)
        return TG_AUTH_BUSY;
    tg_wipe(a->scratch, sizeof a->scratch);
    if (tg_modexp_start(&a->me, a->rsa_in, 256, e, 3, rsa_n(a), 256))
        return fail(a, TG_AERR_STATE, S_RSA_PAD);
    a->state = S_RSA;
    return TG_AUTH_BUSY;
}

/* Handshake.cpp on_res_pq, end: req_DH_params with encrypted_data = RSA result */
static int req_dh_params(tg_auth_t *a)
{
    tg_tlw_t w;
    uint32_t fp_lo, fp_hi;
    tg_modexp_result(&a->me, a->rsa_in);
    tg_wipe(&a->me, sizeof a->me);                  /* held the RSA plaintext */
    msg_begin(a, &w);
    tg_tlw_u32(&w, ID_REQ_DH_PARAMS);
    tg_tlw_raw(&w, a->nonce, 16);
    tg_tlw_raw(&w, a->server_nonce, 16);
    tlw_be64(&w, a->p, 0);
    tlw_be64(&w, a->q, 0);
    rsa_fp(a, &fp_lo, &fp_hi);
    tg_tlw_u64(&w, fp_lo, fp_hi);
    tg_tlw_bytes(&w, a->rsa_in, 256);
    return msg_end(a, &w, S_SEND_DH);
}

/* Handshake.cpp on_server_dh_params, first half: decrypt and check the answer, then the DH config
 * (DhHandshake::check_config, dh_check on g_a), and start g^b (DhHandshake::set_config) */
static int on_dh_params(tg_auth_t *a)
{
    tg_tlr_t r, ir;
    const uint8_t *ans, *prime, *ga;
    uint8_t nonce[16], snonce[16], sha[20], g;
    uint32_t id, len, off, plen, galen, stime;
    if (msg_open(a, &r))
        return TG_AUTH_ERROR;
    id = tg_tlr_u32(&r);
    if (id == ID_SERVER_DH_PARAMS_FAIL)
        return fail(a, TG_AERR_DH_FAIL, 0);
    if (id != ID_SERVER_DH_PARAMS_OK)
        return fail(a, TG_AERR_PARSE, M_DH_PARAMS);
    id = (uint32_t)nonces_bad(a, &r);
    ans = tg_tlr_bytes(&r, &len);
    if (r.err || !ans)
        return fail(a, TG_AERR_PARSE, M_DH_PARAMS);
    if (id)
        return fail(a, TG_AERR_NONCE, M_DH_PARAMS);
    if ((len & 15) || len < 32)                     /* "Bad padding for encrypted part" */
        return fail(a, TG_AERR_PARSE, M_DH_PARAMS);

    /* answer_with_hash := SHA1(answer) + answer + (0-15 random bytes), decrypted in place */
    off = (uint32_t)(ans - a->in);
    tg_kdf_tmp(a->server_nonce, a->new_nonce, a->tmp_key, a->tmp_iv);
    tg_aes_ige_decrypt(a->tmp_key, a->tmp_iv, a->in + off, a->in + off, len);
    tg_wipe(a->tmp_key, sizeof a->tmp_key);         /* derived again for set_client_DH_params */
    tg_wipe(a->tmp_iv, sizeof a->tmp_iv);
    tg_tlr_init(&ir, a->in + off + 20, len - 20);
    if (tg_tlr_u32(&ir) != ID_SERVER_DH_INNER_DATA)
        return fail(a, TG_AERR_PARSE, M_DH_INNER);
    tg_tlr_raw(&ir, nonce, 16);
    tg_tlr_raw(&ir, snonce, 16);
    a->g = tg_tlr_u32(&ir);
    prime = tg_tlr_bytes(&ir, &plen);
    ga = tg_tlr_bytes(&ir, &galen);
    stime = tg_tlr_u32(&ir);
    if (ir.err || !prime || !ga || ir.len - ir.pos >= 16)  /* "Too much pad" */
        return fail(a, TG_AERR_PARSE, M_DH_INNER);
    tg_sha1(a->in + off + 20, ir.pos, sha);
    if (tg_be_cmp(sha, a->in + off, 20))
        return fail(a, TG_AERR_HASH, 0);
    if (tg_be_cmp(nonce, a->nonce, 16) || tg_be_cmp(snonce, a->server_nonce, 16))
        return fail(a, TG_AERR_NONCE, M_DH_INNER);
    a->time_offset = (int32_t)(stime - a->now);

    /* check_config: TDLib's cached good-prime path, against the one prime the DCs use. With it only
     * the generators in TG_DH_G_OK pass the p mod 4g test. */
    if (plen != 256 || tg_be_cmp(prime, TG_DH_P, 256))
        return fail(a, TG_AERR_DH_PRIME, 0);
    if (a->g > 7 || !((TG_DH_G_OK >> a->g) & 1))
        return fail(a, TG_AERR_DH_PRIME, (int32_t)a->g);
    if (galen > 256)
        return fail(a, TG_AERR_PARSE, M_DH_INNER);
    tg_memset(a->g_a, 0, 256 - galen);
    tg_memcpy(a->g_a + 256 - galen, ga, galen);
    if (!dh_range_ok(a, a->g_a))
        return fail(a, TG_AERR_DH_RANGE, 1);

    /* set_config: b = 2048 random bits (BigNum::random(b, 2048, -1, 0)), g_b = g^b mod p */
    tg_rng_bytes(&a->rng, a->b, 256);
    g = (uint8_t)a->g;
    if (tg_modexp_start(&a->me, &g, 1, a->b, 256, TG_DH_P, 256))
        return fail(a, TG_AERR_STATE, S_DH_PARAMS);
    a->state = S_GB;
    return TG_AUTH_BUSY;
}

/* run_checks (dh_check on g_b), then gen_key: g_ab = g_a^b mod p */
static int got_g_b(tg_auth_t *a)
{
    tg_modexp_result(&a->me, a->g_b);
    if (!dh_range_ok(a, a->g_b))
        return fail(a, TG_AERR_DH_RANGE, 2);
    if (tg_modexp_start(&a->me, a->g_a, 256, a->b, 256, TG_DH_P, 256))
        return fail(a, TG_AERR_STATE, S_GB);
    a->state = S_KEY;
    return TG_AUTH_BUSY;
}

/* DhHandshake::gen_key / calc_key_id, then Handshake.cpp on_server_dh_params, second half:
 * client_DH_inner_data, set_client_DH_params, server_salt */
static int set_client_dh_params(tg_auth_t *a)
{
    tg_tlw_t w;
    uint8_t h[20], buf[41];
    uint32_t n, i;
    tg_modexp_result(&a->me, a->auth_key);
    tg_wipe(&a->me, sizeof a->me);
    tg_wipe(a->b, sizeof a->b);
    tg_sha1(a->auth_key, 256, h);
    tg_memcpy(a->auth_key_id, h + 12, 8);

    /* encrypted_data := AES256_IGE(SHA1(data) + data + (0-15 random bytes), tmp_aes_key, tmp_aes_iv) */
    tg_tlw_init(&w, a->scratch + 20, sizeof a->scratch - 20);
    tg_tlw_u32(&w, ID_CLIENT_DH_INNER_DATA);
    tg_tlw_raw(&w, a->nonce, 16);
    tg_tlw_raw(&w, a->server_nonce, 16);
    tg_tlw_u64(&w, 0, 0);                           /* retry_id */
    tg_tlw_bytes(&w, a->g_b, 256);
    if (w.err)
        return fail(a, TG_AERR_SIZE, S_KEY);
    tg_sha1(a->scratch + 20, w.len, a->scratch);
    n = (20 + w.len + 15) & ~15u;
    if (n > sizeof a->scratch)
        return fail(a, TG_AERR_SIZE, S_KEY);
    tg_rng_bytes(&a->rng, a->scratch + 20 + w.len, n - 20 - w.len);
    tg_kdf_tmp(a->server_nonce, a->new_nonce, a->tmp_key, a->tmp_iv);
    tg_aes_ige_encrypt(a->tmp_key, a->tmp_iv, a->scratch, a->scratch, n);
    tg_wipe(a->tmp_key, sizeof a->tmp_key);
    tg_wipe(a->tmp_iv, sizeof a->tmp_iv);

    msg_begin(a, &w);
    tg_tlw_u32(&w, ID_SET_CLIENT_DH_PARAMS);
    tg_tlw_raw(&w, a->nonce, 16);
    tg_tlw_raw(&w, a->server_nonce, 16);
    tg_tlw_bytes(&w, a->scratch, n);
    tg_wipe(a->scratch, sizeof a->scratch);

    /* server_salt := substr(new_nonce, 0, 8) XOR substr(server_nonce, 0, 8) */
    for (i = 0; i < 8; i++)
        a->server_salt[i] = a->new_nonce[i] ^ a->server_nonce[i];
    /* on_dh_gen_response needs only new_nonce_hash1 = substr(SHA1(new_nonce + 0x01 + auth_key_aux_hash), 4, 16),
     * auth_key_aux_hash = substr(SHA1(auth_key), 0, 8). Keep it in tmp_iv and wipe new_nonce. */
    tg_memcpy(buf, a->new_nonce, 32);
    buf[32] = 1;
    tg_memcpy(buf + 33, h, 8);
    tg_sha1(buf, 41, h);
    tg_memcpy(a->tmp_iv, h + 4, 16);
    tg_wipe(buf, sizeof buf);
    tg_wipe(h, sizeof h);
    tg_wipe(a->new_nonce, sizeof a->new_nonce);

    return msg_end(a, &w, S_SEND_CLIENT);
}

/* Handshake.cpp on_dh_gen_response: dh_gen_retry and dh_gen_fail end the attempt, as in TDLib */
static int on_dh_gen(tg_auth_t *a)
{
    tg_tlr_t r;
    uint8_t hash[16];
    uint32_t id;
    int bad;
    if (msg_open(a, &r))
        return TG_AUTH_ERROR;
    id = tg_tlr_u32(&r);
    if (id != ID_DH_GEN_OK && id != ID_DH_GEN_RETRY && id != ID_DH_GEN_FAIL)
        return fail(a, TG_AERR_PARSE, M_DH_GEN);
    bad = nonces_bad(a, &r);
    tg_tlr_raw(&r, hash, 16);
    if (r.err)
        return fail(a, TG_AERR_PARSE, M_DH_GEN);
    if (bad)
        return fail(a, TG_AERR_NONCE, M_DH_GEN);
    if (id == ID_DH_GEN_RETRY)
        return fail(a, TG_AERR_RETRY, 0);
    if (id == ID_DH_GEN_FAIL)
        return fail(a, TG_AERR_GEN, 0);
    if (tg_be_cmp(hash, a->tmp_iv, 16))             /* "New nonce hash mismatch" */
        return fail(a, TG_AERR_GEN, 1);
    tg_wipe(a->tmp_iv, sizeof a->tmp_iv);
    a->state = S_DONE;
    return TG_AUTH_DONE;
}

void tg_auth_start(tg_auth_t *a, int dc, uint32_t unixtime)
{
    tg_rng_t rng;
    tg_tlw_t w;
    tg_memcpy(&rng, &a->rng, sizeof rng);
    tg_wipe(a, sizeof *a);
    tg_memcpy(&a->rng, &rng, sizeof rng);
    tg_wipe(&rng, sizeof rng);
    a->dc = dc;
    a->now = unixtime;
    /* Handshake.cpp on_start: req_pq_multi */
    tg_rng_bytes(&a->rng, a->nonce, 16);
    msg_begin(a, &w);
    tg_tlw_u32(&w, ID_REQ_PQ_MULTI);
    tg_tlw_raw(&w, a->nonce, 16);
    msg_end(a, &w, S_SEND_PQ);
}

int tg_auth_poll(tg_auth_t *a, uint32_t unixtime, uint32_t budget)
{
    a->now = unixtime;
    switch (a->state) {
    case S_SEND_PQ: case S_SEND_DH: case S_SEND_CLIENT:
        return TG_AUTH_SEND;
    case S_WAIT_PQ: case S_WAIT_DH: case S_WAIT_GEN:
        return TG_AUTH_WAIT;
    case S_RES_PQ:
        return on_res_pq(a);
    case S_FACTOR:
        if (!tg_pq_step(&a->pq, budget))
            return TG_AUTH_BUSY;
        if (!a->pq.p_out)
            return fail(a, TG_AERR_PQ, 0);
        a->p = a->pq.p_out;
        a->q = a->pq.q_out;
        a->state = S_INNER;
        return TG_AUTH_BUSY;
    case S_INNER:
        return inner_data(a);
    case S_RSA_PAD:
        return rsa_pad(a);
    case S_RSA:
        return tg_modexp_step(&a->me, budget) ? req_dh_params(a) : TG_AUTH_BUSY;
    case S_DH_PARAMS:
        return on_dh_params(a);
    case S_GB:
        return tg_modexp_step(&a->me, budget) ? got_g_b(a) : TG_AUTH_BUSY;
    case S_KEY:
        return tg_modexp_step(&a->me, budget) ? set_client_dh_params(a) : TG_AUTH_BUSY;
    case S_GEN:
        return on_dh_gen(a);
    case S_DONE:
        return TG_AUTH_DONE;
    case S_ERROR:
        return TG_AUTH_ERROR;
    default:                                        /* tg_auth_start not called */
        return fail(a, TG_AERR_STATE, a->state);
    }
}

void tg_auth_sent(tg_auth_t *a)
{
    if (a->state == S_SEND_PQ || a->state == S_SEND_DH || a->state == S_SEND_CLIENT)
        a->state++;
    else if (a->state != S_ERROR && a->state != S_DONE)
        fail(a, TG_AERR_STATE, a->state);
}

/* A packet in any state but WAIT is a caller error; one after DONE / ERROR is ignored. */
void tg_auth_input(tg_auth_t *a, const uint8_t *pkt, uint32_t len)
{
    if (a->state == S_DONE || a->state == S_ERROR)
        return;
    if (a->state != S_WAIT_PQ && a->state != S_WAIT_DH && a->state != S_WAIT_GEN) {
        fail(a, TG_AERR_STATE, a->state);
        return;
    }
    if (len > sizeof a->in) {
        fail(a, TG_AERR_SIZE, (int32_t)len);
        return;
    }
    tg_memcpy(a->in, pkt, len);
    a->in_len = len;
    a->state++;
}
