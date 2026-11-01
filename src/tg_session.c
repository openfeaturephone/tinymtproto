/* tg_session.c - MTProto 2.0 session layer, ported from TDLib td/mtproto/AuthData.cpp/.h and
 * td/mtproto/SessionConnection.cpp (Boost Software License 1.0). Comments name the TDLib function.
 * Times are whole unix seconds where TDLib uses doubles; see tg_session.h for the calling contract.
 *
 * Derived from TDLib, Copyright Aliaksei Levin, Arseny Smirnov 2014-2026, distributed under the
 * Boost Software License 1.0 (LICENSE_1_0.txt). Changes: C port for small freestanding targets;
 * see THIRD_PARTY.md. */
#include "tg_session.h"

#define ID_MSG_CONTAINER         0x73f1f8dcu
#define ID_RPC_RESULT            0xf35c6d01u
#define ID_RPC_ERROR             0x2144ca19u
#define ID_GZIP_PACKED           0x3072cfa1u
#define ID_PING                  0x7abe77ecu
#define ID_PING_DELAY_DISCONNECT 0xf3427b8cu
#define ID_PONG                  0x347773c5u
#define ID_MSGS_ACK              0x62d6b459u
#define ID_VECTOR                0x1cb5c415u
#define ID_BAD_MSG_NOTIFICATION  0xa7eff811u
#define ID_BAD_SERVER_SALT       0xedab447bu
#define ID_NEW_SESSION_CREATED   0x9ec20908u
/* service messages that need nothing from us (beyond the ack their seq_no asks for) */
#define ID_FUTURE_SALTS          0xae500895u
#define ID_MSGS_STATE_REQ        0xda69fb52u
#define ID_MSGS_STATE_INFO       0x04deb57du
#define ID_MSGS_ALL_INFO         0x8cc0d131u
#define ID_MSG_DETAILED_INFO     0x276d3ec6u
#define ID_MSG_NEW_DETAILED_INFO 0x809db6dfu
#define ID_MSG_RESEND_REQ        0x7d861a08u
#define ID_DESTROY_AUTH_KEY_OK   0xf660e1d4u
#define ID_DESTROY_AUTH_KEY_NONE 0x0a9f2259u
#define ID_DESTROY_AUTH_KEY_FAIL 0xea109b13u
#define ID_DESTROY_SESSION_OK    0xe22045fcu
#define ID_DESTROY_SESSION_NONE  0x62d350c9u

/* bad_msg_notification error codes (SessionConnection::on_packet(bad_msg_notification)) */
#define MSG_ID_TOO_LOW  16
#define MSG_ID_TOO_HIGH 17
#define MSG_ID_TOO_OLD  20

static uint64_t rd64(const uint8_t *p) { return (uint64_t)tg_rd32(p) | (uint64_t)tg_rd32(p + 4) << 32; }
static void wr64(uint8_t *p, uint64_t v) { tg_wr32(p, (uint32_t)v); tg_wr32(p + 4, (uint32_t)(v >> 32)); }

static uint64_t tlr_u64(tg_tlr_t *r)
{
    uint32_t lo, hi;
    tg_tlr_u64(r, &lo, &hi);
    return (uint64_t)hi << 32 | lo;
}

/* AuthData.cpp: check_message_id_duplicates. ids holds 2 * max entries, sorted up to *end.
 * Returns 0 (new, remembered), 1 (already seen) or 2 (older than everything remembered). */
static int dup_check(uint64_t *ids, uint32_t max, uint32_t *end_pos, uint64_t id)
{
    uint32_t end = *end_pos, lo = 0, hi, i;
    if (end == 2 * max) {
        for (i = 0; i < max; i++)
            ids[i] = ids[max + i];
        end = max;
    }
    *end_pos = end;
    if (end == 0 || id > ids[end - 1]) {
        ids[end] = id;
        *end_pos = end + 1;
        return 0;
    }
    if (end >= max && id < ids[0])
        return 2;
    hi = end;
    while (lo < hi) {                               /* std::lower_bound */
        uint32_t mid = (lo + hi) >> 1;
        if (ids[mid] < id)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (ids[lo] == id)
        return 1;
    for (i = end; i > lo; i--)
        ids[i] = ids[i - 1];
    ids[lo] = id;
    *end_pos = end + 1;
    return 0;
}

static int32_t time_diff(const tg_sess_t *s, uint64_t msg_id)
{
    return (int32_t)((uint32_t)(msg_id >> 32) - s->now);
}

/* AuthData::update_server_time_difference: the offset only grows once it is set */
static void update_time(tg_sess_t *s, uint64_t msg_id)
{
    int32_t diff = time_diff(s, msg_id);
    if (!s->time_synced) {
        s->time_synced = 1;
        s->time_offset = diff;
    } else if (diff > s->time_offset) {
        s->time_offset = diff;
    }
}

/* AuthData::reset_server_time_difference */
static void reset_time(tg_sess_t *s, uint64_t msg_id)
{
    s->time_synced = 0;
    s->time_offset = time_diff(s, msg_id);
}

/* SessionConnection::on_packet_rpc_result / on_packet(pong): an answer stamped more than 15 s before
 * the request means our clock ran ahead */
static void check_answer_time(tg_sess_t *s, uint64_t msg_id, uint64_t req_msg_id)
{
    const uint64_t lag = (uint64_t)15 << 32;
    if (req_msg_id > lag && msg_id < req_msg_id - lag)
        reset_time(s, msg_id);
}

/* AuthData::is_valid_inbound_msg_id: server_time - 300 < id_time < server_time + 30 */
static int valid_inbound(const tg_sess_t *s, uint64_t msg_id)
{
    int32_t d = (int32_t)((uint32_t)(msg_id >> 32) - (s->now + (uint32_t)s->time_offset));
    return d > -300 && d < 30;
}

/* AuthData::next_message_id. The low word is random: we only know whole seconds. */
static uint64_t next_msg_id(tg_sess_t *s)
{
    uint8_t rb[4];
    uint32_t rx;
    uint64_t t;
    tg_rng_bytes(&s->rng, rb, 4);
    rx = tg_rd32(rb);
    t = (uint64_t)(s->now + (uint32_t)s->time_offset) << 32;
    t ^= rx & ((1u << 22) - 1);
    t &= ~(uint64_t)3;
    if (s->last_msg_id >= t)
        t = s->last_msg_id + 8 * (uint64_t)(((rx >> 22) & 1023) + 1);
    s->last_msg_id = t;
    return t;
}

/* AuthData::next_seq_no */
static uint32_t next_seq_no(tg_sess_t *s, int content_related)
{
    uint32_t r = s->seq_no;
    if (content_related) {
        r |= 1;
        s->seq_no += 2;
    }
    return r;
}

/* SessionConnection::send_ack */
static void add_ack(tg_sess_t *s, uint64_t msg_id)
{
    if (s->n_acks && s->acks[s->n_acks - 1] == msg_id)
        return;
    if (s->n_acks < TG_SESS_ACKS)
        s->acks[s->n_acks++] = msg_id;
}

int tg_sess_init(tg_sess_t *s, const uint8_t auth_key[256], const uint8_t salt[8], int32_t time_offset,
                 uint8_t *tx, uint32_t tx_cap)
{
    uint8_t h[20];
    uint32_t b;
    tg_memcpy(s->auth_key, auth_key, 256);
    tg_sha1(auth_key, 256, h);
    tg_memcpy(s->auth_key_id, h + 12, 8);
    tg_memcpy(s->salt, salt, 8);
    s->time_offset = time_offset;
    s->time_synced = 0;
    s->now = 0;
    s->last_msg_id = 0;
    s->tx = tx;
    s->tx_cap = tx_cap;
    s->body_cap = 0;
    tg_sess_new_session(s);
    if (tx_cap < TG_NET_HEADROOM + tg_mtp_packet_size(0))
        return -1;
    for (b = (tx_cap - TG_NET_HEADROOM - TG_MTP_HDR) & ~3u; b; b -= 4)
        if (TG_NET_HEADROOM + tg_mtp_packet_size(b) <= tx_cap)
            break;
    s->body_cap = b;
    return 0;
}

void tg_sess_new_session(tg_sess_t *s)
{
    tg_rng_bytes(&s->rng, s->session_id, 8);
    s->seq_no = 0;
    s->dup_end = s->upd_end = s->n_acks = 0;
    s->top = 0;
    s->cont_left = 0;
    s->err_arg = 0;
}

void tg_sess_wipe(tg_sess_t *s)
{
    tg_wipe(s, sizeof *s);
}

uint8_t *tg_sess_body(tg_sess_t *s)
{
    return s->tx + TG_NET_HEADROOM + TG_MTP_HDR;
}

/* SessionConnection::send_crypto / Transport::write: header, then tg_mtp_encrypt */
uint32_t tg_sess_send(tg_sess_t *s, uint32_t body_len, int content_related, uint32_t now, uint64_t *msg_id)
{
    uint8_t *p = s->tx + TG_NET_HEADROOM;
    uint64_t id;
    if (body_len > s->body_cap || body_len % 4)
        return 0;
    s->now = now;
    id = next_msg_id(s);
    tg_memcpy(p + 24, s->salt, 8);
    tg_memcpy(p + 32, s->session_id, 8);
    wr64(p + 40, id);
    tg_wr32(p + 48, next_seq_no(s, content_related));
    tg_wr32(p + 52, body_len);
    if (msg_id)
        *msg_id = id;
    return tg_mtp_encrypt(s->auth_key, s->auth_key_id, TG_X_CLIENT, &s->rng, p, body_len);
}

uint32_t tg_sess_ping(tg_sess_t *s, uint64_t ping_id, uint32_t disconnect_delay, uint32_t now, uint64_t *msg_id)
{
    tg_tlw_t w;
    tg_tlw_init(&w, tg_sess_body(s), s->body_cap);
    tg_tlw_u32(&w, disconnect_delay ? ID_PING_DELAY_DISCONNECT : ID_PING);
    tg_tlw_u64(&w, (uint32_t)ping_id, (uint32_t)(ping_id >> 32));
    if (disconnect_delay)
        tg_tlw_u32(&w, disconnect_delay);
    return w.err ? 0 : tg_sess_send(s, w.len, 1, now, msg_id);
}

/* msgs_ack as a message of its own (no outgoing containers). If the body does not fit, the rest
 * stays queued for the next call. */
uint32_t tg_sess_send_acks(tg_sess_t *s, uint32_t now)
{
    uint32_t n = s->n_acks, i, len;
    tg_tlw_t w;
    if (!n || s->body_cap < 20)
        return 0;
    if (n > (s->body_cap - 12) >> 3)
        n = (s->body_cap - 12) >> 3;
    tg_tlw_init(&w, tg_sess_body(s), s->body_cap);
    tg_tlw_u32(&w, ID_MSGS_ACK);
    tg_tlw_u32(&w, ID_VECTOR);
    tg_tlw_u32(&w, n);
    for (i = 0; i < n; i++)
        tg_tlw_u64(&w, (uint32_t)s->acks[i], (uint32_t)(s->acks[i] >> 32));
    len = tg_sess_send(s, w.len, 0, now, 0);
    if (len) {
        for (i = n; i < s->n_acks; i++)
            s->acks[i - n] = s->acks[i];
        s->n_acks -= n;
    }
    return len;
}

/* Transport::read + AuthData::check_packet + SessionConnection::on_raw_packet */
int tg_sess_input(tg_sess_t *s, uint8_t *pkt, uint32_t len, uint32_t now)
{
    uint32_t body_len;
    uint64_t id;
    int r;
    s->now = now;
    s->top = 0;
    s->cont_left = 0;
    s->err_arg = 0;
    if (len == 4) {
        s->err_arg = (int32_t)tg_rd32(pkt);
        return TG_SERR_TRANSPORT;
    }
    r = tg_mtp_decrypt(s->auth_key, s->auth_key_id, TG_X_SERVER, pkt, len, &body_len);
    if (r) {
        s->err_arg = r;
        return TG_SERR_DECRYPT;
    }
    if (tg_be_cmp(pkt + 32, s->session_id, 8))
        return TG_SERR_SESSION;
    id = rd64(pkt + 40);
    if (!(id & 1))
        return TG_SERR_MSG_ID;
    r = dup_check(s->dup, TG_SESS_DUP, &s->dup_end, id);
    if (r == 1) {
        add_ack(s, id);
        return 1;
    }
    if (r == 2)
        return TG_SERR_TOO_OLD;
    update_time(s, id);
    if (!valid_inbound(s, id))
        return TG_SERR_TIME;
    s->top = pkt + TG_MTP_HDR;
    s->top_len = body_len;
    s->top_id = id;
    s->top_seq = tg_rd32(pkt + 48);
    return 0;
}

static int fatal(tg_sess_t *s, tg_sev_t *ev, int code, int32_t arg)
{
    s->top = 0;
    s->cont_left = 0;
    s->err_arg = arg;
    ev->type = TG_EV_FATAL;
    ev->code = code;
    return TG_EV_FATAL;
}

static int event(tg_sev_t *ev, int type, const uint8_t *body, uint32_t len)
{
    ev->type = type;
    ev->body = body;
    ev->len = len;
    return type;
}

/* SessionConnection::on_packet_rpc_result */
static int on_rpc_result(tg_sess_t *s, uint64_t id, const uint8_t *body, uint32_t len, tg_sev_t *ev)
{
    tg_tlr_t r;
    const uint8_t *data;
    uint32_t n;
    tg_tlr_init(&r, body + 4, len - 4);
    ev->req_msg_id = tlr_u64(&r);
    if (r.err || !ev->req_msg_id)                   /* an update in rpc_result */
        return fatal(s, ev, TG_SERR_PARSE, (int32_t)ID_RPC_RESULT);
    check_answer_time(s, id, ev->req_msg_id);
    if (len < 16)
        return fatal(s, ev, TG_SERR_PARSE, (int32_t)ID_RPC_RESULT);
    switch (tg_rd32(body + 12)) {
    case ID_RPC_ERROR:
        tg_tlr_u32(&r);
        ev->code = (int32_t)tg_tlr_u32(&r);
        data = tg_tlr_bytes(&r, &n);
        if (r.err)
            return fatal(s, ev, TG_SERR_PARSE, (int32_t)ID_RPC_ERROR);
        return event(ev, TG_EV_ERROR, data, n);
    case ID_GZIP_PACKED:
        tg_tlr_u32(&r);
        data = tg_tlr_bytes(&r, &n);
        if (r.err)
            return fatal(s, ev, TG_SERR_PARSE, (int32_t)ID_GZIP_PACKED);
        ev->gzip = 1;
        return event(ev, TG_EV_RESULT, data, n);
    default:
        return event(ev, TG_EV_RESULT, body + 12, len - 12);
    }
}

/* SessionConnection::on_packet(bad_msg_notification) */
static int on_bad_msg(tg_sess_t *s, uint64_t id, int32_t code, tg_sev_t *ev)
{
    ev->code = code;
    switch (code) {
    case MSG_ID_TOO_LOW:                            /* the time offset grew from this message's id */
    case MSG_ID_TOO_OLD:
        ev->type = TG_EV_RESEND;
        return TG_EV_RESEND;
    case MSG_ID_TOO_HIGH:
        reset_time(s, id);
        return fatal(s, ev, TG_SERR_CLOCK, code);
    default:                                        /* msg_id mod 4, collision, seq_no, container */
        return fatal(s, ev, TG_SERR_BAD_MSG, code);
    }
}

/* SessionConnection::on_slice_packet: one message, at the top of a packet or inside a container */
static int on_message(tg_sess_t *s, uint64_t id, uint32_t seq, const uint8_t *body, uint32_t len, int in_cont,
                      tg_sev_t *ev)
{
    tg_tlr_t r;
    uint32_t cid, n;
    uint8_t salt[8];
    const uint8_t *data;
    if (seq & 1)
        add_ack(s, id);
    if (len < 4)
        return fatal(s, ev, TG_SERR_PARSE, 0);
    tg_tlr_init(&r, body, len);
    cid = tg_tlr_u32(&r);
    switch (cid) {
    case ID_MSG_CONTAINER:                          /* on_packet_container (no nesting) */
        s->cont_left = tg_tlr_u32(&r);
        if (in_cont || r.err)
            return fatal(s, ev, TG_SERR_PARSE, (int32_t)cid);
        tg_tlr_init(&s->cont, body + 8, len - 8);
        return TG_EV_NONE;
    case ID_RPC_RESULT:
        return on_rpc_result(s, id, body, len, ev);
    case ID_PONG:
        ev->req_msg_id = tlr_u64(&r);
        ev->id2 = tlr_u64(&r);
        if (r.err || r.pos != r.len)
            return fatal(s, ev, TG_SERR_PARSE, (int32_t)cid);
        check_answer_time(s, id, ev->req_msg_id);
        return event(ev, TG_EV_PONG, 0, 0);
    case ID_BAD_SERVER_SALT:
        ev->req_msg_id = tlr_u64(&r);
        tg_tlr_u32(&r);                             /* bad_msg_seqno */
        ev->code = (int32_t)tg_tlr_u32(&r);
        tg_tlr_raw(&r, salt, 8);
        if (r.err || r.pos != r.len)
            return fatal(s, ev, TG_SERR_PARSE, (int32_t)cid);
        tg_memcpy(s->salt, salt, 8);
        return event(ev, TG_EV_RESEND, 0, 0);
    case ID_BAD_MSG_NOTIFICATION:
        ev->req_msg_id = tlr_u64(&r);
        tg_tlr_u32(&r);
        n = tg_tlr_u32(&r);
        if (r.err || r.pos != r.len)
            return fatal(s, ev, TG_SERR_PARSE, (int32_t)cid);
        return on_bad_msg(s, id, (int32_t)n, ev);
    case ID_NEW_SESSION_CREATED:
        ev->req_msg_id = tlr_u64(&r);
        ev->id2 = tlr_u64(&r);
        tg_tlr_raw(&r, salt, 8);
        if (r.err || r.pos != r.len)
            return fatal(s, ev, TG_SERR_PARSE, (int32_t)cid);
        tg_memcpy(s->salt, salt, 8);                /* TDLib keeps its salt; this one is current */
        return event(ev, TG_EV_NEW_SESSION, 0, 0);
    case ID_MSGS_ACK:
    case ID_FUTURE_SALTS:
    case ID_MSGS_STATE_REQ:
    case ID_MSGS_STATE_INFO:
    case ID_MSGS_ALL_INFO:
    case ID_MSG_DETAILED_INFO:
    case ID_MSG_NEW_DETAILED_INFO:
    case ID_MSG_RESEND_REQ:
    case ID_DESTROY_AUTH_KEY_OK:
    case ID_DESTROY_AUTH_KEY_NONE:
    case ID_DESTROY_AUTH_KEY_FAIL:
    case ID_DESTROY_SESSION_OK:
    case ID_DESTROY_SESSION_NONE:
        return TG_EV_NONE;
    default:
        break;
    }
    /* an update (or gzip_packed, which TDLib inflates and dispatches again): AuthData::check_update */
    n = (uint32_t)dup_check(s->upd, TG_SESS_UPD, &s->upd_end, id);
    if (n == 2)
        return fatal(s, ev, TG_SERR_TOO_OLD, 0);
    if (n == 1)
        return TG_EV_NONE;
    if (cid == ID_GZIP_PACKED) {
        data = tg_tlr_bytes(&r, &n);
        if (r.err)
            return fatal(s, ev, TG_SERR_PARSE, (int32_t)cid);
        return event(ev, TG_EV_GZIP, data, n);
    }
    return event(ev, TG_EV_UPDATE, body, len);
}

/* SessionConnection::parse_packet / parse_message, one message per call */
int tg_sess_next(tg_sess_t *s, tg_sev_t *ev)
{
    for (;;) {
        uint64_t id;
        uint32_t seq, len;
        const uint8_t *body;
        int in_cont, t;
        tg_memset(ev, 0, sizeof *ev);
        if (s->cont_left) {
            tg_tlr_t *r = &s->cont;
            id = tlr_u64(r);
            seq = tg_tlr_u32(r);
            len = tg_tlr_u32(r);
            if (r->err || len % 4 || len > r->len - r->pos)
                return fatal(s, ev, TG_SERR_PARSE, (int32_t)ID_MSG_CONTAINER);
            body = r->p + r->pos;
            r->pos += len;
            s->cont_left--;
            in_cont = 1;
        } else if (s->top) {
            body = s->top;
            len = s->top_len;
            id = s->top_id;
            seq = s->top_seq;
            s->top = 0;
            in_cont = 0;
        } else {
            return TG_EV_NONE;
        }
        ev->msg_id = id;
        t = on_message(s, id, seq, body, len, in_cont, ev);
        if (t != TG_EV_NONE)
            return t;
    }
}
