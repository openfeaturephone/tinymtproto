/* tg_session.h - MTProto 2.0 session layer, ported from TDLib td/mtproto/AuthData.cpp/.h (message ids,
 * seq_no, inbound checks, server time) and td/mtproto/SessionConnection.cpp (parsing, containers,
 * rpc_result, service messages, acks). Left out, as in the MVP plan: actors, query bookkeeping, future
 * salts, HTTP modes, outgoing containers, PFS (temporary keys). gzip_packed is handed to the caller.
 *
 * Usage (s->rng seeded first, as for tg_auth_t):
 *   tg_sess_init(s, auth_key, server_salt, time_offset, tx, tx_cap)
 *   send:    body = tg_sess_body(s) (room: s->body_cap); write the TL body there;
 *            len = tg_sess_send(s, body_len, content_related, now, &msg_id)   (0: body too big)
 *            the packet is at s->tx + TG_NET_HEADROOM; frame it with tg_net_frame(net, s->tx, len, &off).
 *            tg_sess_ping and tg_sess_send_acks build their own body.
 *   receive: r = tg_sess_input(s, pkt, len, now) on each transport packet (decrypts in place), then
 *            while ((t = tg_sess_next(s, &ev)) != TG_EV_NONE) handle ev; pointers in ev point into pkt.
 *            r < 0: drop the connection (TG_SERR_*, s->err_arg); r == 1: duplicate, ignored.
 *   acks:    after a batch of input, if s->n_acks, tg_sess_send_acks (msgs_ack is its own message).
 * One outgoing packet at a time: transmit it before building the next. Times are unix seconds.
 *
 * Derived from TDLib, Copyright Aliaksei Levin, Arseny Smirnov 2014-2026, distributed under the
 * Boost Software License 1.0 (LICENSE_1_0.txt). Changes: C port for small freestanding targets;
 * see THIRD_PARTY.md. */
#ifndef TG_SESSION_H
#define TG_SESSION_H

#include "tg_mtp.h"
#include "tg_net.h"

#define TG_SESS_DUP   64     /* inbound msg_ids remembered for duplicate checks (TDLib: 1000) */
#define TG_SESS_UPD   32     /* update msg_ids remembered (TDLib: 1000 + 100) */
#define TG_SESS_ACKS  64     /* pending acks; more are dropped (the server resends, then we ack) */

/* tg_sess_next event types */
enum {
    TG_EV_NONE,
    TG_EV_RESULT,       /* rpc_result: req_msg_id, body/len = result object (gzip: packed_data) */
    TG_EV_ERROR,        /* rpc_result with rpc_error: req_msg_id, code, body/len = error_message */
    TG_EV_UPDATE,       /* anything not MTProto service: msg_id, body/len = the object */
    TG_EV_GZIP,         /* gzip_packed outside rpc_result: msg_id, body/len = packed_data */
    TG_EV_PONG,         /* pong: req_msg_id = the ping's msg_id, id2 = ping_id */
    TG_EV_RESEND,       /* our message req_msg_id was refused, send it again with a new msg_id:
                         * code 48 bad_server_salt (salt already updated), 16 msg_id too low, 20 too old */
    TG_EV_NEW_SESSION,  /* new_session_created: req_msg_id = first_msg_id, id2 = unique_id (salt updated) */
    TG_EV_FATAL,        /* code = TG_SERR_*, err_arg = detail: drop the connection */
};

/* tg_sess_input / TG_EV_FATAL codes */
enum {
    TG_SERR_TRANSPORT = -1,  /* 4-byte transport error packet, err_arg = e.g. -404 (unknown key), -429 */
    TG_SERR_DECRYPT = -2,    /* err_arg = tg_mtp_decrypt error */
    TG_SERR_SESSION = -3,    /* packet for another session_id */
    TG_SERR_MSG_ID = -4,     /* even (client-parity) msg_id */
    TG_SERR_TOO_OLD = -5,    /* msg_id older than every remembered one */
    TG_SERR_TIME = -6,       /* msg_id outside [server_time - 300, server_time + 30) */
    TG_SERR_PARSE = -7,      /* malformed message, err_arg = constructor or 0 */
    TG_SERR_BAD_MSG = -8,    /* bad_msg_notification for a client bug, err_arg = error_code */
    TG_SERR_CLOCK = -9,      /* bad_msg_notification 17 (msg_id too high): time offset was reset */
};

typedef struct {
    int type;
    int32_t code;
    int gzip;                      /* TG_EV_RESULT: body is gzip_packed data */
    uint64_t msg_id;               /* the inbound message carrying this event */
    uint64_t req_msg_id, id2;
    const uint8_t *body;
    uint32_t len;
} tg_sev_t;

typedef struct {
    uint8_t auth_key[256], auth_key_id[8];
    uint8_t salt[8], session_id[8];
    int32_t time_offset;           /* server_time - local time (AuthData::server_time_difference_) */
    int time_synced;               /* server_time_difference_was_updated_ */
    uint32_t now;                  /* time of the last call */
    uint64_t last_msg_id;
    uint32_t seq_no;
    tg_rng_t rng;
    uint64_t dup[2 * TG_SESS_DUP];
    uint64_t upd[2 * TG_SESS_UPD];
    uint32_t dup_end, upd_end;
    uint64_t acks[TG_SESS_ACKS];
    uint32_t n_acks;
    uint8_t *tx;                   /* caller's send buffer, packet at tx + TG_NET_HEADROOM */
    uint32_t tx_cap, body_cap;
    /* inbound iterator over the current packet */
    const uint8_t *top;            /* body of the packet's message, not yet dispatched (0 = done) */
    uint32_t top_len, top_seq;
    uint64_t top_id;
    tg_tlr_t cont;                 /* messages left in a container */
    uint32_t cont_left;
    int32_t err_arg;
} tg_sess_t;

/* Returns 0, or -1 if tx_cap cannot hold even a small message. */
int tg_sess_init(tg_sess_t *s, const uint8_t auth_key[256], const uint8_t salt[8], int32_t time_offset,
                 uint8_t *tx, uint32_t tx_cap);
void tg_sess_new_session(tg_sess_t *s);      /* new session_id, seq_no 0, forget inbound ids and acks */
void tg_sess_wipe(tg_sess_t *s);             /* wipe the key and session state */

uint8_t *tg_sess_body(tg_sess_t *s);
uint32_t tg_sess_send(tg_sess_t *s, uint32_t body_len, int content_related, uint32_t now, uint64_t *msg_id);
/* ping, or ping_delay_disconnect when disconnect_delay != 0 */
uint32_t tg_sess_ping(tg_sess_t *s, uint64_t ping_id, uint32_t disconnect_delay, uint32_t now, uint64_t *msg_id);
uint32_t tg_sess_send_acks(tg_sess_t *s, uint32_t now);      /* 0 if nothing to ack */

int tg_sess_input(tg_sess_t *s, uint8_t *pkt, uint32_t len, uint32_t now);
int tg_sess_next(tg_sess_t *s, tg_sev_t *ev);

#endif
