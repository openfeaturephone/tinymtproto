/* tg_client.h - the Telegram client: connection, auth key, initConnection, login (with DC migration),
 * chat list, history, sending, incoming messages and update state. No I/O and no globals: the host
 * (a PC harness, a relay pipe, real sockets) moves bytes and the app reacts to events.
 *
 *   c = alloc(sizeof *c); tg_cl_init(c, &cfg, persist_or_0);     cfg holds alloc/free, api_id/hash, seed
 *   (these are the only platform hooks: no file, socket or clock calls happen inside the library)
 *   loop on a timer:
 *     switch (tg_cl_poll(c, unix_now, budget)) {
 *     TG_CL_CONNECT: open TCP to c->ip (IPv4, host order) : c->port, then tg_cl_connected(c) or
 *                    tg_cl_disconnected(c)
 *     TG_CL_SEND:    write c->out[0 .. c->out_len) to the socket, then tg_cl_sent(c)
 *     TG_CL_CLOSE:   close the socket (poll again: it may ask to CONNECT elsewhere)
 *     TG_CL_EVENT:   handle c->ev (TG_CLE_*), then poll again
 *     TG_CL_BUSY:    heavy work pending (key, inflate): poll again on the next tick
 *     TG_CL_IDLE:    nothing to do until bytes arrive or the app asks for something
 *     }
 *   socket bytes: p = tg_cl_rx_space(c, &room); read into p; tg_cl_rx_commit(c, n)
 *   app requests (one at a time; TG_CLE_ERROR code -1 if one is already running):
 *     tg_cl_send_code(phone) -> CODE_SENT;  tg_cl_sign_in(code) -> LOGGED_IN | SIGNUP_REQUIRED | PASSWORD;
 *     tg_cl_sign_up(first, last) -> LOGGED_IN;  tg_cl_get_dialogs -> DIALOGS (c->dlg[0 .. n_dlg));
 *     tg_cl_get_history(dlg) -> HISTORY (c->msg[0 .. n_msg), newest first);  tg_cl_send_text(dlg, utf8) -> SENT;
 *     tg_cl_get_difference -> NEW_MESSAGE events, then DIFF_DONE
 *   TG_CLE_PERSIST: save c->ps (auth key, DC, user, update state) like a password.
 * dlg -1 means Saved Messages (the account's own chat).
 * Strings are UTF-8 in arenas: tg_cl_str(c, off) gives a 0-terminated pointer. */
#ifndef TG_CLIENT_H
#define TG_CLIENT_H

#include "tg_session.h"
#include "tg_inflate.h"
#include "tg_tlwalk.h"

#define TG_CL_MAX_DLG   30
#define TG_CL_MAX_MSG   30
#define TG_CL_MAX_PEERS 96
#define TG_CL_ARENA     16384          /* names and texts of the last dialogs/history reply */
#define TG_CL_INBOX     8
#define TG_CL_RX        65536
#define TG_CL_TX        4800
#define TG_CL_REQ       4500
#define TG_CL_MAX_REPLY (512 * 1024)   /* largest inflated reply accepted */

enum { TG_CL_IDLE, TG_CL_BUSY, TG_CL_CONNECT, TG_CL_SEND, TG_CL_CLOSE, TG_CL_EVENT };
enum {
    TG_CLE_STATUS = 1,       /* a = TG_CLS_* */
    TG_CLE_PERSIST,          /* c->ps changed: save it */
    TG_CLE_CODE_SENT,        /* a = code type constructor (auth.sentCodeTypeApp / Sms / ...), b = length */
    TG_CLE_SIGNUP_REQUIRED,
    TG_CLE_PASSWORD,         /* the account has 2FA: not supported yet */
    TG_CLE_LOGGED_IN,
    TG_CLE_DIALOGS,          /* a = n_dlg */
    TG_CLE_HISTORY,          /* a = n_msg, b = dialog index */
    TG_CLE_SENT,             /* a = message id */
    TG_CLE_NEW_MESSAGE,      /* a = inbox slot (c->inbox[a], text tg_cl_inbox_text) */
    TG_CLE_DIFF_DONE,
    TG_CLE_ERROR,            /* code = rpc error code (or < 0 local), c->err_text */
};
enum { TG_CLS_OFFLINE, TG_CLS_CONNECTING, TG_CLS_KEY, TG_CLS_ONLINE };
enum { TG_PEER_NONE, TG_PEER_USER, TG_PEER_CHAT, TG_PEER_CHANNEL };

typedef struct {
    void *(*alloc)(void *ctx, uint32_t n);
    void (*free)(void *ctx, void *p);
    void *ctx;
    int32_t api_id;
    char api_hash[33];
    uint8_t seed[32];          /* entropy for the RNG (the host's best) */
    int test;                  /* test DCs */
    int dc;                    /* first DC to try when there is no saved one */
    /* initConnection strings (shown in the account's "active sessions" list); 0 = a default */
    const char *device_model, *system_version, *app_version;
} tg_clcfg_t;

typedef struct {               /* what must survive restarts; it holds the account key */
    uint32_t magic, version;
    int32_t dc, test, has_key, logged_in;
    uint8_t auth_key[256], salt[8];
    int32_t time_offset;
    uint64_t user_id;
    int32_t pts, qts, date, seq;
} tg_persist_t;
#define TG_PERSIST_MAGIC 0x46324754u   /* "TG2F" */

typedef struct {
    uint8_t type, out, media, pad;
    uint64_t id, access_hash;
    int32_t top_msg, unread;
    uint32_t date, title, preview;     /* title/preview: arena offsets */
} tg_dlg_t;

typedef struct {
    int32_t id;
    uint32_t date;
    uint8_t out, media, peer_type, from_type;
    uint64_t peer_id, from_id;
    uint32_t text, from_name;          /* arena offsets */
} tg_msg_t;

typedef struct { int type; int32_t code; uint32_t a, b; } tg_clev_t;

typedef struct {
    uint8_t type;
    uint64_t id, access_hash;
    uint32_t name;
} tg_peer_t;

typedef struct {                /* reply walk state (tg_client.c) */
    tg_tlwalk_t w;
    int mode, mk, dk, pk, n_tmp;
    uint32_t root;
    tg_msg_t m;
    tg_dlg_t d;
    tg_peer_t p;
    char name[100];             /* the peer's name being read: first [+ ' ' + last], or a title */
    uint8_t name_len, has_first, has_last, pad;
    int32_t sent_id;
} tg_coll_t;

typedef struct {
    tg_clcfg_t cfg;
    tg_persist_t ps;
    int conn, inited, want_online, close_pending, login_chain;
    uint32_t now, ip, port, retry_at;
    tg_rng_t rng;
    int32_t migrate_to;
    /* connection */
    tg_net_t net;
    tg_sess_t sess;
    tg_auth_t *auth;
    uint8_t *rx, *tx;
    uint8_t *out;
    uint32_t out_len;
    int sending, in_packet;
    uint32_t last_send, last_ping;
    /* request in flight */
    uint8_t *req;
    uint32_t req_len;
    int req_kind, req_sent, req_dlg;
    uint64_t req_msg_id;
    /* login */
    char phone[24];
    char code_hash[40];
    uint32_t code_type, code_len;
    uint32_t auth_restarts;             /* AUTH_RESTART answers to this sendCode (resent up to 2 times) */
    /* reply in progress */
    tg_inflate_t z;
    uint8_t *zbuf;
    int zkind, inflating;
    /* results */
    tg_dlg_t dlg[TG_CL_MAX_DLG];
    int n_dlg;
    tg_msg_t msg[TG_CL_MAX_MSG];
    int n_msg;
    tg_peer_t peers[TG_CL_MAX_PEERS];
    int n_peers;
    char *arena;
    uint32_t arena_len, arena_m, arena_p;
    tg_msg_t tmp[TG_CL_MAX_MSG];
    tg_coll_t coll;
    tg_msg_t inbox[TG_CL_INBOX];
    char inbox_text[TG_CL_INBOX][200];
    int inbox_next;
    /* events */
    tg_clev_t evq[16];
    int ev_head, ev_tail;
    tg_clev_t ev;
    char err_text[64];
} tg_client_t;

/* 0 ok, -1 out of memory. ps: a saved tg_persist_t or 0. */
int tg_cl_init(tg_client_t *c, const tg_clcfg_t *cfg, const tg_persist_t *ps);
void tg_cl_free(tg_client_t *c);                /* frees buffers, wipes the key copy in c */
int tg_cl_poll(tg_client_t *c, uint32_t now, uint32_t budget);
void tg_cl_connected(tg_client_t *c);
void tg_cl_disconnected(tg_client_t *c);
void tg_cl_sent(tg_client_t *c);
uint8_t *tg_cl_rx_space(tg_client_t *c, uint32_t *room);
void tg_cl_rx_commit(tg_client_t *c, uint32_t n);
void tg_cl_online(tg_client_t *c, int on);      /* connect (and stay connected) or not */

int tg_cl_send_code(tg_client_t *c, const char *phone);
int tg_cl_sign_in(tg_client_t *c, const char *code);
int tg_cl_sign_up(tg_client_t *c, const char *first, const char *last);
int tg_cl_get_dialogs(tg_client_t *c);
int tg_cl_get_history(tg_client_t *c, int dlg);
int tg_cl_send_text(tg_client_t *c, int dlg, const char *utf8);
/* the same by peer (type, id, access_hash of a tg_dlg_t; NULL = Saved Messages): the dialog list
 * reorders as messages arrive, so an index taken earlier may name another chat by now */
int tg_cl_get_history_peer(tg_client_t *c, const tg_dlg_t *peer);
int tg_cl_send_text_peer(tg_client_t *c, const tg_dlg_t *peer, const char *utf8);
int tg_cl_get_difference(tg_client_t *c);

const char *tg_cl_str(const tg_client_t *c, uint32_t off);
/* a known user / chat / channel's name (UTF-8), "" if not seen yet */
const char *tg_cl_peer_name(tg_client_t *c, int type, uint64_t id);

#endif
