/* tg_client.c - Telegram client state machine on tg_net / tg_session / tg_auth / tg_inflate /
 * tg_tlwalk. See tg_client.h for the host contract. One request is in flight at a time; replies are
 * walked once with tg_tlwalk and reduced to small tables (dialogs, messages, peers) and strings in
 * arenas, so nothing big stays in memory. */
#include "tg_client.h"

enum { C_OFF, C_WANT, C_WAIT_CONN, C_AUTH, C_READY, C_BACKOFF };
enum { K_NONE, K_SEND_CODE, K_SIGN_IN, K_SIGN_UP, K_GET_STATE, K_DIALOGS, K_HISTORY, K_SEND_MSG, K_DIFF, K_UPDATES };
enum { MODE_DIALOGS, MODE_HISTORY, MODE_UPDATES, MODE_SENT };

#define A_DLG   0x00000000u      /* arena tags in string offsets */
#define A_MSG   0x40000000u
#define A_PEER  0x80000000u
#define A_MASK  0xc0000000u
#define ARENA_D (TG_CL_ARENA / 4)
#define ARENA_M (TG_CL_ARENA / 2)
#define ARENA_P (TG_CL_ARENA / 4)

/* TDLib ConnectionCreator::get_default_dc_options, IPv4 (DC 2 production: .50, which our tests use) */
static uint32_t dc_ip(int test, int dc)
{
    static const uint32_t PROD[6] = { 0, 0x959aaf32u, 0x959aa732u, 0x959aaf64u, 0x959aa75bu, 0x959aab05u };
    static const uint32_t TEST[4] = { 0, 0x959aaf0au, 0x959aa728u, 0x959aaf75u };
    if (test)
        return dc >= 1 && dc <= 3 ? TEST[dc] : 0;
    return dc >= 1 && dc <= 5 ? PROD[dc] : 0;
}

static uint32_t slen(const char *s)
{
    uint32_t n = 0;
    while (s[n])
        n++;
    return n;
}

/* first name / title (part 0) or last name (part 1) of the peer being read, into k->name */
static void name_part(tg_coll_t *k, int part, const uint8_t *s, uint32_t n)
{
    uint32_t room;
    if (part == 0) {                                /* first name / title; a username only stands in for no name */
        if (k->has_first || k->has_last)
            return;
        k->has_first = 1;
    } else {
        if (k->has_last || !n)
            return;
        k->has_last = 1;
        if (k->name_len && k->name_len < sizeof k->name - 1)
            k->name[k->name_len++] = ' ';
    }
    room = sizeof k->name - 1 - k->name_len;
    if (n > room) {
        n = room;
        while (n && (s[n] & 0xc0) == 0x80)
            n--;
    }
    tg_memcpy(k->name + k->name_len, s, n);
    k->name_len = (uint8_t)(k->name_len + n);
}

static void scopy(char *d, const char *s, uint32_t cap)
{
    uint32_t i = 0;
    for (; s[i] && i + 1 < cap; i++)
        d[i] = s[i];
    d[i] = 0;
}


static void ev_push(tg_client_t *c, int type, int32_t code, uint32_t a, uint32_t b)
{
    int next = (c->ev_tail + 1) & 15;
    if (next == c->ev_head)
        return;                                     /* full: drop (the app is not polling) */
    c->evq[c->ev_tail].type = type;
    c->evq[c->ev_tail].code = code;
    c->evq[c->ev_tail].a = a;
    c->evq[c->ev_tail].b = b;
    c->ev_tail = next;
}

static void error(tg_client_t *c, int32_t code, const char *text, uint32_t len)
{
    uint32_t i;
    for (i = 0; i < len && i < sizeof c->err_text - 1; i++)
        c->err_text[i] = text[i];
    c->err_text[i] = 0;
    ev_push(c, TG_CLE_ERROR, code, 0, 0);
}

static void status(tg_client_t *c, int s)
{
    ev_push(c, TG_CLE_STATUS, 0, (uint32_t)s, 0);
}

/* ---- string arenas: offset 0 of each is "" ---- */
static uint32_t arena_base(uint32_t tag) { return tag == A_DLG ? 0 : tag == A_MSG ? ARENA_D : ARENA_D + ARENA_M; }
static uint32_t arena_size(uint32_t tag) { return tag == A_DLG ? ARENA_D : tag == A_MSG ? ARENA_M : ARENA_P; }

static uint32_t *arena_fill(tg_client_t *c, uint32_t tag)
{
    return tag == A_DLG ? &c->arena_len : tag == A_MSG ? &c->arena_m : &c->arena_p;
}

static void arena_reset(tg_client_t *c, uint32_t tag)
{
    *arena_fill(c, tag) = 1;
    c->arena[arena_base(tag)] = 0;
}

/* appends s (n bytes, cut at a UTF-8 boundary to fit) + 0; returns a tagged offset ("" if full) */
static uint32_t arena_add(tg_client_t *c, uint32_t tag, const uint8_t *s, uint32_t n)
{
    uint32_t *fill = arena_fill(c, tag), room = arena_size(tag) - *fill, off;
    char *base = c->arena + arena_base(tag);
    if (room < 2)
        return tag;
    if (n > room - 1) {
        n = room - 1;
        while (n && (s[n] & 0xc0) == 0x80)
            n--;
    }
    off = *fill;
    tg_memcpy(base + off, s, n);
    base[off + n] = 0;
    *fill += n + 1;
    return tag | off;
}

const char *tg_cl_str(const tg_client_t *c, uint32_t off)
{
    uint32_t tag = off & A_MASK;
    if (!c->arena)
        return "";
    return c->arena + arena_base(tag) + (off & ~A_MASK);
}

/* ---- peers (names survive between replies; the table is reset when it or its arena fills) ---- */
static tg_peer_t *peer_find(tg_client_t *c, int type, uint64_t id)
{
    for (int i = 0; i < c->n_peers; i++)
        if (c->peers[i].type == type && c->peers[i].id == id)
            return &c->peers[i];
    return 0;
}

const char *tg_cl_peer_name(tg_client_t *c, int type, uint64_t id)
{
    tg_peer_t *p = peer_find(c, type, id);
    return p ? tg_cl_str(c, p->name) : "";
}

static tg_peer_t *peer_add(tg_client_t *c, int type, uint64_t id)
{
    tg_peer_t *p = peer_find(c, type, id);
    if (p)
        return p;
    if (c->n_peers >= TG_CL_MAX_PEERS || c->arena_p > ARENA_P - 96) {
        c->n_peers = 0;
        arena_reset(c, A_PEER);
    }
    p = &c->peers[c->n_peers++];
    p->type = (uint8_t)type;
    p->id = id;
    p->access_hash = 0;
    p->name = A_PEER;
    return p;
}

/* ---- connection ---- */
static void drop(tg_client_t *c, uint32_t delay)
{
    c->conn = C_BACKOFF;
    c->retry_at = c->now + delay;
    c->in_packet = 0;
    c->sending = 0;
    c->req_sent = 0;                                /* resend after reconnecting */
    if (c->auth) {
        tg_wipe(c->auth, sizeof *c->auth);
        c->cfg.free(c->cfg.ctx, c->auth);
        c->auth = 0;
    }
    c->close_pending = 1;
    status(c, TG_CLS_OFFLINE);
}

static void persist(tg_client_t *c)
{
    c->ps.magic = TG_PERSIST_MAGIC;
    c->ps.version = 1;
    if (c->conn == C_READY) {
        tg_memcpy(c->ps.salt, c->sess.salt, 8);
        c->ps.time_offset = c->sess.time_offset;
    }
    ev_push(c, TG_CLE_PERSIST, 0, 0, 0);
}

static void frame_out(tg_client_t *c, uint32_t len)
{
    uint32_t off;
    uint32_t n = tg_net_frame(&c->net, c->tx, len, &off);
    c->out = c->tx + off;
    c->out_len = n;
    c->sending = 1;
    c->last_send = c->now;
}

/* a session on the open connection (the key exists) */
static void start_session(tg_client_t *c)
{
    uint8_t seed[32];
    tg_rng_bytes(&c->rng, seed, 32);
    c->sess.rng = c->rng;                           /* a copy, re-keyed apart */
    tg_rng_add(&c->sess.rng, seed, 32);
    tg_sess_init(&c->sess, c->ps.auth_key, c->ps.salt, c->ps.time_offset, c->tx, TG_CL_TX);
    tg_wipe(seed, 32);
    c->inited = 0;
    c->conn = C_READY;
    status(c, TG_CLS_ONLINE);
}

void tg_cl_connected(tg_client_t *c)
{
    uint8_t seed[32];
    if (c->conn != C_WAIT_CONN)
        return;
    tg_net_reset(&c->net);
    c->in_packet = 0;
    c->last_send = c->last_ping = c->now;
    if (c->ps.has_key) {
        start_session(c);
        return;
    }
    c->auth = c->cfg.alloc(c->cfg.ctx, sizeof *c->auth);
    if (!c->auth) {
        error(c, -3, "no memory for the key", 21);
        drop(c, 30);
        return;
    }
    tg_rng_bytes(&c->rng, seed, 32);
    tg_rng_init(&c->auth->rng);
    tg_rng_add(&c->auth->rng, seed, 32);
    tg_wipe(seed, 32);
    tg_auth_start(c->auth, c->ps.dc + (c->ps.test ? 10000 : 0), c->now);
    c->conn = C_AUTH;
    status(c, TG_CLS_KEY);
}

void tg_cl_disconnected(tg_client_t *c)
{
    if (c->conn != C_OFF)
        drop(c, 5);
    c->close_pending = 0;
}

void tg_cl_sent(tg_client_t *c)
{
    c->sending = 0;
}

uint8_t *tg_cl_rx_space(tg_client_t *c, uint32_t *room)
{
    return tg_net_rx_space(&c->net, room);
}

void tg_cl_rx_commit(tg_client_t *c, uint32_t n)
{
    tg_net_rx_commit(&c->net, n);
}

void tg_cl_online(tg_client_t *c, int on)
{
    c->want_online = on;
    if (on && c->conn == C_OFF)
        c->conn = C_WANT;
    if (!on && c->conn != C_OFF) {
        c->conn = C_OFF;
        c->close_pending = 1;
        c->sending = 0;
        status(c, TG_CLS_OFFLINE);
    }
}

/* ---- requests ---- */
static int req_begin(tg_client_t *c, tg_tlw_t *w, int kind)
{
    if (c->req_kind != K_NONE) {
        error(c, -1, "busy", 4);
        return -1;
    }
    tg_tlw_init(w, c->req, TG_CL_REQ);
    c->req_kind = kind;
    return 0;
}

static int req_end(tg_client_t *c, tg_tlw_t *w)
{
    if (w->err) {
        c->req_kind = K_NONE;
        error(c, -4, "request too big", 15);
        return -1;
    }
    c->req_len = w->len;
    c->req_sent = 0;
    tg_cl_online(c, 1);
    return 0;
}

static void tlw_str(tg_tlw_t *w, const char *s) { tg_tlw_bytes(w, s, slen(s)); }
static void tlw_long(tg_tlw_t *w, uint64_t v) { tg_tlw_u64(w, (uint32_t)v, (uint32_t)(v >> 32)); }

/* d NULL = Saved Messages (inputPeerSelf) */
static void input_peer(tg_tlw_t *w, const tg_dlg_t *d)
{
    if (!d) {
        tg_tlw_u32(w, TL_inputPeerSelf);
    } else if (d->type == TG_PEER_USER) {
        tg_tlw_u32(w, TL_inputPeerUser);
        tlw_long(w, d->id);
        tlw_long(w, d->access_hash);
    } else if (d->type == TG_PEER_CHAT) {
        tg_tlw_u32(w, TL_inputPeerChat);
        tlw_long(w, d->id);
    } else {
        tg_tlw_u32(w, TL_inputPeerChannel);
        tlw_long(w, d->id);
        tlw_long(w, d->access_hash);
    }
}

int tg_cl_send_code(tg_client_t *c, const char *phone)
{
    tg_tlw_t w;
    if (req_begin(c, &w, K_SEND_CODE))
        return -1;
    scopy(c->phone, phone, sizeof c->phone);
    c->auth_restarts = 0;
    tg_tlw_u32(&w, TL_auth_sendCode);
    tlw_str(&w, c->phone);
    tg_tlw_u32(&w, (uint32_t)c->cfg.api_id);
    tlw_str(&w, c->cfg.api_hash);
    tg_tlw_u32(&w, TL_codeSettings);
    tg_tlw_u32(&w, 0);
    return req_end(c, &w);
}

int tg_cl_sign_in(tg_client_t *c, const char *code)
{
    tg_tlw_t w;
    if (req_begin(c, &w, K_SIGN_IN))
        return -1;
    tg_tlw_u32(&w, TL_auth_signIn);
    tg_tlw_u32(&w, 1u << TLB_auth_signIn_phone_code);
    tlw_str(&w, c->phone);
    tlw_str(&w, c->code_hash);
    tlw_str(&w, code);
    return req_end(c, &w);
}

int tg_cl_sign_up(tg_client_t *c, const char *first, const char *last)
{
    tg_tlw_t w;
    if (req_begin(c, &w, K_SIGN_UP))
        return -1;
    tg_tlw_u32(&w, TL_auth_signUp);
    tg_tlw_u32(&w, 0);
    tlw_str(&w, c->phone);
    tlw_str(&w, c->code_hash);
    tlw_str(&w, first);
    tlw_str(&w, last);
    return req_end(c, &w);
}

static int get_state(tg_client_t *c)
{
    tg_tlw_t w;
    if (req_begin(c, &w, K_GET_STATE))
        return -1;
    tg_tlw_u32(&w, TL_updates_getState);
    return req_end(c, &w);
}

int tg_cl_get_dialogs(tg_client_t *c)
{
    tg_tlw_t w;
    if (req_begin(c, &w, K_DIALOGS))
        return -1;
    tg_tlw_u32(&w, TL_messages_getDialogs);
    tg_tlw_u32(&w, 0);                              /* flags */
    tg_tlw_u32(&w, 0);                              /* offset_date */
    tg_tlw_u32(&w, 0);                              /* offset_id */
    tg_tlw_u32(&w, TL_inputPeerEmpty);
    tg_tlw_u32(&w, TG_CL_MAX_DLG);                  /* limit */
    tlw_long(&w, 0);                                /* hash */
    return req_end(c, &w);
}

int tg_cl_get_history(tg_client_t *c, int dlg)
{
    if (dlg < -1 || dlg >= c->n_dlg) {
        error(c, -5, "no such chat", 12);
        return -1;
    }
    if (tg_cl_get_history_peer(c, dlg < 0 ? 0 : &c->dlg[dlg]))
        return -1;
    c->req_dlg = dlg;
    return 0;
}

int tg_cl_get_history_peer(tg_client_t *c, const tg_dlg_t *peer)
{
    tg_tlw_t w;
    if (req_begin(c, &w, K_HISTORY))
        return -1;
    c->req_dlg = -2;
    tg_tlw_u32(&w, TL_messages_getHistory);
    input_peer(&w, peer);
    tg_tlw_u32(&w, 0);                              /* offset_id */
    tg_tlw_u32(&w, 0);                              /* offset_date */
    tg_tlw_u32(&w, 0);                              /* add_offset */
    tg_tlw_u32(&w, 20);                             /* limit */
    tg_tlw_u32(&w, 0);                              /* max_id */
    tg_tlw_u32(&w, 0);                              /* min_id */
    tlw_long(&w, 0);                                /* hash */
    return req_end(c, &w);
}

int tg_cl_send_text(tg_client_t *c, int dlg, const char *utf8)
{
    if (dlg < -1 || dlg >= c->n_dlg) {
        error(c, -5, "no such chat", 12);
        return -1;
    }
    if (tg_cl_send_text_peer(c, dlg < 0 ? 0 : &c->dlg[dlg], utf8))
        return -1;
    c->req_dlg = dlg;
    return 0;
}

int tg_cl_send_text_peer(tg_client_t *c, const tg_dlg_t *peer, const char *utf8)
{
    tg_tlw_t w;
    uint8_t rid[8];
    if (req_begin(c, &w, K_SEND_MSG))
        return -1;
    c->req_dlg = -2;
    tg_rng_bytes(&c->rng, rid, 8);
    tg_tlw_u32(&w, TL_messages_sendMessage);
    tg_tlw_u32(&w, 0);
    input_peer(&w, peer);
    tlw_str(&w, utf8);
    tg_tlw_raw(&w, rid, 8);                         /* random_id */
    return req_end(c, &w);
}

int tg_cl_get_difference(tg_client_t *c)
{
    tg_tlw_t w;
    if (!c->ps.logged_in || !c->ps.date) {
        error(c, -6, "no update state", 15);
        return -1;
    }
    if (req_begin(c, &w, K_DIFF))
        return -1;
    tg_tlw_u32(&w, TL_updates_getDifference);
    tg_tlw_u32(&w, 0);
    tg_tlw_u32(&w, (uint32_t)c->ps.pts);
    tg_tlw_u32(&w, (uint32_t)c->ps.date);
    tg_tlw_u32(&w, (uint32_t)c->ps.qts);
    return req_end(c, &w);
}

/* ---- reply parsing ---- */
typedef tg_coll_t coll_t;

static int is_message(uint32_t cid) { return cid == TL_message || cid == TL_messageService || cid == TL_messageEmpty; }

static int peer_type(uint32_t cid)
{
    return cid == TL_peerUser ? TG_PEER_USER : cid == TL_peerChat ? TG_PEER_CHAT : cid == TL_peerChannel ? TG_PEER_CHANNEL : 0;
}

static void commit_message(tg_client_t *c, coll_t *k)
{
    tg_msg_t *m = &k->m;
    if (!m->from_type && !m->out) {                 /* private chats: the sender is the peer */
        m->from_type = m->peer_type;
        m->from_id = m->peer_id;
    }
    if (k->mode == MODE_HISTORY) {
        if (c->n_msg < TG_CL_MAX_MSG)
            c->msg[c->n_msg++] = *m;
    } else if (k->mode == MODE_DIALOGS) {
        if (k->n_tmp < TG_CL_MAX_MSG)
            c->tmp[k->n_tmp++] = *m;
    } else if (k->mode == MODE_SENT) {
        if (!k->sent_id)
            k->sent_id = m->id;
    } else {
        int slot = c->inbox_next;
        const char *t = tg_cl_str(c, m->text);
        c->inbox_next = (slot + 1) % TG_CL_INBOX;
        c->inbox[slot] = *m;
        scopy(c->inbox_text[slot], t, sizeof c->inbox_text[slot]);
        ev_push(c, TG_CLE_NEW_MESSAGE, 0, (uint32_t)slot, 0);
    }
}

static uint32_t msg_tag(const coll_t *k) { return k->mode == MODE_DIALOGS ? A_DLG : A_MSG; }

/* one walker event; returns < 0 on a walk error */
static void on_field(tg_client_t *c, coll_t *k)
{
    tg_tlwalk_t *w = &k->w;
    int f = w->sp - 1, fld = w->field;
    uint32_t cid = w->cid;
    /* update state, wherever it appears */
    if (cid == TL_updates_state) {
        if (fld == TLF_updates_state_pts) c->ps.pts = (int32_t)w->v32;
        else if (fld == TLF_updates_state_qts) c->ps.qts = (int32_t)w->v32;
        else if (fld == TLF_updates_state_date) c->ps.date = (int32_t)w->v32;
        else if (fld == TLF_updates_state_seq) c->ps.seq = (int32_t)w->v32;
        return;
    }
    if ((cid == TL_updateNewMessage && fld == TLF_updateNewMessage_pts) ||
        (cid == TL_updateShortMessage && fld == TLF_updateShortMessage_pts) ||
        (cid == TL_updateShortChatMessage && fld == TLF_updateShortChatMessage_pts) ||
        (cid == TL_updateShortSentMessage && fld == TLF_updateShortSentMessage_pts)) {
        if ((int32_t)w->v32 > c->ps.pts)
            c->ps.pts = (int32_t)w->v32;
    }
    if (f == 0 && (cid == TL_updates || cid == TL_updatesCombined)) {
        if (fld == TLF_updates_date) c->ps.date = (int32_t)w->v32;
        if ((cid == TL_updates && fld == TLF_updates_seq) || (cid == TL_updatesCombined && fld == TLF_updatesCombined_seq))
            if (w->v32) c->ps.seq = (int32_t)w->v32;
    }
    if (f == 0 && cid == TL_updates_differenceEmpty) {
        if (fld == TLF_updates_differenceEmpty_date) c->ps.date = (int32_t)w->v32;
        if (fld == TLF_updates_differenceEmpty_seq) c->ps.seq = (int32_t)w->v32;
    }
    if (f == 0 && cid == TL_updates_differenceTooLong && fld == TLF_updates_differenceTooLong_pts)
        c->ps.pts = (int32_t)w->v32;
    /* the short forms: the root is the message */
    if (f == 0 && (cid == TL_updateShortMessage || cid == TL_updateShortChatMessage)) {
        tg_msg_t *m = &k->m;
        int user = cid == TL_updateShortMessage;
        if (fld == (user ? TLF_updateShortMessage_out : TLF_updateShortChatMessage_out)) m->out = 1;
        else if (fld == (user ? TLF_updateShortMessage_id : TLF_updateShortChatMessage_id)) m->id = (int32_t)w->v32;
        else if (fld == (user ? TLF_updateShortMessage_date : TLF_updateShortChatMessage_date)) m->date = w->v32;
        else if (fld == (user ? TLF_updateShortMessage_message : TLF_updateShortChatMessage_message))
            m->text = arena_add(c, A_MSG, w->val, w->len);
        else if (user && fld == TLF_updateShortMessage_user_id) {
            m->peer_type = TG_PEER_USER;
            m->peer_id = w->v64;
        } else if (!user && fld == TLF_updateShortChatMessage_chat_id) {
            m->peer_type = TG_PEER_CHAT;
            m->peer_id = w->v64;
        } else if (!user && fld == TLF_updateShortChatMessage_from_id) {
            m->from_type = TG_PEER_USER;
            m->from_id = w->v64;
        }
        return;
    }
    if (f == 0 && cid == TL_updateShortSentMessage && fld == TLF_updateShortSentMessage_id) {
        k->sent_id = (int32_t)w->v32;
        return;
    }
    /* login replies */
    if (f == 1 && cid == c->code_type && w->type == TG_TT_INT && !c->code_len && k->root == TL_auth_sentCode) {
        c->code_len = w->v32;                        /* the first int of the code type: its length */
        return;
    }
    if (f == 0 && cid == TL_auth_sentCode && fld == TLF_auth_sentCode_phone_code_hash) {
        uint32_t i;
        for (i = 0; i < w->len && i < sizeof c->code_hash - 1; i++)
            c->code_hash[i] = (char)w->val[i];
        c->code_hash[i] = 0;
        return;
    }
    if (k->root == TL_auth_authorization || k->root == TL_auth_sentCodeSuccess) {
        if (cid == TL_user && fld == TLF_user_id && w->sp >= 2 && w->st[w->sp - 2].cid != TL_user)
            c->ps.user_id = w->v64;
        return;
    }
    /* message being collected */
    if (k->mk >= 0 && f == k->mk) {
        tg_msg_t *m = &k->m;
        if (cid == TL_message) {
            if (fld == TLF_message_out) m->out = 1;
            else if (fld == TLF_message_id) m->id = (int32_t)w->v32;
            else if (fld == TLF_message_date) m->date = w->v32;
            else if (fld == TLF_message_message && w->len) m->text = arena_add(c, msg_tag(k), w->val, w->len);
        } else if (cid == TL_messageService) {
            if (fld == TLF_messageService_out) m->out = 1;
            else if (fld == TLF_messageService_id) m->id = (int32_t)w->v32;
            else if (fld == TLF_messageService_date) m->date = w->v32;
        } else if (cid == TL_messageEmpty && fld == TLF_messageEmpty_id) {
            m->id = (int32_t)w->v32;
        }
        return;
    }
    if (k->mk >= 0 && f == k->mk + 1 && peer_type(cid) && fld == 0) {
        uint32_t owner = w->st[k->mk].cid;
        int of = w->st[k->mk].field;
        int is_from = (owner == TL_message && of == TLF_message_from_id) ||
                      (owner == TL_messageService && of == TLF_messageService_from_id);
        int is_peer = (owner == TL_message && of == TLF_message_peer_id) ||
                      (owner == TL_messageService && of == TLF_messageService_peer_id) ||
                      (owner == TL_messageEmpty && of == TLF_messageEmpty_peer_id);
        if (is_from) {
            k->m.from_type = (uint8_t)peer_type(cid);
            k->m.from_id = w->v64;
        } else if (is_peer) {
            k->m.peer_type = (uint8_t)peer_type(cid);
            k->m.peer_id = w->v64;
        }
        return;
    }
    /* dialog */
    if (k->dk >= 0 && f == k->dk) {
        if (fld == TLF_dialog_top_message) k->d.top_msg = (int32_t)w->v32;
        else if (fld == TLF_dialog_unread_count) k->d.unread = (int32_t)w->v32;
        return;
    }
    if (k->dk >= 0 && f == k->dk + 1 && peer_type(cid) && fld == 0 && w->st[k->dk].field == TLF_dialog_peer) {
        k->d.type = (uint8_t)peer_type(cid);
        k->d.id = w->v64;
        return;
    }
    /* users and chats */
    if (k->pk >= 0 && f == k->pk) {
        tg_peer_t *p = &k->p;
        if (cid == TL_user) {
            if (fld == TLF_user_id) p->id = w->v64;
            else if (fld == TLF_user_access_hash) p->access_hash = w->v64;
            else if (fld == TLF_user_first_name) name_part(k, 0, w->val, w->len);
            else if (fld == TLF_user_last_name) name_part(k, 1, w->val, w->len);
            else if (fld == TLF_user_username && !k->has_first) name_part(k, 0, w->val, w->len);
        } else if (cid == TL_userEmpty && fld == TLF_userEmpty_id) {
            p->id = w->v64;
        } else if (cid == TL_chat || cid == TL_chatForbidden || cid == TL_chatEmpty) {
            if (fld == 0 && cid != TL_chat) p->id = w->v64;
            else if (cid == TL_chat && fld == TLF_chat_id) p->id = w->v64;
            else if ((cid == TL_chat && fld == TLF_chat_title) || (cid == TL_chatForbidden && fld == TLF_chatForbidden_title))
                name_part(k, 0, w->val, w->len);
        } else if (cid == TL_channel) {
            if (fld == TLF_channel_id) p->id = w->v64;
            else if (fld == TLF_channel_access_hash) p->access_hash = w->v64;
            else if (fld == TLF_channel_title) name_part(k, 0, w->val, w->len);
        } else if (cid == TL_channelForbidden) {
            if (fld == TLF_channelForbidden_id) p->id = w->v64;
            else if (fld == TLF_channelForbidden_access_hash) p->access_hash = w->v64;
            else if (fld == TLF_channelForbidden_title) name_part(k, 0, w->val, w->len);
        }
    }
}

static void on_obj(tg_client_t *c, coll_t *k)
{
    tg_tlwalk_t *w = &k->w;
    int f = w->sp - 1;
    tg_twf_t *parent = f > 0 ? &w->st[f - 1] : 0;
    int top = parent && parent->is_vec && f - 1 == 1;  /* element of a vector field of the root */
    uint32_t cid = w->cid;
    if (f == 0)
        k->root = cid;
    if (f == 1 && k->root == TL_auth_sentCode && w->pfield == TLF_auth_sentCode_type) {
        c->code_type = cid;                          /* auth.sentCodeType* */
        c->code_len = 0;
    }
    if (is_message(cid) && k->mk < 0 &&
        (top || (parent && !parent->is_vec && (parent->cid == TL_updateNewMessage || parent->cid == TL_updateNewChannelMessage)))) {
        if (top && k->mode == MODE_DIALOGS && parent->cid != TL_messages_dialogs && parent->cid != TL_messages_dialogsSlice)
            return;
        tg_memset(&k->m, 0, sizeof k->m);
        k->m.text = msg_tag(k);
        k->mk = f;
        if (cid == TL_messageService)
            k->m.media = 2;
        return;
    }
    if (cid == TL_dialog && top) {
        tg_memset(&k->d, 0, sizeof k->d);
        k->dk = f;
        return;
    }
    if (top && (cid == TL_user || cid == TL_userEmpty || cid == TL_chat || cid == TL_chatEmpty || cid == TL_chatForbidden ||
                cid == TL_channel || cid == TL_channelForbidden)) {
        tg_memset(&k->p, 0, sizeof k->p);
        k->p.type = (uint8_t)(cid == TL_user || cid == TL_userEmpty ? TG_PEER_USER
                              : cid == TL_channel || cid == TL_channelForbidden ? TG_PEER_CHANNEL : TG_PEER_CHAT);
        k->name_len = k->has_first = k->has_last = 0;
        k->pk = f;
        return;
    }
    if (k->mk >= 0 && f == k->mk + 1 && cid != TL_messageMediaEmpty) {
        int of = w->st[k->mk].field;
        if (w->st[k->mk].cid == TL_message && of == TLF_message_media)
            k->m.media = 1;
    }
}

static void on_end(tg_client_t *c, coll_t *k)
{
    int f = k->w.sp;                                /* index of the frame just closed */
    if (f == k->mk) {
        commit_message(c, k);
        k->mk = -1;
    } else if (f == k->dk) {
        if (c->n_dlg < TG_CL_MAX_DLG && k->d.type)
            c->dlg[c->n_dlg++] = k->d;
        k->dk = -1;
    } else if (f == k->pk) {
        tg_peer_t *p = peer_add(c, k->p.type, k->p.id);
        if (k->p.access_hash)
            p->access_hash = k->p.access_hash;
        if (k->name_len) {
            /* store the name only when it is new: replies repeat the same users, and re-adding every
             * name each time filled the arena until names came out empty */
            const char *old = tg_cl_str(c, p->name);
            uint32_t i = 0;
            while (i < k->name_len && old[i] == k->name[i])
                i++;
            if (i < k->name_len || old[i])
                p->name = arena_add(c, A_PEER, (const uint8_t *)k->name, k->name_len);
        } else if (k->p.type == TG_PEER_USER && p->name == A_PEER) {
            p->name = arena_add(c, A_PEER, (const uint8_t *)"Deleted", 7);
        }
        k->pk = -1;
    }
}

static int walk(tg_client_t *c, coll_t *k, const uint8_t *body, uint32_t len)
{
    int e;
    k->mk = k->dk = k->pk = -1;
    tg_tlwalk_start(&k->w, body, len);
    while ((e = tg_tlwalk_next(&k->w)) > TG_WE_END) {
        if (e == TG_WE_FIELD) on_field(c, k);
        else if (e == TG_WE_OBJ) on_obj(c, k);
        else if (e == TG_WE_OBJ_END) on_end(c, k);
    }
    if (e == TG_WE_ERROR) {
        char t[24] = "schema error ";
        static const char HEX[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
        for (int i = 0; i < 8; i++)
            t[13 + i] = HEX[(k->w.err_arg >> (28 - 4 * i)) & 15];
        error(c, -7, t, 21);
        return -1;
    }
    /* updateShortMessage / updateShortChatMessage: the root is the message */
    if ((k->root == TL_updateShortMessage || k->root == TL_updateShortChatMessage) && k->mode == MODE_UPDATES) {
        if (k->m.out == 0 && !k->m.from_type) {
            k->m.from_type = k->m.peer_type;
            k->m.from_id = k->m.peer_id;
        }
        commit_message(c, k);
    }
    return 0;
}

static void resolve_dialogs(tg_client_t *c, coll_t *k)
{
    for (int i = 0; i < c->n_dlg; i++) {
        tg_dlg_t *d = &c->dlg[i];
        tg_peer_t *p = peer_find(c, d->type, d->id);
        if (p) {
            d->title = p->name;
            d->access_hash = p->access_hash;
        } else {
            d->title = A_PEER;
        }
        d->preview = A_DLG;
        for (int j = 0; j < k->n_tmp; j++) {
            tg_msg_t *m = &c->tmp[j];
            if (m->id == d->top_msg && m->peer_type == d->type && m->peer_id == d->id) {
                d->preview = m->text;
                d->date = m->date;
                d->out = m->out;
                d->media = m->media;
                break;
            }
        }
    }
}

static void resolve_messages(tg_client_t *c)
{
    for (int i = 0; i < c->n_msg; i++) {
        tg_msg_t *m = &c->msg[i];
        tg_peer_t *p = m->out ? 0 : peer_find(c, m->from_type, m->from_id);
        m->from_name = p ? p->name : A_PEER;
    }
}

/* a full peer table or name arena is cleared before a reply, never in the middle of one (the
 * reply brings the users and chats it refers to) */
static void peers_trim(tg_client_t *c)
{
    if (c->n_peers > TG_CL_MAX_PEERS - 48 || c->arena_p > ARENA_P - 1024) {
        c->n_peers = 0;
        arena_reset(c, A_PEER);
    }
}

static void reply_done(tg_client_t *c)
{
    c->req_kind = K_NONE;
    c->req_sent = 0;
}

/* a complete (inflated) reply for the request in flight, or pushed updates (kind K_UPDATES) */
static void on_reply(tg_client_t *c, int kind, const uint8_t *body, uint32_t len)
{
    coll_t *k = &c->coll;
    tg_memset(k, 0, sizeof *k);
    peers_trim(c);
    switch (kind) {
    case K_SEND_CODE:
    case K_SIGN_IN:
    case K_SIGN_UP:
        k->mode = MODE_UPDATES;
        if (walk(c, k, body, len)) {
            reply_done(c);
            return;
        }
        reply_done(c);
        if (k->root == TL_auth_sentCode) {
            ev_push(c, TG_CLE_CODE_SENT, 0, c->code_type, c->code_len);
        } else if (k->root == TL_auth_authorizationSignUpRequired) {
            ev_push(c, TG_CLE_SIGNUP_REQUIRED, 0, 0, 0);
        } else if (k->root == TL_auth_authorization || k->root == TL_auth_sentCodeSuccess) {
            c->ps.logged_in = 1;
            c->login_chain = 1;
            persist(c);
            get_state(c);
        } else {
            error(c, -8, "unexpected reply", 16);
        }
        return;
    case K_GET_STATE:
        k->mode = MODE_UPDATES;
        walk(c, k, body, len);
        reply_done(c);
        persist(c);
        if (c->login_chain) {
            c->login_chain = 0;
            ev_push(c, TG_CLE_LOGGED_IN, 0, 0, 0);
        }
        return;
    case K_DIALOGS:
        c->n_dlg = 0;
        arena_reset(c, A_DLG);
        k->mode = MODE_DIALOGS;
        if (!walk(c, k, body, len)) {
            resolve_dialogs(c, k);
            ev_push(c, TG_CLE_DIALOGS, 0, (uint32_t)c->n_dlg, 0);
        }
        reply_done(c);
        return;
    case K_HISTORY:
        c->n_msg = 0;
        arena_reset(c, A_MSG);
        k->mode = MODE_HISTORY;
        if (!walk(c, k, body, len)) {
            resolve_messages(c);
            ev_push(c, TG_CLE_HISTORY, 0, (uint32_t)c->n_msg, (uint32_t)c->req_dlg);
        }
        reply_done(c);
        return;
    case K_SEND_MSG:
        k->mode = MODE_SENT;
        walk(c, k, body, len);
        reply_done(c);
        ev_push(c, TG_CLE_SENT, 0, (uint32_t)k->sent_id, 0);
        return;
    case K_DIFF:
        k->mode = MODE_UPDATES;
        arena_reset(c, A_MSG);
        walk(c, k, body, len);
        reply_done(c);
        persist(c);
        if (k->root == TL_updates_differenceSlice)
            tg_cl_get_difference(c);
        else
            ev_push(c, TG_CLE_DIFF_DONE, 0, 0, 0);
        return;
    case K_UPDATES:
        k->mode = MODE_UPDATES;
        if (c->arena_m > ARENA_M - 1024)
            arena_reset(c, A_MSG);
        walk(c, k, body, len);
        if (k->root == TL_updatesTooLong && c->req_kind == K_NONE)
            tg_cl_get_difference(c);
        return;
    }
}

static void start_inflate(tg_client_t *c, int kind, const uint8_t *data, uint32_t len)
{
    uint32_t n = tg_gzip_isize(data, len);
    if (!n || n > TG_CL_MAX_REPLY) {
        error(c, -9, "reply too big", 13);
        if (kind != K_UPDATES)
            reply_done(c);
        return;
    }
    c->zbuf = c->cfg.alloc(c->cfg.ctx, n);
    if (!c->zbuf) {
        error(c, -3, "no memory for reply", 19);
        if (kind != K_UPDATES)
            reply_done(c);
        return;
    }
    tg_inflate_start(&c->z, data, len, c->zbuf, n);
    c->zkind = kind;
    c->inflating = 1;
}

/* rpc errors for the request in flight */
static int starts(const uint8_t *s, uint32_t n, const char *p)
{
    uint32_t i = 0;
    for (; p[i]; i++)
        if (i >= n || s[i] != (uint8_t)p[i])
            return 0;
    return 1;
}

static void on_rpc_error(tg_client_t *c, int32_t code, const uint8_t *t, uint32_t n)
{
    if (code == 303) {                               /* *_MIGRATE_X: go to DC X */
        int dc = 0;
        for (uint32_t i = 0; i < n; i++)
            dc = (t[i] >= '0' && t[i] <= '9') ? dc * 10 + (t[i] - '0') : 0;
        if (dc >= 1 && dc <= 5 && dc != c->ps.dc) {
            c->ps.dc = dc;
            c->ps.has_key = 0;                       /* a key per DC: make one there */
            c->ps.logged_in = 0;
            tg_wipe(c->ps.auth_key, 256);
            drop(c, 0);
            return;                                  /* the request is kept and resent there */
        }
    }
    if (code == 400 && starts(t, n, "CONNECTION_NOT_INITED")) {
        c->inited = 0;
        c->req_sent = 0;
        return;
    }
    if (code == 500 && starts(t, n, "AUTH_RESTART") && c->req_kind == K_SEND_CODE && c->auth_restarts < 2) {
        c->auth_restarts++;                          /* "restart the authorization": send it again (as Telethon does) */
        c->req_sent = 0;
        return;
    }
    if (code == 401 && starts(t, n, "SESSION_PASSWORD_NEEDED")) {
        reply_done(c);
        ev_push(c, TG_CLE_PASSWORD, 0, 0, 0);
        return;
    }
    if (code == 401 && !starts(t, n, "PHONE_CODE") && !starts(t, n, "PHONE_NUMBER")) {
        c->ps.logged_in = 0;                         /* AUTH_KEY_UNREGISTERED, SESSION_REVOKED, ... */
        persist(c);
    }
    reply_done(c);
    error(c, code, (const char *)t, n);
}

/* one session event */
static void on_sev(tg_client_t *c, const tg_sev_t *e)
{
    int mine = c->req_kind != K_NONE && c->req_sent && e->req_msg_id == c->req_msg_id;
    switch (e->type) {
    case TG_EV_RESULT:
        if (!mine)
            return;                                  /* an answer to something we gave up on */
        c->inited = 1;
        if (e->gzip)
            start_inflate(c, c->req_kind, e->body, e->len);
        else
            on_reply(c, c->req_kind, e->body, e->len);
        return;
    case TG_EV_ERROR:
        if (mine) {
            c->inited = c->inited || e->code != 400;
            on_rpc_error(c, e->code, e->body, e->len);
        }
        return;
    case TG_EV_RESEND:
        if (mine)
            c->req_sent = 0;
        return;
    case TG_EV_UPDATE:
        on_reply(c, K_UPDATES, e->body, e->len);
        return;
    case TG_EV_GZIP:
        start_inflate(c, K_UPDATES, e->body, e->len);
        return;
    case TG_EV_FATAL:
        drop(c, 5);
        return;
    default:                                         /* pong, new session */
        return;
    }
}

/* drives input, acks, the request and pings for a ready connection */
static int ready(tg_client_t *c)
{
    for (;;) {
        tg_sev_t e;
        int t;
        if (!c->in_packet) {
            uint8_t *pkt;
            uint32_t len;
            int r = tg_net_rx_packet(&c->net, &pkt, &len);
            if (r == 0)
                break;
            if (r < 0) {
                drop(c, 5);
                return TG_CL_BUSY;
            }
            r = tg_sess_input(&c->sess, pkt, len, c->now);
            if (r < 0) {
                if (r == TG_SERR_TRANSPORT && c->sess.err_arg == -404) {
                    c->ps.has_key = 0;               /* the DC forgot our key */
                    c->ps.logged_in = 0;
                    persist(c);
                    error(c, -404, "auth key unknown", 16);
                }
                drop(c, 5);
                return TG_CL_BUSY;
            }
            if (r == 1) {
                tg_net_rx_done(&c->net);
                continue;
            }
            c->in_packet = 1;
        }
        while ((t = tg_sess_next(&c->sess, &e)) != TG_EV_NONE) {
            on_sev(c, &e);
            if (c->conn != C_READY)
                return TG_CL_BUSY;
            if (c->inflating)
                return TG_CL_BUSY;                   /* the packet stays until the reply is inflated */
        }
        c->in_packet = 0;
        tg_net_rx_done(&c->net);
    }
    if (c->sess.n_acks) {
        uint32_t len = tg_sess_send_acks(&c->sess, c->now);
        if (len) {
            frame_out(c, len);
            return TG_CL_SEND;
        }
    }
    if (c->req_kind != K_NONE && !c->req_sent) {
        tg_tlw_t w;
        uint32_t len;
        tg_tlw_init(&w, tg_sess_body(&c->sess), c->sess.body_cap);
        if (!c->inited) {                            /* invokeWithLayer(initConnection(...)) */
            tg_tlw_u32(&w, TL_invokeWithLayer);
            tg_tlw_u32(&w, TL_LAYER);
            tg_tlw_u32(&w, TL_initConnection);
            tg_tlw_u32(&w, 0);
            tg_tlw_u32(&w, (uint32_t)c->cfg.api_id);
            tlw_str(&w, c->cfg.device_model ? c->cfg.device_model : "tinymtproto");
            tlw_str(&w, c->cfg.system_version ? c->cfg.system_version : "unknown");
            tlw_str(&w, c->cfg.app_version ? c->cfg.app_version : "0.1");
            tlw_str(&w, "en");
            tlw_str(&w, "");
            tlw_str(&w, "en");
        }
        tg_tlw_raw(&w, c->req, c->req_len);
        len = w.err ? 0 : tg_sess_send(&c->sess, w.len, 1, c->now, &c->req_msg_id);
        if (!len) {
            reply_done(c);
            error(c, -4, "request too big", 15);
            return TG_CL_BUSY;
        }
        c->req_sent = 1;
        frame_out(c, len);
        return TG_CL_SEND;
    }
    if (c->now - c->last_send >= 60) {               /* keep NATs and the server session alive */
        uint32_t len = tg_sess_ping(&c->sess, c->now, 75, c->now, 0);
        if (len) {
            frame_out(c, len);
            return TG_CL_SEND;
        }
    }
    return TG_CL_IDLE;
}

static int auth_step(tg_client_t *c, uint32_t budget)
{
    tg_auth_t *a = c->auth;
    int st = tg_auth_poll(a, c->now, budget);
    uint8_t *pkt;
    uint32_t len;
    int r;
    switch (st) {
    case TG_AUTH_SEND:
        tg_memcpy(c->tx + TG_NET_HEADROOM, a->out, a->out_len);
        frame_out(c, a->out_len);
        tg_auth_sent(a);
        return TG_CL_SEND;
    case TG_AUTH_WAIT:
        r = tg_net_rx_packet(&c->net, &pkt, &len);
        if (r < 0) {
            drop(c, 5);
            return TG_CL_BUSY;
        }
        if (r == 0)
            return TG_CL_IDLE;
        tg_auth_input(a, pkt, len);
        tg_net_rx_done(&c->net);
        return TG_CL_BUSY;
    case TG_AUTH_BUSY:
        return TG_CL_BUSY;
    case TG_AUTH_DONE:
        tg_memcpy(c->ps.auth_key, a->auth_key, 256);
        tg_memcpy(c->ps.salt, a->server_salt, 8);
        c->ps.time_offset = a->time_offset;
        c->ps.has_key = 1;
        tg_wipe(a, sizeof *a);
        c->cfg.free(c->cfg.ctx, a);
        c->auth = 0;
        start_session(c);                            /* same TCP connection */
        persist(c);
        return TG_CL_BUSY;
    default:
        error(c, -2, "auth key failed", 15);
        drop(c, 30);
        return TG_CL_BUSY;
    }
}

int tg_cl_poll(tg_client_t *c, uint32_t now, uint32_t budget)
{
    c->now = now;
    if (c->ev_head != c->ev_tail) {
        c->ev = c->evq[c->ev_head];
        c->ev_head = (c->ev_head + 1) & 15;
        return TG_CL_EVENT;
    }
    if (c->close_pending) {
        c->close_pending = 0;
        return TG_CL_CLOSE;
    }
    if (c->sending)
        return TG_CL_IDLE;
    if (c->inflating) {
        int r = tg_inflate_step(&c->z, budget * 64);
        if (!r)
            return TG_CL_BUSY;
        c->inflating = 0;
        if (r > 0)
            on_reply(c, c->zkind, c->zbuf, c->z.out_len);
        else {
            error(c, -10, "bad gzip reply", 14);
            if (c->zkind != K_UPDATES)
                reply_done(c);
        }
        c->cfg.free(c->cfg.ctx, c->zbuf);
        c->zbuf = 0;
        return TG_CL_BUSY;
    }
    switch (c->conn) {
    case C_OFF:
        return TG_CL_IDLE;
    case C_BACKOFF:
        if ((int32_t)(now - c->retry_at) < 0 || !c->want_online)
            return TG_CL_IDLE;
        c->conn = C_WANT;
        /* fall through */
    case C_WANT:
        c->ip = dc_ip(c->ps.test, c->ps.dc);
        c->port = 443;
        if (!c->ip) {
            error(c, -11, "unknown DC", 10);
            c->conn = C_OFF;
            return TG_CL_BUSY;
        }
        c->conn = C_WAIT_CONN;
        status(c, TG_CLS_CONNECTING);
        return TG_CL_CONNECT;
    case C_WAIT_CONN:
        return TG_CL_IDLE;
    case C_AUTH:
        return auth_step(c, budget);
    case C_READY:
        return ready(c);
    }
    return TG_CL_IDLE;
}

int tg_cl_init(tg_client_t *c, const tg_clcfg_t *cfg, const tg_persist_t *ps)
{
    tg_memset(c, 0, sizeof *c);
    c->cfg = *cfg;
    tg_rng_init(&c->rng);
    tg_rng_add(&c->rng, cfg->seed, 32);
    if (ps && ps->magic == TG_PERSIST_MAGIC && ps->version == 1 && ps->test == cfg->test) {
        c->ps = *ps;
    } else {
        c->ps.magic = TG_PERSIST_MAGIC;
        c->ps.version = 1;
        c->ps.test = cfg->test;
        c->ps.dc = cfg->dc ? cfg->dc : 2;
    }
    c->rx = cfg->alloc(cfg->ctx, TG_CL_RX);
    c->tx = cfg->alloc(cfg->ctx, TG_CL_TX);
    c->req = cfg->alloc(cfg->ctx, TG_CL_REQ);
    c->arena = cfg->alloc(cfg->ctx, TG_CL_ARENA);
    if (!c->rx || !c->tx || !c->req || !c->arena) {
        tg_cl_free(c);
        return -1;
    }
    tg_net_init(&c->net, c->rx, TG_CL_RX);
    arena_reset(c, A_DLG);
    arena_reset(c, A_MSG);
    arena_reset(c, A_PEER);
    return 0;
}

void tg_cl_free(tg_client_t *c)
{
    void (*fr)(void *, void *) = c->cfg.free;
    void *ctx = c->cfg.ctx;
    if (c->auth) { tg_wipe(c->auth, sizeof *c->auth); fr(ctx, c->auth); }
    if (c->zbuf) fr(ctx, c->zbuf);
    if (c->rx) fr(ctx, c->rx);
    if (c->tx) fr(ctx, c->tx);
    if (c->req) fr(ctx, c->req);
    if (c->arena) fr(ctx, c->arena);
    tg_wipe(c, sizeof *c);
}
