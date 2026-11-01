/* sess_host.c - PC driver for tg_net.c + tg_session.c over stdin/stdout, one command per line.
 *   INIT key salt offset seed now rx_cap tx_cap      -> OK body_cap
 *   NOW t                                            -> OK
 *   SALT hex8                                        -> OK      (force a salt, e.g. a stale one)
 *   NEWSESSION                                       -> OK
 *   PING ping_id_hex16 delay                         -> SEND msg_id seq framed_hex
 *   CALL content body_hex                            -> SEND msg_id seq framed_hex | TOOBIG
 *   ACKS                                             -> SEND msg_id seq framed_hex | NOACK
 *   RX stream_hex      (any slice of the TCP stream) -> per packet: PKT r err_arg, then events:
 *       EV RESULT req gzip hex | EV ERROR req code text_hex | EV UPDATE msg_id hex | EV GZIP msg_id hex
 *       EV PONG req ping_id | EV RESEND req code | EV NEWSESSION first unique | EV FATAL code arg
 *     then NETERR err arg if framing failed, and END
 *   STATE                                            -> STATE salt offset synced n_acks session_id quick_acks
 * Built by check_session.py. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tg_session.h"

static void puthex(const uint8_t *b, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static uint32_t unhex(const char *s, uint8_t *b, uint32_t cap)
{
    uint32_t n = 0;
    while (s[0] && s[1] && s[0] != '\n' && s[0] != '\r' && s[0] != ' ' && n < cap) {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) break;
        b[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

static const char *word(const char *s, int k)       /* start of the k-th space-separated word */
{
    while (k--) {
        s = strchr(s, ' ');
        if (!s) return "";
        s++;
    }
    return s;
}

static tg_sess_t s;
static tg_net_t net;
static uint8_t rx[1 << 20], tx[1 << 20], tmp[1 << 20];
static char line[1 << 22];
static uint32_t now;

static void sent(uint32_t len, uint64_t id, uint32_t seq)   /* seq as sent (the header is encrypted now) */
{
    uint32_t off, n;
    if (!len) { printf("TOOBIG\n"); return; }
    n = tg_net_frame(&net, s.tx, len, &off);
    printf("SEND %016llx %u ", (unsigned long long)id, seq);
    puthex(s.tx + off, n);
    printf("\n");
}

static void events(void)
{
    tg_sev_t ev;
    int t;
    while ((t = tg_sess_next(&s, &ev)) != TG_EV_NONE) {
        switch (t) {
        case TG_EV_RESULT:
            printf("EV RESULT %016llx %d ", (unsigned long long)ev.req_msg_id, ev.gzip);
            puthex(ev.body, ev.len);
            break;
        case TG_EV_ERROR:
            printf("EV ERROR %016llx %d ", (unsigned long long)ev.req_msg_id, (int)ev.code);
            puthex(ev.body, ev.len);
            break;
        case TG_EV_UPDATE:
        case TG_EV_GZIP:
            printf("EV %s %016llx ", t == TG_EV_UPDATE ? "UPDATE" : "GZIP", (unsigned long long)ev.msg_id);
            puthex(ev.body, ev.len);
            break;
        case TG_EV_PONG:
            printf("EV PONG %016llx %016llx", (unsigned long long)ev.req_msg_id, (unsigned long long)ev.id2);
            break;
        case TG_EV_RESEND:
            printf("EV RESEND %016llx %d", (unsigned long long)ev.req_msg_id, (int)ev.code);
            break;
        case TG_EV_NEW_SESSION:
            printf("EV NEWSESSION %016llx %016llx", (unsigned long long)ev.req_msg_id, (unsigned long long)ev.id2);
            break;
        case TG_EV_FATAL:
            printf("EV FATAL %d %d", (int)ev.code, (int)s.err_arg);
            break;
        }
        printf("\n");
    }
}

int main(void)
{
    while (fgets(line, sizeof line, stdin)) {
        uint64_t id = 0;
        if (!strncmp(line, "INIT ", 5)) {
            uint8_t key[256], salt[8], seed[64];
            unhex(word(line, 1), key, 256);
            unhex(word(line, 2), salt, 8);
            int32_t off = atoi(word(line, 3));
            uint32_t n = unhex(word(line, 4), seed, 64);
            now = (uint32_t)strtoul(word(line, 5), 0, 10);
            uint32_t rxc = (uint32_t)atoi(word(line, 6)), txc = (uint32_t)atoi(word(line, 7));
            tg_rng_init(&s.rng);
            tg_rng_add(&s.rng, seed, n);
            tg_net_init(&net, rx, rxc);
            int r = tg_sess_init(&s, key, salt, off, tx, txc);
            printf(r ? "ERR\n" : "OK %u\n", s.body_cap);
        } else if (!strncmp(line, "NOW ", 4)) {
            now = (uint32_t)strtoul(line + 4, 0, 10);
            printf("OK\n");
        } else if (!strncmp(line, "SALT ", 5)) {
            unhex(line + 5, s.salt, 8);
            printf("OK\n");
        } else if (!strncmp(line, "NEWSESSION", 10)) {
            tg_sess_new_session(&s);
            printf("OK\n");
        } else if (!strncmp(line, "PING ", 5)) {
            uint64_t pid = strtoull(word(line, 1), 0, 16);
            uint32_t seq = s.seq_no | 1, len = tg_sess_ping(&s, pid, (uint32_t)atoi(word(line, 2)), now, &id);
            sent(len, id, seq);
        } else if (!strncmp(line, "CALL ", 5)) {
            int content = atoi(word(line, 1));
            uint32_t n = unhex(word(line, 2), tmp, sizeof tmp);
            uint32_t len = 0, seq = content ? s.seq_no | 1 : s.seq_no;
            if (n <= s.body_cap) {
                memcpy(tg_sess_body(&s), tmp, n);
                len = tg_sess_send(&s, n, content, now, &id);
            }
            sent(len, id, seq);
        } else if (!strncmp(line, "ACKS", 4)) {
            uint32_t seq = s.seq_no, len = tg_sess_send_acks(&s, now);
            if (len) sent(len, 0, seq);
            else printf("NOACK\n");
        } else if (!strncmp(line, "RX ", 3)) {
            const char *h = line + 3;
            for (;;) {                               /* feed in as many slices as the buffer takes */
                uint32_t room;
                uint8_t *p = tg_net_rx_space(&net, &room);
                uint32_t n = unhex(h, p, room);
                tg_net_rx_commit(&net, n);
                h += 2 * n;
                uint8_t *pkt;
                uint32_t plen;
                int r;
                while ((r = tg_net_rx_packet(&net, &pkt, &plen)) == 1) {
                    int k = tg_sess_input(&s, pkt, plen, now);
                    printf("PKT %d %d\n", k, (int)s.err_arg);
                    if (!k) events();
                    tg_net_rx_done(&net);
                }
                if (r < 0) {
                    printf("NETERR %d %u\n", net.err, net.err_arg);
                    break;
                }
                if (!h[0] || h[0] == '\n' || h[0] == '\r' || !n) break;
            }
            printf("END\n");
        } else if (!strncmp(line, "STATE", 5)) {
            printf("STATE ");
            puthex(s.salt, 8);
            printf(" %d %d %u ", (int)s.time_offset, s.time_synced, s.n_acks);
            puthex(s.session_id, 8);
            printf(" %u\n", net.quick_acks);
        } else {
            printf("ERR unknown\n");
        }
        fflush(stdout);
    }
    return 0;
}
