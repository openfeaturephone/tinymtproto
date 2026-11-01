/* tg_net.h - MTProto TCP "intermediate" framing, ported from TDLib td/mtproto/TcpTransport.cpp
 * (IntermediateTransport without padding: magic 0xeeeeeeee once, then a 4-byte LE length before each
 * packet, both ways). No sockets here: the caller moves stream bytes in and out.
 *
 * Receive:  p = tg_net_rx_space(n, &room); read up to room bytes into p; tg_net_rx_commit(n, got);
 *           while (tg_net_rx_packet(n, &pkt, &len) == 1) { use pkt (mutable); tg_net_rx_done(n); }
 * Send:     the packet sits at buf + TG_NET_HEADROOM; k = tg_net_frame(n, buf, len, &off);
 *           write buf[off .. off + k) to the stream.
 *
 * Derived from TDLib, Copyright Aliaksei Levin, Arseny Smirnov 2014-2026, distributed under the
 * Boost Software License 1.0 (LICENSE_1_0.txt). Changes: C port for small freestanding targets;
 * see THIRD_PARTY.md. */
#ifndef TG_NET_H
#define TG_NET_H

#include "tg_crypto.h"

#define TG_NET_HEADROOM 8          /* magic (first packet only) + length */
#define TG_NET_MAGIC    0xeeeeeeeeu

enum { TG_NERR_NONE, TG_NERR_TOO_BIG /* frame larger than the receive buffer */, TG_NERR_SHORT /* length < 4 */ };

typedef struct {
    uint8_t *rx;                   /* caller's receive buffer */
    uint32_t cap, have;            /* its size, bytes in it */
    uint32_t pkt;                  /* length of the packet handed out at rx + 4, 0 = none */
    uint32_t quick_acks;           /* quick-ack words skipped (we never ask for them) */
    int magic_sent, err;
    uint32_t err_arg;              /* the bad length word */
} tg_net_t;

void tg_net_init(tg_net_t *n, uint8_t *rx, uint32_t cap);
void tg_net_reset(tg_net_t *n);                       /* new TCP connection: drop input, send magic again */
uint8_t *tg_net_rx_space(tg_net_t *n, uint32_t *room);
void tg_net_rx_commit(tg_net_t *n, uint32_t len);
/* 1: a packet is at *pkt (writable, valid until tg_net_rx_done); 0: need more bytes;
 * -1: framing error (n->err), the connection must be dropped. */
int tg_net_rx_packet(tg_net_t *n, uint8_t **pkt, uint32_t *len);
void tg_net_rx_done(tg_net_t *n);
/* Writes the length (and the magic before the first packet) into buf[0..8); returns the byte
 * count to send from buf + *off. len must be a multiple of 4 (MTProto packets are). */
uint32_t tg_net_frame(tg_net_t *n, uint8_t *buf, uint32_t len, uint32_t *off);

#endif
