/* tg_net.c - TCP intermediate framing, ported from TDLib td/mtproto/TcpTransport.cpp
 * (Boost Software License 1.0). Comments name the TDLib function.
 *
 * Derived from TDLib, Copyright Aliaksei Levin, Arseny Smirnov 2014-2026, distributed under the
 * Boost Software License 1.0 (LICENSE_1_0.txt). Changes: C port for small freestanding targets;
 * see THIRD_PARTY.md. */
#include "tg_net.h"
#include "tg_proto.h"

void tg_net_init(tg_net_t *n, uint8_t *rx, uint32_t cap)
{
    tg_memset(n, 0, sizeof *n);
    n->rx = rx;
    n->cap = cap;
}

void tg_net_reset(tg_net_t *n)
{
    tg_net_init(n, n->rx, n->cap);
}

uint8_t *tg_net_rx_space(tg_net_t *n, uint32_t *room)
{
    *room = n->cap - n->have;
    return n->rx + n->have;
}

void tg_net_rx_commit(tg_net_t *n, uint32_t len)
{
    n->have += len <= n->cap - n->have ? len : n->cap - n->have;
}

/* drop k bytes from the front of the buffer (forward copy: the destination is lower) */
static void consume(tg_net_t *n, uint32_t k)
{
    uint32_t i, rest = n->have - k;
    for (i = 0; i < rest; i++)
        n->rx[i] = n->rx[k + i];
    n->have = rest;
}

/* IntermediateTransport::read_from_stream */
int tg_net_rx_packet(tg_net_t *n, uint8_t **pkt, uint32_t *len)
{
    if (n->err)
        return -1;
    if (!n->pkt) {
        uint32_t size;
        for (;;) {
            if (n->have < 4)
                return 0;
            size = tg_rd32(n->rx);
            if (!(size & 0x80000000u))
                break;
            n->quick_acks++;                    /* quick ack: a bare length word with the top bit */
            consume(n, 4);
        }
        if (size < 4) {
            n->err = TG_NERR_SHORT;
            n->err_arg = size;
            return -1;
        }
        if (size > n->cap - 4) {
            n->err = TG_NERR_TOO_BIG;
            n->err_arg = size;
            return -1;
        }
        if (n->have < 4 + size)
            return 0;
        n->pkt = size;
    }
    *pkt = n->rx + 4;
    *len = n->pkt;
    return 1;
}

void tg_net_rx_done(tg_net_t *n)
{
    if (n->pkt) {
        consume(n, 4 + n->pkt);
        n->pkt = 0;
    }
}

/* IntermediateTransport::init_output_stream and write_prepare_inplace (no padding, no quick ack) */
uint32_t tg_net_frame(tg_net_t *n, uint8_t *buf, uint32_t len, uint32_t *off)
{
    tg_wr32(buf + 4, len);
    if (n->magic_sent) {
        *off = 4;
        return len + 4;
    }
    tg_wr32(buf, TG_NET_MAGIC);
    n->magic_sent = 1;
    *off = 0;
    return len + 8;
}
