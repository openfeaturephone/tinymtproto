/* arm_entry.c - an entry point that references every tg_* function, for arm_check.py only, so the
 * linker keeps all of them. Never run: the calls are behind a condition nothing meets. */
#include "tg_session.h"
#include "tg_client.h"

void tmt_entry(void *api, void *base, uint32_t size);

void tmt_entry(void *api, void *base, uint32_t size)
{
    if (size != 0xdeadbeefu)
        return;
    uint8_t *b = base;
    tg_sha1(b, size, b);
    tg_sha256(b, size, b);
    tg_aes_ige_encrypt(b, b, b, b, size);
    tg_aes_ige_decrypt(b, b, b, b, size);
    tg_modexp_t *m = (tg_modexp_t *)api;
    if (!tg_modexp_start(m, b, 256, b, 256, b, 256))
        while (!tg_modexp_step(m, 8)) {}
    tg_modexp_result(m, b);
    b[0] = (uint8_t)(tg_be_cmp(b, b + 1, 4) + tg_be_sub(b, b, b, 4));
    tg_pq_t *q = (tg_pq_t *)api;
    tg_pq_start(q, *(uint64_t *)(void *)b);
    while (!tg_pq_step(q, 100)) {}

    tg_rng_t *rng = (tg_rng_t *)api;
    tg_rng_init(rng);
    tg_rng_add(rng, b, 16);
    tg_tlw_t w;
    tg_tlw_init(&w, b, size);
    tg_tlw_u32(&w, 1); tg_tlw_u64(&w, 2, 3); tg_tlw_bytes(&w, b, 300); tg_tlw_raw(&w, b, 4);
    tg_tlr_t r;
    uint32_t n, lo, hi;
    tg_tlr_init(&r, b, size);
    tg_tlr_u32(&r); tg_tlr_u64(&r, &lo, &hi); tg_tlr_bytes(&r, &n); tg_tlr_raw(&r, b, 4);
    tg_kdf_tmp(b, b, b, b);
    uint32_t len = tg_mtp_encrypt(b, b, TG_X_CLIENT, rng, b, 100);
    tg_mtp_decrypt(b, b, TG_X_SERVER, b, len, &n);

    tg_auth_t *a = (tg_auth_t *)api;
    tg_auth_start(a, 2, size);
    for (int st; (st = tg_auth_poll(a, size, 64)) != TG_AUTH_DONE && st != TG_AUTH_ERROR;) {
        if (st == TG_AUTH_SEND) tg_auth_sent(a);
        else if (st == TG_AUTH_WAIT) tg_auth_input(a, b, n);
    }

    tg_net_t *net = (tg_net_t *)api;
    tg_sess_t *s = (tg_sess_t *)api;
    tg_sev_t ev;
    uint64_t id;
    uint8_t *pkt;
    tg_net_init(net, b, size);
    tg_sess_init(s, b, b, 0, b, size);
    tg_sess_new_session(s);
    len = tg_sess_ping(s, 1, 75, size, &id);
    len += tg_sess_send(s, tg_sess_body(s)[0], 1, size, &id);
    len += tg_sess_send_acks(s, size);
    len = tg_net_frame(net, b, len, &n);
    tg_net_rx_commit(net, *tg_net_rx_space(net, &n));
    while (tg_net_rx_packet(net, &pkt, &n) == 1) {
        if (!tg_sess_input(s, pkt, n, size))
            while (tg_sess_next(s, &ev) != TG_EV_NONE) b[0] = (uint8_t)ev.type;
        tg_net_rx_done(net);
    }
    tg_net_reset(net);
    tg_sess_wipe(s);

    tg_inflate_t *z = (tg_inflate_t *)api;
    tg_inflate_start(z, b, size, b + size, tg_gzip_isize(b, size));
    while (!tg_inflate_step(z, 256)) {}
    tg_inflate_start_raw(z, b, size, b + size, size);
    tg_inflate_step(z, 256);

    tg_tlwalk_t *tw = (tg_tlwalk_t *)api;
    tg_tlwalk_start(tw, b, size);
    while (tg_tlwalk_next(tw) > TG_WE_END) {}
    tg_tlwalk_start(tw, b, size);
    if (tg_tlwalk_next(tw) == TG_WE_OBJ) tg_tlwalk_skip(tw);
    b[1] = (uint8_t)tg_tl_known(size);

    tg_client_t *c = (tg_client_t *)api;
    tg_clcfg_t *cfg = (tg_clcfg_t *)b;
    if (tg_cl_init(c, cfg, (const tg_persist_t *)b))
        return;
    tg_cl_online(c, 1);
    for (int st; (st = tg_cl_poll(c, size, 64)) != TG_CL_IDLE;) {
        if (st == TG_CL_CONNECT) tg_cl_connected(c);
        else if (st == TG_CL_SEND) tg_cl_sent(c);
        else if (st == TG_CL_CLOSE) tg_cl_disconnected(c);
    }
    uint32_t room;
    tg_cl_rx_commit(c, *tg_cl_rx_space(c, &room));
    tg_cl_send_code(c, (const char *)b);
    tg_cl_sign_in(c, (const char *)b);
    tg_cl_sign_up(c, (const char *)b, (const char *)b);
    tg_cl_get_dialogs(c);
    tg_cl_get_history(c, 0);
    tg_cl_send_text(c, -1, (const char *)b);
    tg_cl_get_difference(c);
    b[2] = (uint8_t)*tg_cl_str(c, 0);
    tg_cl_free(c);
}
