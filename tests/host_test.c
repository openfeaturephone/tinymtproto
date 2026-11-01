/* host_test.c - PC driver for the tg crypto core. One request per stdin line, one hex answer per
 * stdout line; check.py generates the requests and compares with Python's reference code.
 *   sha1 HEX | sha256 HEX | igeenc KEY IV HEX | igedec KEY IV HEX
 *   modexp BUDGET BASE EXP MOD   -> result, then the number of step calls
 *   pq N_HEX                      -> p q (decimal) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tg_mtp.h"

static unsigned char *unhex(const char *s, uint32_t *len)
{
    size_t n = strlen(s) / 2;
    unsigned char *b = malloc(n + 1);
    for (size_t i = 0; i < n; i++) { unsigned v; sscanf(s + 2 * i, "%2x", &v); b[i] = (unsigned char)v; }
    *len = (uint32_t)n;
    return b;
}

static void puthex(const unsigned char *b, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) printf("%02x", b[i]);
}

int main(void)
{
    static char line[1 << 16];
    static tg_modexp_t me;
    while (fgets(line, sizeof line, stdin)) {
        char *tok[6] = {0};
        int nt = 0;
        for (char *p = strtok(line, " \r\n"); p && nt < 6; p = strtok(NULL, " \r\n")) tok[nt++] = p;
        if (!nt) continue;
        uint32_t l0, l1, l2;
        if (!strcmp(tok[0], "sha1") || !strcmp(tok[0], "sha256")) {
            unsigned char *d = unhex(nt > 1 ? tok[1] : "", &l0), out[32];
            if (tok[0][3] == '1') { tg_sha1(d, l0, out); puthex(out, 20); }
            else {                       /* exercise the incremental path: odd-sized updates */
                tg_sha256_t c;
                tg_sha256_init(&c);
                for (uint32_t off = 0; off < l0;) { uint32_t k = 1 + (off * 7) % 70; if (k > l0 - off) k = l0 - off; tg_sha256_update(&c, d + off, k); off += k; }
                tg_sha256_final(&c, out);
                puthex(out, 32);
            }
            free(d);
        } else if (!strcmp(tok[0], "igeenc") || !strcmp(tok[0], "igedec")) {
            unsigned char *k = unhex(tok[1], &l0), *iv = unhex(tok[2], &l1), *d = unhex(tok[3], &l2);
            unsigned char *o = malloc(l2 + 1);
            if (tok[0][3] == 'e') tg_aes_ige_encrypt(k, iv, d, o, l2); else tg_aes_ige_decrypt(k, iv, d, o, l2);
            puthex(o, l2);
            free(k); free(iv); free(d); free(o);
        } else if (!strcmp(tok[0], "modexp")) {
            uint32_t budget = (uint32_t)atoi(tok[1]), steps = 0;
            unsigned char *b = unhex(tok[2], &l0), *e = unhex(tok[3], &l1), *m = unhex(tok[4], &l2), out[256];
            if (tg_modexp_start(&me, b, l0, e, l1, m, l2)) printf("ERR");
            else {
                while (!tg_modexp_step(&me, budget)) steps++;
                tg_modexp_result(&me, out);
                puthex(out, me.mod_len);
                printf(" %u", steps + 1);
            }
            free(b); free(e); free(m);
        } else if (!strcmp(tok[0], "pq")) {
            tg_pq_t c;
            uint32_t steps = 0;
            tg_pq_start(&c, strtoull(tok[1], NULL, 16));
            while (!tg_pq_step(&c, 1000)) steps++;
            printf("%u %u %u", c.p_out, c.q_out, steps + 1);
        } else if (!strcmp(tok[0], "kdftmp")) {             /* kdftmp SERVER_NONCE NEW_NONCE */
            unsigned char *sn = unhex(tok[1], &l0), *nn = unhex(tok[2], &l1), key[32], iv[32];
            tg_kdf_tmp(sn, nn, key, iv);
            puthex(key, 32); printf(" "); puthex(iv, 32);
            free(sn); free(nn);
        } else if (!strcmp(tok[0], "kdf2")) {               /* kdf2 AUTH_KEY MSG_KEY X */
            unsigned char *ak = unhex(tok[1], &l0), *mk = unhex(tok[2], &l1), key[32], iv[32];
            tg_kdf2(ak, mk, atoi(tok[3]), key, iv);
            puthex(key, 32); printf(" "); puthex(iv, 32);
            free(ak); free(mk);
        } else if (!strcmp(tok[0], "mtpenc")) {             /* mtpenc AUTH_KEY KEY_ID X SEED HDR32+BODY */
            unsigned char *ak = unhex(tok[1], &l0), *id = unhex(tok[2], &l1), *seed = unhex(tok[4], &l2);
            uint32_t ld;
            unsigned char *d = unhex(tok[5], &ld);
            tg_rng_t rng;
            tg_rng_init(&rng);
            tg_rng_add(&rng, seed, l2);
            unsigned char *buf = calloc(1, tg_mtp_packet_size(ld - 32) + 16);
            memcpy(buf + 24, d, ld);
            uint32_t n = tg_mtp_encrypt(ak, id, atoi(tok[3]), &rng, buf, ld - 32);
            puthex(buf, n);
            free(ak); free(id); free(seed); free(d); free(buf);
        } else if (!strcmp(tok[0], "mtpdec")) {             /* mtpdec AUTH_KEY KEY_ID X PACKET */
            unsigned char *ak = unhex(tok[1], &l0), *id = unhex(tok[2], &l1), *p = unhex(tok[4], &l2);
            uint32_t body;
            int r = tg_mtp_decrypt(ak, id, atoi(tok[3]), p, l2, &body);
            if (r) printf("ERR %d", r);
            else { printf("OK "); puthex(p + TG_MTP_HDR, body); }
            free(ak); free(id); free(p);
        } else {
            printf("?");
        }
        printf("\n");
        fflush(stdout);
    }
    return 0;
}
