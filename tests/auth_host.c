/* auth_host.c - PC driver for tg_auth.c: loops tg_auth_poll and moves packets over stdin/stdout.
 *   auth_host SEED_HEX DC BUDGET
 *   out: "SEND <hex>"  in: "IN <hex>" (one per WAIT)
 *   end: "DONE <auth_key> <auth_key_id> <server_salt> <time_offset>" or "ERR <error> <error_arg>"
 * stderr: per internal state, the number of BUSY polls and the slowest one (us).
 * Built by check_auth.py, with the real keys (build/auth_host, for live_auth.py) or with a test RSA
 * key (build/auth_fake, via auth_testkey.c) for the offline fake server. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
static double now_us(void)
{
    LARGE_INTEGER c, f;
    QueryPerformanceCounter(&c);
    QueryPerformanceFrequency(&f);
    return (double)c.QuadPart * 1e6 / (double)f.QuadPart;
}
#else
static double now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}
#endif
#include "tg_proto.h"

static void puthex(const uint8_t *b, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static uint32_t unhex(const char *s, uint8_t *b, uint32_t cap)
{
    uint32_t n = 0;
    while (s[0] && s[1] && s[0] != '\n' && s[0] != '\r' && n < cap) {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) break;
        b[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

int main(int argc, char **argv)
{
    static tg_auth_t a;
    static char line[1 << 14];
    static uint8_t pkt[4096];
    static uint32_t polls[64];
    static double slowest[64];
    if (argc < 4) { fprintf(stderr, "usage: auth_host SEED_HEX DC BUDGET\n"); return 2; }
    uint32_t budget = (uint32_t)atoi(argv[3]), n = unhex(argv[1], pkt, sizeof pkt);
    tg_rng_init(&a.rng);
    tg_rng_add(&a.rng, pkt, n);
    tg_auth_start(&a, atoi(argv[2]), (uint32_t)time(NULL));
    for (;;) {
        int s0 = a.state;
        double t0 = now_us();
        int st = tg_auth_poll(&a, (uint32_t)time(NULL), budget);
        double dt = now_us() - t0;
        if (s0 >= 0 && s0 < 64) {
            polls[s0]++;
            if (dt > slowest[s0]) slowest[s0] = dt;
        }
        if (st == TG_AUTH_SEND) {
            printf("SEND ");
            puthex(a.out, a.out_len);
            printf("\n");
            fflush(stdout);
            tg_auth_sent(&a);
        } else if (st == TG_AUTH_WAIT) {
            if (!fgets(line, sizeof line, stdin)) { fprintf(stderr, "stdin closed\n"); return 1; }
            if (strncmp(line, "IN ", 3)) { fprintf(stderr, "bad line\n"); return 1; }
            n = unhex(line + 3, pkt, sizeof pkt);
            tg_auth_input(&a, pkt, n);
        } else if (st == TG_AUTH_DONE) {
            printf("DONE ");
            puthex(a.auth_key, 256);
            printf(" ");
            puthex(a.auth_key_id, 8);
            printf(" ");
            puthex(a.server_salt, 8);
            printf(" %d\n", (int)a.time_offset);
            break;
        } else if (st == TG_AUTH_ERROR) {
            printf("ERR %d %d\n", a.error, (int)a.error_arg);
            break;
        }
    }
    fflush(stdout);
    for (int i = 0; i < 64; i++)
        if (polls[i]) fprintf(stderr, "STAT %d %u %.0f\n", i, polls[i], slowest[i]);
    return 0;
}
