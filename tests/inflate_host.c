/* inflate_host.c - PC driver for tg_inflate.c, one request per stdin line:
 *   Z budget cap raw hex   (cap -1 = use tg_gzip_isize; raw 1 = no gzip wrapper)
 *   -> OK steps hex | ERR code
 * Built by check_inflate.py. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tg_inflate.h"

static char line[1 << 24];
static uint8_t in[1 << 23], out[1 << 23];

int main(void)
{
    static tg_inflate_t z;
    while (fgets(line, sizeof line, stdin)) {
        unsigned budget, raw;
        int cap;
        char *p;
        if (sscanf(line, "Z %u %d %u", &budget, &cap, &raw) != 3) { printf("ERR bad\n"); continue; }
        p = line;
        for (int k = 0; k < 4; k++) p = strchr(p, ' ') + 1;
        uint32_t n = 0;
        while (p[0] && p[1] && p[0] != '\n' && p[0] != '\r') {
            unsigned v;
            sscanf(p, "%2x", &v);
            in[n++] = (uint8_t)v;
            p += 2;
        }
        uint32_t c = cap < 0 ? tg_gzip_isize(in, n) : (uint32_t)cap;
        if (c > sizeof out) c = sizeof out;
        if (raw) tg_inflate_start_raw(&z, in, n, out, c);
        else tg_inflate_start(&z, in, n, out, c);
        int r;
        unsigned steps = 0;
        while (!(r = tg_inflate_step(&z, budget))) steps++;
        if (r < 0) { printf("ERR %d\n", r); fflush(stdout); continue; }
        printf("OK %u ", steps);
        for (uint32_t i = 0; i < z.out_len; i++) printf("%02x", out[i]);
        printf("\n");
        fflush(stdout);
    }
    return 0;
}
