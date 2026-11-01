/* walk_host.c - PC driver for tg_tlwalk.c, one object per stdin line:
 *   W hex  -> one line per event, then END or ERR err arg:
 *     O cid pcid pfield | E cid | F cid field type in_vec value | V cid field count | X cid field
 *     (value: hex of the bytes; Bool/true: v0/v1)
 *   S hex  -> skips the root object: SKIP <end-or-error> <bytes consumed>
 * Built by check_tlwalk.py. */
#include <stdio.h>
#include <string.h>
#include "tg_tlwalk.h"

static char line[1 << 23];
static uint8_t buf[1 << 22];

int main(void)
{
    static tg_tlwalk_t w;
    while (fgets(line, sizeof line, stdin)) {
        uint32_t n = 0;
        for (char *p = line + 2; p[0] && p[1] && p[0] != '\n' && p[0] != '\r'; p += 2) {
            unsigned v;
            sscanf(p, "%2x", &v);
            buf[n++] = (uint8_t)v;
        }
        tg_tlwalk_start(&w, buf, n);
        if (line[0] == 'S') {
            int e = tg_tlwalk_next(&w);
            if (e == TG_WE_OBJ || e == TG_WE_VEC) e = tg_tlwalk_skip(&w);
            printf("SKIP %d %u\n", e, w.r.pos);
            fflush(stdout);
            continue;
        }
        int e;
        while ((e = tg_tlwalk_next(&w)) > TG_WE_END) {
            switch (e) {
            case TG_WE_OBJ: printf("O %08x %08x %d\n", w.cid, w.pcid, w.pfield); break;
            case TG_WE_OBJ_END: printf("E %08x\n", w.cid); break;
            case TG_WE_VEC: printf("V %08x %d %u\n", w.cid, w.field, w.count); break;
            case TG_WE_VEC_END: printf("X %08x %d\n", w.cid, w.field); break;
            case TG_WE_FIELD:
                printf("F %08x %d %d %d ", w.cid, w.field, w.type, w.in_vec);
                if (w.type == TG_TT_BOOL || w.type == TG_TT_TRUE) printf("v%u", w.v32);
                else for (uint32_t i = 0; i < w.len; i++) printf("%02x", w.val[i]);
                printf("\n");
                break;
            }
        }
        if (e == TG_WE_END) printf("END %u\n", w.r.pos);
        else printf("ERR %d %08x\n", w.err, w.err_arg);
        fflush(stdout);
    }
    return 0;
}
