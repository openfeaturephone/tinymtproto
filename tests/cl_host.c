/* cl_host.c - PC host for tg_client.c: Winsock TCP, BCryptGenRandom seed, the saved session
 * (auth key = the account credential) encrypted with DPAPI under the Windows login.
 *
 *   cl_host.exe [--test] [--dc N] [--state PATH]      default state: %LOCALAPPDATA%\tinymtproto\state_{test,prod}.bin
 * stdin, one command per line (api_id/hash come this way, never on the command line):
 *   API <id> <hash> | PHONE <number> | CODE <code> | SIGNUP <first> <last> | DIALOGS | HISTORY <i>
 *   SEND <i> <text> | DIFF | ONLINE | FORGET (delete the saved session) | QUIT
 * stdout: EV <name> ... lines, DLG / MSG / NEW rows (fields separated by '|').
 * Built and driven by live_client.py (against the test DCs). */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "tg_client.h"

static void *h_alloc(void *ctx, uint32_t n) { (void)ctx; return malloc(n); }
static void h_free(void *ctx, void *p) { (void)ctx; free(p); }

/* ---- stdin reader thread (select() on Windows cannot wait on a pipe) ---- */
static CRITICAL_SECTION lock;
static char queue[64][4096];
static int q_head, q_tail, q_eof;

static DWORD WINAPI reader(LPVOID arg)
{
    char line[4096];
    (void)arg;
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\r\n")] = 0;
        for (;;) {
            EnterCriticalSection(&lock);
            if (((q_tail + 1) & 63) != q_head) {
                strcpy(queue[q_tail], line);
                q_tail = (q_tail + 1) & 63;
                LeaveCriticalSection(&lock);
                break;
            }
            LeaveCriticalSection(&lock);
            Sleep(5);
        }
    }
    q_eof = 1;
    return 0;
}

static int next_cmd(char *out)
{
    int got = 0;
    EnterCriticalSection(&lock);
    if (q_head != q_tail) {
        strcpy(out, queue[q_head]);
        q_head = (q_head + 1) & 63;
        got = 1;
    }
    LeaveCriticalSection(&lock);
    return got;
}

/* ---- saved session, DPAPI ---- */
static char state_path[MAX_PATH];

static int load_state(tg_persist_t *ps)
{
    FILE *f = fopen(state_path, "rb");
    static uint8_t blob[4096];
    size_t n;
    DATA_BLOB in, out;
    if (!f) return 0;
    n = fread(blob, 1, sizeof blob, f);
    fclose(f);
    in.pbData = blob;
    in.cbData = (DWORD)n;
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out)) return 0;
    int ok = out.cbData == sizeof *ps;
    if (ok) memcpy(ps, out.pbData, sizeof *ps);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return ok;
}

static void save_state(const tg_persist_t *ps)
{
    DATA_BLOB in, out;
    in.pbData = (BYTE *)ps;
    in.cbData = sizeof *ps;
    if (!CryptProtectData(&in, L"tinymtproto session", NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        printf("EV ERROR -100 DPAPI failed\n");
        return;
    }
    FILE *f = fopen(state_path, "wb");
    if (f) {
        fwrite(out.pbData, 1, out.cbData, f);
        fclose(f);
    }
    LocalFree(out.pbData);
}

/* ---- output ---- */
static void field(const char *s)                       /* one '|'-free, newline-free field */
{
    for (; *s; s++) putchar(*s == '|' || *s == '\n' || *s == '\r' ? ' ' : *s);
}

static const char *ev_name(int t)
{
    switch (t) {
    case TG_CLE_STATUS: return "STATUS";
    case TG_CLE_PERSIST: return "PERSIST";
    case TG_CLE_CODE_SENT: return "CODE_SENT";
    case TG_CLE_SIGNUP_REQUIRED: return "SIGNUP_REQUIRED";
    case TG_CLE_PASSWORD: return "PASSWORD";
    case TG_CLE_LOGGED_IN: return "LOGGED_IN";
    case TG_CLE_DIALOGS: return "DIALOGS";
    case TG_CLE_HISTORY: return "HISTORY";
    case TG_CLE_SENT: return "SENT";
    case TG_CLE_NEW_MESSAGE: return "NEW_MESSAGE";
    case TG_CLE_DIFF_DONE: return "DIFF_DONE";
    case TG_CLE_ERROR: return "ERROR";
    }
    return "?";
}

static void on_event(tg_client_t *c)
{
    tg_clev_t *e = &c->ev;
    printf("EV %s", ev_name(e->type));
    switch (e->type) {
    case TG_CLE_STATUS: {
        static const char *const names[4] = { "offline", "connecting", "key", "online" };
        printf(" %s", e->a < 4 ? names[e->a] : "?");
        break;
    }
    case TG_CLE_PERSIST:
        save_state(&c->ps);
        printf(" dc %d logged_in %d", c->ps.dc, c->ps.logged_in);
        break;
    case TG_CLE_LOGGED_IN:
        printf(" user %llu dc %d", (unsigned long long)c->ps.user_id, c->ps.dc);
        break;
    case TG_CLE_ERROR:
        printf(" %d %s", (int)e->code, c->err_text);
        break;
    case TG_CLE_CODE_SENT:
        printf(" type %08x length %u hash_len %u", e->a, e->b, (unsigned)strlen(c->code_hash));
        break;
    case TG_CLE_SENT:
        printf(" %u", e->a);
        break;
    case TG_CLE_DIALOGS:
        printf(" %u\n", e->a);
        for (int i = 0; i < c->n_dlg; i++) {
            tg_dlg_t *d = &c->dlg[i];
            printf("DLG %d|%d|%llu|%d|", i, d->type, (unsigned long long)d->id, (int)d->unread);
            field(tg_cl_str(c, d->title));
            putchar('|');
            field(d->media && !*tg_cl_str(c, d->preview) ? "[media]" : tg_cl_str(c, d->preview));
            putchar('\n');
        }
        printf("END");
        break;
    case TG_CLE_HISTORY:
        printf(" %u %u\n", e->a, e->b);
        for (int i = 0; i < c->n_msg; i++) {
            tg_msg_t *m = &c->msg[i];
            printf("MSG %d|%u|%d|", (int)m->id, m->date, m->out);
            field(m->out ? "me" : tg_cl_str(c, m->from_name));
            putchar('|');
            field(m->media == 2 ? "[service]" : m->media && !*tg_cl_str(c, m->text) ? "[media]" : tg_cl_str(c, m->text));
            putchar('\n');
        }
        printf("END");
        break;
    case TG_CLE_NEW_MESSAGE: {
        tg_msg_t *m = &c->inbox[e->a];
        tg_peer_t *p = 0;
        for (int i = 0; i < c->n_peers; i++)
            if (c->peers[i].type == m->from_type && c->peers[i].id == m->from_id) p = &c->peers[i];
        printf("\nNEW %d|%d|%llu|%d|", (int)m->id, m->peer_type, (unsigned long long)m->peer_id, m->out);
        field(p ? tg_cl_str(c, p->name) : "");
        putchar('|');
        field(c->inbox_text[e->a]);
        break;
    }
    }
    printf("\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    static tg_client_t c;
    tg_clcfg_t cfg;
    tg_persist_t ps;
    WSADATA wsa;
    SOCKET s = INVALID_SOCKET;
    char cmd[4096];
    int test = 0, dc = 2, have_api = 0;

    state_path[0] = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--test")) test = 1;
        else if (!strcmp(argv[i], "--dc") && i + 1 < argc) dc = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--state") && i + 1 < argc) snprintf(state_path, sizeof state_path, "%s", argv[++i]);
    }
    if (!state_path[0]) {
        const char *base = getenv("LOCALAPPDATA");
        char dir[MAX_PATH];
        snprintf(dir, sizeof dir, "%s\\tinymtproto", base ? base : ".");
        CreateDirectoryA(dir, NULL);
        snprintf(state_path, sizeof state_path, "%s\\state_%s.bin", dir, test ? "test" : "prod");
    }
    WSAStartup(MAKEWORD(2, 2), &wsa);
    InitializeCriticalSection(&lock);
    CreateThread(NULL, 0, reader, NULL, 0, NULL);

    memset(&cfg, 0, sizeof cfg);
    cfg.alloc = h_alloc;
    cfg.free = h_free;
    cfg.test = test;
    cfg.dc = dc;
    BCryptGenRandom(NULL, cfg.seed, sizeof cfg.seed, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    /* the API line must come first */
    while (!have_api) {
        if (next_cmd(cmd)) {
            if (!strncmp(cmd, "API ", 4)) {
                char hash[64];
                if (sscanf(cmd + 4, "%d %63s", &cfg.api_id, hash) == 2 && strlen(hash) == 32) {
                    memcpy(cfg.api_hash, hash, 33);
                    have_api = 1;
                } else {
                    printf("EV ERROR -101 bad API line\n");
                }
                SecureZeroMemory(cmd, sizeof cmd);
            }
        } else if (q_eof) {
            return 1;
        } else {
            Sleep(10);
        }
    }
    int loaded = load_state(&ps);
    if (tg_cl_init(&c, &cfg, loaded ? &ps : NULL)) { printf("EV ERROR -3 no memory\n"); return 1; }
    SecureZeroMemory(&ps, sizeof ps);
    SecureZeroMemory(cfg.api_hash, sizeof cfg.api_hash);
    printf("EV READY saved %d logged_in %d dc %d test %d\n", loaded, c.ps.logged_in, c.ps.dc, test);
    fflush(stdout);

    for (;;) {
        uint32_t now = (uint32_t)time(NULL);
        while (next_cmd(cmd)) {
            char a[1024], b[1024];
            int i;
            if (!strncmp(cmd, "QUIT", 4)) goto out;
            else if (sscanf(cmd, "PHONE %63s", a) == 1) tg_cl_send_code(&c, a);
            else if (sscanf(cmd, "CODE %63s", a) == 1) tg_cl_sign_in(&c, a);
            else if (sscanf(cmd, "SIGNUP %255s %255s", a, b) == 2) tg_cl_sign_up(&c, a, b);
            else if (!strcmp(cmd, "DIALOGS")) tg_cl_get_dialogs(&c);
            else if (sscanf(cmd, "HISTORY %d", &i) == 1) tg_cl_get_history(&c, i);
            else if (sscanf(cmd, "SEND %d %1000[^\n]", &i, a) == 2) tg_cl_send_text(&c, i, a);
            else if (!strcmp(cmd, "DIFF")) tg_cl_get_difference(&c);
            else if (!strcmp(cmd, "ONLINE")) tg_cl_online(&c, 1);
            else if (!strcmp(cmd, "FORGET")) { remove(state_path); printf("EV FORGOTTEN\n"); fflush(stdout); }
            else { printf("EV ERROR -102 unknown command\n"); fflush(stdout); }
        }
        if (q_eof && q_head == q_tail) goto out;
        for (int k = 0; k < 200; k++) {
            int r = tg_cl_poll(&c, now, 64);
            if (r == TG_CL_IDLE) break;
            if (r == TG_CL_EVENT) on_event(&c);
            else if (r == TG_CL_CONNECT) {
                struct sockaddr_in sa;
                char ip[32];
                memset(&sa, 0, sizeof sa);
                sa.sin_family = AF_INET;
                sa.sin_port = htons((u_short)c.port);
                sa.sin_addr.s_addr = htonl(c.ip);
                snprintf(ip, sizeof ip, "%u.%u.%u.%u", c.ip >> 24, (c.ip >> 16) & 255, (c.ip >> 8) & 255, c.ip & 255);
                printf("EV CONNECT %s:%u\n", ip, c.port);
                fflush(stdout);
                s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s != INVALID_SOCKET && connect(s, (struct sockaddr *)&sa, sizeof sa) == 0) {
                    u_long nb = 1;
                    ioctlsocket(s, FIONBIO, &nb);
                    tg_cl_connected(&c);
                } else {
                    if (s != INVALID_SOCKET) closesocket(s);
                    s = INVALID_SOCKET;
                    tg_cl_disconnected(&c);
                }
            } else if (r == TG_CL_SEND) {
                uint32_t off = 0;
                while (off < c.out_len && s != INVALID_SOCKET) {
                    int n = send(s, (const char *)c.out + off, (int)(c.out_len - off), 0);
                    if (n > 0) off += (uint32_t)n;
                    else if (WSAGetLastError() == WSAEWOULDBLOCK) Sleep(1);
                    else break;
                }
                tg_cl_sent(&c);
            } else if (r == TG_CL_CLOSE) {
                if (s != INVALID_SOCKET) closesocket(s);
                s = INVALID_SOCKET;
                tg_cl_disconnected(&c);
            }
        }
        if (s != INVALID_SOCKET) {
            fd_set rd;
            struct timeval tv = { 0, 10000 };
            FD_ZERO(&rd);
            FD_SET(s, &rd);
            if (select(0, &rd, NULL, NULL, &tv) > 0) {
                uint32_t room;
                uint8_t *p = tg_cl_rx_space(&c, &room);
                int n = room ? recv(s, (char *)p, (int)room, 0) : 0;
                if (n > 0) tg_cl_rx_commit(&c, (uint32_t)n);
                else if (room && (n == 0 || WSAGetLastError() != WSAEWOULDBLOCK)) {
                    closesocket(s);
                    s = INVALID_SOCKET;
                    tg_cl_disconnected(&c);
                }
            }
        } else {
            Sleep(10);
        }
    }
out:
    if (s != INVALID_SOCKET) closesocket(s);
    tg_cl_free(&c);
    return 0;
}
