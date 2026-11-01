/* arm_sizes.c - compiled (not linked) by arm_check.py for 32-bit ARM: each array's size is the
 * sizeof of one library struct on the target, read back from the object file's symbol table. */
#include "tg_client.h"

#define SZ(t) const char sz_##t[sizeof(t)] = { 0 };
SZ(tg_client_t)
SZ(tg_auth_t)
SZ(tg_sess_t)
SZ(tg_net_t)
SZ(tg_inflate_t)
SZ(tg_tlwalk_t)
SZ(tg_modexp_t)
SZ(tg_persist_t)
