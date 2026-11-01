/* auth_testkey.c - tg_auth.c built with a test RSA key, for the offline fake server in check_auth.py.
 * tg_testkey.h (generated into build/ by check_auth.py) defines TG_KEYS_H and the same names as
 * tg_keys.h, so the real key header is skipped. The DH prime in it is the real one. */
#include "tg_testkey.h"
#include "tg_auth.c"
