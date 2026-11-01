# tinymtproto

A small Telegram client library in C (MTProto 2.0) for machines with very little RAM and no libc.
I wrote it for a Ruio F286 feature phone (Unisoc, ARM Cortex-A7, apps run as position-independent
blobs with no C runtime), where it logs into a real account, lists chats, reads history and sends
messages. The phone app is in [f286-telegram](https://github.com/openfeaturephone/f286-telegram);
this repository is the part that has nothing to do with the phone.

The protocol code is a C port of TDLib's `td/mtproto/` (auth key exchange, KDF, message crypto,
TCP framing, session layer), plus a TL walker driven by tables generated from TDLib's
`telegram_api.tl`, a resumable gzip decoder and a small client state machine on top.

## What it does and doesn't do

Works:
- auth key exchange (RSA_PAD, DH-2048), production and test DCs
- `invokeWithLayer(initConnection)` at layer 232, `*_MIGRATE_X` (new key on the other DC)
- login with phone number and code (`auth.sendCode`, `auth.signIn`, `auth.signUp`)
- chat list (`messages.getDialogs`, 30 chats), history (`messages.getHistory`, 20 messages),
  sending text, pushed new messages, `updates.getDifference`, update state kept across restarts
- `gzip_packed` replies, `bad_server_salt` / `bad_msg_notification` recovery, acks, pings

Not supported:
- two-step verification (2FA, SRP): the client reports `TG_CLE_PASSWORD` and stops there
- media of any kind (shown as a flag on the message), secret chats, calls, reactions, edits
- PFS / temporary keys, outgoing containers, HTTP transport, obfuscated transport, proxies
- IPv6, DNS: the DC addresses are built in

It has only been used against a real account from one phone, so treat it as young code. Use a
secondary account while trying it: client bugs can earn flood waits.

## Design rules

Everything in `src/` follows the rules of the original target:
- no writable globals; every function works on a context struct the caller allocates
- no libc; the only things the compiler may call are `memcpy`/`memset`
- no 64-bit division (no `__aeabi_uldivmod` on the target)
- wire data is read byte by byte, so any alignment is fine
- nothing blocks: the 2048-bit modexps, pq factoring and inflate are `*_step(budget)` state
  machines, so a single-threaded UI loop can drive them from a timer
- no I/O inside: the host opens TCP, moves bytes in and out, supplies the time and the entropy,
  and saves `tg_persist_t` when told to

The host contract is at the top of `src/tg_client.h`. In short: call `tg_cl_poll()` from a timer
and act on what it returns (`CONNECT`, `SEND`, `CLOSE`, `EVENT`, `BUSY`, `IDLE`). The lower
layers (`tg_auth`, `tg_session`, `tg_net`) can be used on their own; their headers say how.

## Sizes

Measured with `python tests/arm_check.py` (zig 0.16 clang, Thumb-2, `-Os`, `-fropi`, strict
alignment):

| | bytes |
|---|---|
| whole library, linked | 51128 |
| of which schema tables (all 1722 constructors) | 20541 |
| `tg_client_t` (includes the session state) | 14056 |
| `tg_auth_t` (only during key exchange) | 9016 |
| buffers `tg_cl_init` allocates (rx 64 KiB, tx, request, string arena) | 91220 |

So a connected client needs about 103 KiB of heap, 112 KiB while it makes an auth key. A
`gzip_packed` reply also needs a buffer the size of the unpacked reply while it is parsed (the
gzip trailer gives the size; anything over 512 KiB is refused). The buffer sizes are the
`TG_CL_*` defines at the top of `tg_client.h`; the 64 KiB receive buffer is the big one and it
has to hold the largest single packet the server sends (a reply is still gzipped at that point). Stack use was not measured; nothing recurses.

On the phone (Cortex-A7, budget 64 per step) the whole key exchange took about 10 s, most of it
pq factoring (about 7 s); the DH part about 1 s.

## Building and testing

You need Python 3 with `cryptography` and `pycryptodome` for the tests, and a C compiler. The
tests use `$CC` if it is set, otherwise `python -m ziglang cc`, which is what I use on Windows:

```
pip install ziglang cryptography pycryptodome pyelftools
python tests/run_all.py
```

That runs, with no network and no account:

| test | what it checks |
|---|---|
| `check.py` | SHA-1/256, AES-256-IGE, modexp (Telegram's DH prime, RSA-2048, random moduli, budgets 1..100000), pq, all against Python |
| `check_mtp.py` | MTProto 2.0 KDF and message encryption against a reference written from core.telegram.org, tampered packets |
| `check_auth.py` | the key exchange against an offline fake server with generated RSA keys, 14 broken-server cases, the constants in `tg_keys.h` |
| `check_session.py` | framing and session layer against an offline fake DC: containers, acks, salts, time offsets, duplicates, fuzz |
| `check_inflate.py` | inflate against zlib/gzip, every strategy, corrupted and truncated input |
| `check_tlwalk.py` | the TL walker against a Python model built from `telegram_api.tl` |
| `arm_check.py` | the freestanding ARM build above: links with no runtime, no `.data` |

On Linux or macOS there is also a Makefile (`make`, `make test`, `make arm`); I have only run the
Python runner on Windows, so the Makefile is untested.

### Live tests

These talk to Telegram's servers:

```
python tests/live_auth.py --test            # new auth key with test DC 2, no account needed
python tests/live_session.py --test         # ping, help.getConfig, stale-salt recovery
python tests/live_client.py                 # whole client on a test account (Windows only)
```

`live_client.py` uses test numbers `99966XYYYY` (X = DC id, the login code is X repeated), which
need no SIM. When I last ran it (late October 2026) the test DCs refused the documented code with
`PHONE_CODE_INVALID`, and other projects reported the same, so it may fail on Telegram's side.
Its host program `tests/cl_host.c` uses Winsock and DPAPI, so it only builds on Windows.

## api_id and api_hash

Telegram wants every client to identify itself with an api_id and api_hash. Get your own:
log in at https://my.telegram.org with your phone number, open "API development tools", fill in
the form (any app title and short name), and you get a number (api_id) and a 32-character hex
string (api_hash). They are tied to your account: don't publish them.

The library takes them in `tg_clcfg_t`; it never reads files. The Python tests read them from
environment variables, or from the OS keyring (Windows Credential Manager, macOS Keychain,
Secret Service) under the service name `telegram-api`:

```
python -m keyring set telegram-api api_id
python -m keyring set telegram-api api_hash
```

or `TG_API_ID=... TG_API_HASH=...` for one run. `TG_KEYRING_SERVICE` changes the service name.
Only `live_session.py` (api_id) and `live_client.py` (both) need them.

## Gotchas

- `tg_persist_t` holds the auth key, which is as good as a logged-in session. Store it like a
  password. `cl_host.c` encrypts it with DPAPI; on a phone with no protected storage that is up
  to you.
- The RNG is a SHA-256 pool and only as good as what you feed it (`cfg.seed`, `tg_rng_add`).
  On a device with no hardware RNG, get entropy from somewhere real before making a key.
- zig cc ignores `-mno-unaligned-access` for ARM and still emits unaligned `ldr.w`/`str.w`;
  `-Xclang -target-feature -Xclang +strict-align` is what works (see `tests/arm_check.py`).
- Under `-fropi` a table of pointers to string literals needs RW relocations, which the target
  loader did not support. Keep such tables out of `src/`.
- Test DCs need their own RSA key; `tg_auth.c` picks it when the DC id is 10000 + n, which is
  how test DCs are named on the wire.

## Updating the schema

`tools/gen_tl.py` turns `schema/telegram_api.tl` into `src/tg_schema.c`/`.h`. For a newer layer,
take `td/generate/scheme/telegram_api.tl` from a TDLib checkout, set `LAYER` in `gen_tl.py` to
that commit's `MTPROTO_LAYER` (`td/telegram/Version.h`), and run:

```
python tools/gen_tl.py --tl path/to/telegram_api.tl
python tests/check_tlwalk.py
```

Names used by `tg_client.c` must still exist in the new schema; the generator stops if one is
missing.

## Licence

MIT (see `LICENSE`), copyright (c) 2026 willisdylan. Parts are derived from TDLib (Boost Software
License 1.0) and from zlib's puff.c (zlib licence); `THIRD_PARTY.md` lists which.
