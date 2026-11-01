"""live_auth.py - create an auth key with a real Telegram DC: build/auth_host (tg_auth.c with the real
tg_keys.h) runs the handshake, this script only moves packets over TCP, "intermediate" framing
(0xeeeeeeee once, then a 4-byte LE length + packet each way). No api_id is needed for this step.

    python tests/check_auth.py      # builds build/auth_host
    python tests/live_auth.py [--dc 2] [--test] [--host IP] [--budget 64]

--test uses Telegram's test DCs: their own addresses and RSA key, and dc + 10000 on the wire.

DONE means the DC answered dh_gen_ok and its new_nonce_hash1 matched ours (tg_auth.c checks it).
The key is printed only as its id: it is a throwaway, not bound to any account.
"""
import argparse
import hashlib
import os
import socket
import struct
import subprocess
import sys

import common

EXE = common.exe("auth_host")


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("DC closed the connection")
        b += c
    return b


# TDLib ConnectionCreator::get_default_dc_options (IPv4). DC 2 production: TDLib lists .51; .50
# answers the same and is what these tests were first run against.
PROD_DCS = {1: "149.154.175.50", 2: "149.154.167.50", 3: "149.154.175.100", 4: "149.154.167.91", 5: "149.154.171.5"}
TEST_DCS = {1: "149.154.175.10", 2: "149.154.167.40", 3: "149.154.175.117"}


def add_dc_args(ap):
    ap.add_argument("--dc", type=int, default=2)
    ap.add_argument("--test", action="store_true", help="Telegram test DCs")
    ap.add_argument("--host", help="override the DC address")
    ap.add_argument("--port", type=int, default=443)


def resolve_dc(a):
    """-> (host, dc id as sent in p_q_inner_data_dc)"""
    dcs = TEST_DCS if a.test else PROD_DCS
    host = a.host or dcs.get(a.dc)
    if not host:
        sys.exit(f"no address for {'test ' if a.test else ''}DC {a.dc}: pass --host")
    return host, a.dc + 10000 if a.test else a.dc


def handshake(host, port, dc, budget, verbose=True):
    """Runs build/auth_host over a fresh TCP connection. -> (auth_key, auth_key_id, server_salt, time_offset)"""
    if not os.path.exists(EXE):
        sys.exit("build it first: python tests/check_auth.py")
    s = socket.create_connection((host, port), timeout=20)
    s.sendall(b"\xee\xee\xee\xee")
    p = subprocess.Popen([EXE, os.urandom(32).hex(), str(dc), str(budget)], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    res = None
    while True:
        line = p.stdout.readline()
        if not line:
            break
        if line.startswith("SEND "):
            pkt = bytes.fromhex(line[5:].strip())
            s.sendall(struct.pack("<I", len(pkt)) + pkt)
            n = struct.unpack("<I", recv_exact(s, 4))[0]
            reply = recv_exact(s, n)
            if verbose:
                print(f"  sent {len(pkt):4d} B, got {len(reply):4d} B" + (f" (code {struct.unpack('<i', reply)[0]})" if n == 4 else ""))
            p.stdin.write("IN " + reply.hex() + "\n")
            p.stdin.flush()
        else:
            res = line.split()
            break
    p.stdin.close()
    stats = p.stderr.read()
    p.wait()
    s.close()
    if not res or res[0] != "DONE":
        sys.exit(f"handshake failed: {res}\n{stats}")
    key = bytes.fromhex(res[1])
    assert hashlib.sha1(key).digest()[12:20].hex() == res[2], "auth_key_id"
    return key, bytes.fromhex(res[2]), bytes.fromhex(res[3]), int(res[4])


def main():
    ap = argparse.ArgumentParser()
    add_dc_args(ap)
    ap.add_argument("--budget", type=int, default=64)
    a = ap.parse_args()
    host, dc = resolve_dc(a)
    print(f"{host}:{a.port}, dc {dc}")
    _, key_id, salt, offset = handshake(host, a.port, dc, a.budget)
    print(f"DONE: dh_gen_ok, new_nonce_hash1 matched. auth_key_id {key_id.hex()}, server_salt {salt.hex()}, time_offset {offset} s")


if __name__ == "__main__":
    main()
