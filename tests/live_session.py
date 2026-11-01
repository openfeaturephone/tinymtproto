"""live_session.py - tg_net.c + tg_session.c against a real Telegram DC. A new auth key is made first
(live_auth.handshake, a throwaway key bound to no account), then a second TCP connection carries the
session; this script only moves stream bytes, build/sess_host does all the MTProto work.

    python tests/check_session.py     # builds build/sess_host
    python tests/live_session.py [--dc 2] [--test] [--host IP] [--api-id N]

Steps: ping -> pong; help.getConfig -> rpc_result; a stale salt -> bad_server_salt -> resend -> rpc_result.
The call is wrapped in invokeWithLayer(LAYER, initConnection(api_id, ...)) and must return a config.
api_id comes from $TG_API_ID or the keyring (see sess_lib.credential), or --api-id N. With --api-id 0 the bare call must get rpc_error 400 CONNECTION_NOT_INITED.
"""
import argparse
import os
import socket
import struct
import sys
import time
import zlib

import live_auth
import sess_lib as L
from sess_lib import u32


class Conn:
    def __init__(self, host, port, h):
        self.s = socket.create_connection((host, port), timeout=20)
        self.h = h
        self.events = []

    def send(self, sent):
        assert sent, "nothing to send (body too big?)"
        self.s.sendall(sent[2])
        return sent[0]

    def wait(self, pred, timeout=15):
        """reads until an event matches pred; acks what the DC asks for. -> that event"""
        end = time.time() + timeout
        while time.time() < end:
            for i, e in enumerate(self.events):
                if pred(e):
                    return self.events.pop(i)
            self.s.settimeout(max(0.1, end - time.time()))
            try:
                data = self.s.recv(65536)
            except socket.timeout:
                break
            if not data:
                sys.exit("DC closed the connection")
            self.h.now(int(time.time()))
            for x in self.h.rx(data):
                if isinstance(x, tuple):
                    if x[0] == "NETERR" or x[1] < 0:
                        sys.exit(f"receive error {x}")
                    continue
                print(f"    {x}")
                if x.kind == "FATAL":
                    sys.exit("session failed")
                self.events.append(x)
            if self.h.state()["acks"]:
                self.send(self.h.acks())
        sys.exit("timeout waiting for the DC")


def describe(e):
    body = bytes.fromhex(e.args[2])
    if e.args[1] == "1":
        body = zlib.decompress(body, 16 + zlib.MAX_WBITS)
    cid = struct.unpack("<I", body[:4])[0]
    return body, cid


def tl_str(t):
    return L.tl_bytes(t.encode())


def get_config(api_id, layer=L.LAYER):
    q = u32(L.HELP_GET_CONFIG)
    if not api_id:
        return q
    init = (u32(0xc1cd5ea9) + u32(0) + u32(api_id) + tl_str("tinymtproto") + tl_str("unknown") + tl_str("0.1")
            + tl_str("en") + tl_str("") + tl_str("en") + q)                       # initConnection
    return u32(L.INVOKE_WITH_LAYER) + u32(layer) + init


def check_config(e, api_id, test=False):
    """-> description; exits if the answer is not what this mode expects"""
    if e.kind == "ERROR":
        text = bytes.fromhex(e.args[2]).decode(errors="replace")
        if not api_id and e.args[1] == "400" and text == "CONNECTION_NOT_INITED":
            return "rpc_result with rpc_error 400 CONNECTION_NOT_INITED (expected with --api-id 0)"
        sys.exit(f"rpc_error {e.args[1]} {text}")
    body, cid = describe(e)
    if cid != 0xcc1a241e:
        sys.exit(f"rpc_result {cid:08x} is not a config")
    # config#cc1a241e flags:# date:int expires:int test_mode:Bool this_dc:int ...
    _, _, date, expires, test_mode, this_dc = struct.unpack("<IIIIII", body[:24])
    want = 0x997275b5 if test else 0xbc799737                                    # boolTrue / boolFalse
    if test_mode != want or abs(date - time.time()) > 300 or expires <= date:
        sys.exit(f"config fields look wrong: date {date} expires {expires} test_mode {test_mode:08x}")
    return (f"rpc_result config, {len(body)} B" + (" (gzip_packed)" if e.args[1] == "1" else "")
            + f", this_dc {this_dc}, test_mode {'true' if test else 'false'}, expires in {expires - date} s")


def main():
    ap = argparse.ArgumentParser()
    live_auth.add_dc_args(ap)
    ap.add_argument("--api-id", type=int, default=None, help="default: $TG_API_ID or the keyring; 0 = no initConnection")
    a = ap.parse_args()
    if a.api_id is None:
        a.api_id = int(L.credential("api_id"))
    req = get_config(a.api_id)
    if not os.path.exists(L.EXE):
        sys.exit("build it first: python tests/check_session.py")

    print("auth key:")
    host, dc = live_auth.resolve_dc(a)
    print(f"  {host}:{a.port}, dc {dc}")
    key, key_id, salt, offset = live_auth.handshake(host, a.port, dc, 64)
    print(f"  auth_key_id {key_id.hex()}, salt {salt.hex()}, time_offset {offset}")
    h = L.Host()
    h.init(key, salt, offset, int(time.time()))
    c = Conn(host, a.port, h)

    print("ping:")
    mid = c.send(h.ping(0x5eed0001))
    e = c.wait(lambda e: e.kind == "PONG")
    assert int(e.args[0], 16) == mid and int(e.args[1], 16) == 0x5eed0001, e
    st = h.state()
    print(f"  PONG for our ping. salt {st['salt'].hex()}, time_offset {st['offset']} (synced {st['synced']})")

    print("help.getConfig:")
    mid = c.send(h.call(req))
    e = c.wait(lambda e: e.kind in ("RESULT", "ERROR") and int(e.args[0], 16) == mid)
    print("  " + check_config(e, a.api_id, a.test))

    print("stale salt:")
    h.salt(os.urandom(8))
    mid = c.send(h.call(req))
    e = c.wait(lambda e: e.kind == "RESEND" and int(e.args[0], 16) == mid)
    assert e.args[1] == "48", e
    print(f"  bad_server_salt (48) for our call; new salt {h.state()['salt'].hex()}; resending")
    mid = c.send(h.call(req))
    e = c.wait(lambda e: e.kind in ("RESULT", "ERROR") and int(e.args[0], 16) == mid)
    print("  after the resend: " + check_config(e, a.api_id, a.test))
    c.s.close()
    h.close()
    print("ALL OK")


if __name__ == "__main__":
    main()
