"""sess_lib.py - shared by check_session.py and live_session.py: builds build/sess_host (tg_net.c +
tg_session.c), drives it over its line protocol, and has the server side of MTProto 2.0 for the
offline fake server (check_mtp.py reference crypto, x = 8)."""
import os
import struct
import subprocess
import sys

import check_mtp
import common

EXE = common.exe("sess_host")
SRCS = ["tg_sha.c", "tg_aes.c", "tg_bn.c", "tg_pq.c", "tg_tl.c", "tg_mtp.c", "tg_net.c", "tg_session.c"]

# MTProto constructor ids (mtproto_api.tl and core.telegram.org/mtproto/service_messages)
MSG_CONTAINER, RPC_RESULT, RPC_ERROR, GZIP_PACKED = 0x73f1f8dc, 0xf35c6d01, 0x2144ca19, 0x3072cfa1
PING, PING_DELAY_DISCONNECT, PONG = 0x7abe77ec, 0xf3427b8c, 0x347773c5
MSGS_ACK, VECTOR = 0x62d6b459, 0x1cb5c415
BAD_MSG_NOTIFICATION, BAD_SERVER_SALT, NEW_SESSION_CREATED = 0xa7eff811, 0xedab447b, 0x9ec20908
FUTURE_SALTS = 0xae500895
HELP_GET_CONFIG, INVOKE_WITH_LAYER = 0xc4f9186b, 0xda9b0d0d
# MTPROTO_LAYER in TDLib td/telegram/Version.h at 4c6377a, the commit schema/telegram_api.tl comes from
LAYER = 232
# keyring service holding the api_id / api_hash (users "api_id" and "api_hash"); see README.md
CRED_SERVICE = os.environ.get("TG_KEYRING_SERVICE", "telegram-api")


def credential(name):
    """api_id / api_hash: $TG_API_ID / $TG_API_HASH if set, else the OS keyring (Windows Credential
    Manager, macOS Keychain, Secret Service). Never print the value."""
    v = os.environ.get("TG_" + name.upper())
    if v:
        return v
    try:
        import keyring
        v = keyring.get_password(CRED_SERVICE, name)
    except Exception as e:                              # noqa: BLE001  (no keyring module or backend)
        sys.exit(f"no {name}: set TG_{name.upper()} or install keyring ({e})")
    if v is None:
        sys.exit(f"no {name}: set TG_{name.upper()}, or python -m keyring set {CRED_SERVICE} {name}")
    return v


def build():
    common.build("sess_host", "sess_host.c", SRCS)

def u32(v): return struct.pack("<I", v & 0xffffffff)
def i32(v): return struct.pack("<i", v)
def u64(v): return struct.pack("<Q", v & 0xffffffffffffffff)


def tl_bytes(b):
    h = bytes([len(b)]) if len(b) <= 253 else bytes([254]) + len(b).to_bytes(3, "little")
    return h + b + b"\0" * ((-(len(h) + len(b))) % 4)


def tl_read_bytes(b, pos):
    n = b[pos]
    if n == 254:
        n, head = int.from_bytes(b[pos + 1:pos + 4], "little"), 4
    else:
        head = 1
    data = b[pos + head:pos + head + n]
    return data, pos + head + n + (-(head + n)) % 4


class Event:
    def __init__(self, parts):
        self.kind = parts[0]
        self.args = parts[1:]

    def __repr__(self):
        return f"EV {self.kind} " + " ".join(a if len(a) < 40 else a[:40] + ".." for a in self.args)


class Host:
    """build/sess_host; one method per command."""

    def __init__(self):
        self.p = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def _cmd(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        return self.p.stdout.readline().split()

    def init(self, key, salt, offset, now, rx_cap=65536, tx_cap=4096, seed=None):
        seed = seed or os.urandom(32)
        r = self._cmd(f"INIT {key.hex()} {salt.hex()} {offset} {seed.hex()} {now} {rx_cap} {tx_cap}")
        assert r[0] == "OK", r
        return int(r[1])

    def now(self, t): assert self._cmd(f"NOW {t}") == ["OK"]
    def salt(self, s): assert self._cmd(f"SALT {s.hex()}") == ["OK"]
    def new_session(self): assert self._cmd("NEWSESSION") == ["OK"]

    def _sent(self, r):
        """-> (msg_id, seq_no, framed stream bytes) or None"""
        if r[0] != "SEND":
            return None
        return int(r[1], 16), int(r[2]), bytes.fromhex(r[3])

    def ping(self, ping_id, delay=0): return self._sent(self._cmd(f"PING {ping_id:016x} {delay}"))
    def call(self, body, content=1): return self._sent(self._cmd(f"CALL {int(content)} {body.hex()}"))
    def acks(self): return self._sent(self._cmd("ACKS"))

    def rx(self, data):
        """-> list of ("PKT", r, arg) / Event / ("NETERR", err, arg)"""
        self.p.stdin.write(f"RX {data.hex()}\n")
        self.p.stdin.flush()
        out = []
        while True:
            r = self.p.stdout.readline().split()
            if not r or r[0] == "END":
                return out
            if r[0] == "PKT":
                out.append(("PKT", int(r[1]), int(r[2])))
            elif r[0] == "NETERR":
                out.append(("NETERR", int(r[1]), int(r[2])))
            else:
                out.append(Event(r[1:]))

    def state(self):
        r = self._cmd("STATE")
        return {"salt": bytes.fromhex(r[1]), "offset": int(r[2]), "synced": int(r[3]), "acks": int(r[4]),
                "session_id": bytes.fromhex(r[5]), "quick_acks": int(r[6])}

    def close(self):
        self.p.stdin.close()
        self.p.wait()


def events(out):
    return [e for e in out if isinstance(e, Event)]


class Server:
    """The DC side of one connection: unframes and decrypts client packets, frames and encrypts replies."""

    def __init__(self, key, rng):
        self.key, self.rng = key, rng
        self.key_id = check_mtp.sha1(key)[-8:]
        self.buf = b""
        self.magic = False
        self.last_id = 0
        self.max_pad = 1024

    def recv(self, stream):
        """-> list of dicts (salt, session_id, msg_id, seq_no, body) for each complete client packet"""
        self.buf += stream
        if not self.magic:
            assert self.buf[:4] == b"\xee\xee\xee\xee", "missing intermediate magic"
            self.buf, self.magic = self.buf[4:], True
        msgs = []
        while len(self.buf) >= 4:
            n = struct.unpack("<I", self.buf[:4])[0]
            if len(self.buf) < 4 + n:
                break
            pkt, self.buf = self.buf[4:4 + n], self.buf[4 + n:]
            assert pkt[:8] == self.key_id, "auth_key_id"
            ok, plain = check_mtp.ref_decrypt(self.key, 0, pkt)
            assert ok, "client msg_key"
            salt, sid, mid, seq, ln = struct.unpack("<8s8sQII", plain[:32])
            pad = len(plain) - 32 - ln
            assert 12 <= pad <= 1024 and len(plain) % 16 == 0, "client padding"
            msgs.append({"salt": salt, "session_id": sid, "msg_id": mid, "seq_no": seq, "body": plain[32:32 + ln]})
        return msgs

    def msg_id(self, t, kind=1):
        """server msg_id at unix time t: odd, increasing; kind 1 = answer, 3 = not an answer"""
        mid = (t << 32) | (self.rng.getrandbits(30) << 2) | kind
        if mid <= self.last_id:
            mid = (self.last_id & ~3) + 4 + kind
        self.last_id = mid
        return mid

    def packet(self, session_id, msg_id, seq_no, body, salt=b"\0" * 8, frame=True):
        pad = self.rng.randrange(12, self.max_pad)
        pad += (-(32 + len(body) + pad)) % 16
        if pad > 1024:
            pad -= 16
        plain = salt + session_id + struct.pack("<QII", msg_id, seq_no, len(body)) + body + self.rng.randbytes(pad)
        pkt = check_mtp.ref_encrypt(self.key, 8, plain)
        return u32(len(pkt)) + pkt if frame else pkt


def container(msgs):
    """msgs: (msg_id, seq_no, body) -> msg_container body"""
    return u32(MSG_CONTAINER) + u32(len(msgs)) + b"".join(struct.pack("<QII", m, s, len(b)) + b for m, s, b in msgs)


def rand_key(rng):
    return bytes(rng.getrandbits(8) for _ in range(256))

