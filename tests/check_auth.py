"""check_auth.py - run tg_auth.c (the TDLib auth key handshake port) against a fake Telegram server.

    python tests/check_auth.py [--runs 6]

Builds auth_host.c twice: build/auth_host with the real tg_keys.h (for live_auth.py) and build/auth_fake
with a freshly generated test RSA key (auth_testkey.c, key header in build/). The fake server here is written from the
MTProto spec with pycryptodome / cryptography and pow(): it decrypts RSA_PAD, checks every hash,
and plays the whole exchange. Then a set of broken servers must each end in the right TG_AERR_*.
Also checks the tg_keys.h constants: fingerprints of TG_RSA_N and TG_RSA_TEST_N, TG_DH_P a safe prime,
TG_DH_G_OK. The fake build has a second generated key in TG_RSA_TEST_N, so the test-DC path (dc + 10000)
is run too, and each network's client must refuse the other network's key.
"""
import argparse
import hashlib
import os
import random
import struct
import subprocess
import sys
import time

from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import common

TG = common.SRC
OUT = common.BUILD
SRCS = ["tg_sha.c", "tg_aes.c", "tg_bn.c", "tg_pq.c", "tg_tl.c", "tg_mtp.c"]
REAL_EXE = common.exe("auth_host")
FAKE_EXE = common.exe("auth_fake")

E = {n: i for i, n in enumerate("NONE TRANSPORT PARSE NONCE NO_KEY PQ DH_FAIL HASH DH_PRIME DH_RANGE GEN RETRY STATE SIZE".split())}


# ---- TL helpers ----
def tl_bytes(b):
    h = bytes([len(b)]) if len(b) <= 253 else b"\xfe" + struct.pack("<I", len(b))[:3]
    s = h + b
    return s + b"\0" * (-len(s) % 4)


class R:
    def __init__(self, b):
        self.b, self.p = b, 0

    def raw(self, n):
        v = self.b[self.p:self.p + n]
        assert len(v) == n, "short read"
        self.p += n
        return v

    def u32(self):
        return struct.unpack("<I", self.raw(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.raw(8))[0]

    def bytes(self):
        n = self.raw(1)[0]
        head = 1
        if n == 254:
            n = int.from_bytes(self.raw(3), "little")
            head = 4
        v = self.raw(n)
        self.raw(-(head + n) % 4)
        return v


def be(x, n=None):
    n = n or max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(n, "big")


def ige(key, iv, data, enc):
    ecb = Cipher(algorithms.AES(key), modes.ECB())
    f = (ecb.encryptor() if enc else ecb.decryptor()).update
    prev_y, prev_x = (iv[:16], iv[16:]) if enc else (iv[16:], iv[:16])
    out = b""
    for i in range(0, len(data), 16):
        cur = data[i:i + 16]
        t = f(bytes(a ^ b for a, b in zip(cur, prev_y)))
        t = bytes(a ^ b for a, b in zip(t, prev_x))
        out += t
        prev_x, prev_y = cur, t
    return out


def kdf_tmp(sn, nn):
    a, b = hashlib.sha1(nn + sn).digest(), hashlib.sha1(sn + nn).digest()
    return a + b[:12], b[12:] + hashlib.sha1(nn + nn).digest() + nn[:4]


def fingerprint(n, e=65537):
    return struct.unpack("<Q", hashlib.sha1(tl_bytes(be(n)) + tl_bytes(be(e))).digest()[12:20])[0]


def c_array(name, b):
    rows = [", ".join(f"0x{x:02x}" for x in b[i:i + 16]) for i in range(0, len(b), 16)]
    return f"static const uint8_t {name}[{len(b)}] = {{\n    " + ",\n    ".join(rows) + ",\n};\n"


def read_keys_h():
    src = open(os.path.join(TG, "tg_keys.h")).read()

    def arr(name):
        body = src.split(f"{name}[256] = {{")[1].split("};")[0]
        return bytes(int(x, 16) for x in body.replace("\n", " ").split(",") if x.strip())

    def num(name):
        return int(src.split(f"#define {name} ")[1].split("u")[0], 16)
    return arr("TG_RSA_N"), arr("TG_DH_P"), num("TG_RSA_FP_LO") | num("TG_RSA_FP_HI") << 32


def read_test_key_h():
    src = open(os.path.join(TG, "tg_keys.h")).read()
    body = src.split("TG_RSA_TEST_N[256] = {")[1].split("};")[0]
    n = bytes(int(x, 16) for x in body.replace("\n", " ").split(",") if x.strip())
    lo = int(src.split("#define TG_RSA_TEST_FP_LO ")[1].split("u")[0], 16)
    hi = int(src.split("#define TG_RSA_TEST_FP_HI ")[1].split("u")[0], 16)
    return n, lo | hi << 32


def is_prime(n, rounds=24):
    if n < 4:
        return n in (2, 3)
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    rng = random.Random(n)
    for _ in range(rounds):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def check_constants():
    n, p, fp = read_keys_h()
    n, p = int.from_bytes(n, "big"), int.from_bytes(p, "big")
    assert fingerprint(n) == fp, "TG_RSA_FP does not match TG_RSA_N"
    tn, tfp = read_test_key_h()
    assert fingerprint(int.from_bytes(tn, "big")) == tfp == 0xb25898df208d2603, "TG_RSA_TEST_FP / TG_RSA_TEST_N"
    assert p.bit_length() == 2048 and is_prime(p) and is_prime((p - 1) // 2), "TG_DH_P not a safe prime"
    # DhHandshake::check_config's p mod 4g conditions
    ok = {2: p % 8 == 7, 3: p % 3 == 2, 4: True, 5: p % 5 in (1, 4), 6: p % 24 in (19, 23), 7: p % 7 in (3, 5, 6)}
    want = (1 << 3) | (1 << 4) | (1 << 7)
    got = sum(1 << g for g, v in ok.items() if v)
    assert got == want, f"TG_DH_G_OK should be {got:#x}"
    print("tg_keys.h constants OK (fingerprint, safe prime, generators", sorted(g for g, v in ok.items() if v), ")")
    return p


def build(exe, auth_src, extra_inc=()):
    """auth_src: "tg_auth.c" (in src/) or a harness file in tests/"""
    name = os.path.splitext(os.path.basename(exe))[0]
    if auth_src == "tg_auth.c":
        common.build(name, "auth_host.c", SRCS + ["tg_auth.c"], [f"-I{d}" for d in extra_inc])
    else:
        common.build(name, "auth_host.c", SRCS, [*[f"-I{d}" for d in extra_inc], os.path.join(common.HERE, auth_src)])

def build_all(key, test_key, dh_p):
    os.makedirs(OUT, exist_ok=True)
    build(REAL_EXE, "tg_auth.c")
    fp, tfp = fingerprint(key.n), fingerprint(test_key.n)
    with open(os.path.join(OUT, "tg_testkey.h"), "w") as f:
        f.write("/* generated by check_auth.py: test RSA keys, real DH prime */\n#ifndef TG_KEYS_H\n#define TG_KEYS_H\n"
                "#include <stdint.h>\n")
        f.write(f"#define TG_RSA_FP_LO 0x{fp & 0xffffffff:08x}u\n#define TG_RSA_FP_HI 0x{fp >> 32:08x}u\n")
        f.write(f"#define TG_RSA_TEST_FP_LO 0x{tfp & 0xffffffff:08x}u\n#define TG_RSA_TEST_FP_HI 0x{tfp >> 32:08x}u\n")
        f.write("#define TG_DH_G_OK ((1u << 3) | (1u << 4) | (1u << 7))\n")
        f.write(c_array("TG_RSA_N", be(key.n, 256)) + c_array("TG_RSA_TEST_N", be(test_key.n, 256))
                + c_array("TG_DH_P", be(dh_p, 256)) + "#endif\n")
    build(FAKE_EXE, "auth_testkey.c", [OUT])


# ---- the fake server ----
def rand_prime32(rng):
    while True:
        x = rng.getrandbits(32) | (1 << 31) | 1
        if is_prime(x):
            return x


class FakeServer:
    """bug: name of one deliberate fault, or None. Raises on any client mistake."""

    def __init__(self, key, dh_p, rng, bug=None, time_skew=1234, dc=2):
        self.key, self.p, self.rng, self.bug, self.skew, self.dc = key, dh_p, rng, bug, time_skew, dc
        self.msg = 0

    def wrap(self, body):
        self.msg += 4
        return struct.pack("<QQI", 0, (int(time.time()) << 32) | self.msg | 1, len(body)) + body

    def unwrap(self, pkt):
        key_id, msg_id, n = struct.unpack("<QQI", pkt[:20])
        assert key_id == 0 and n == len(pkt) - 20, "bad no-crypto header"
        assert msg_id % 4 == 0 and abs((msg_id >> 32) - time.time() - self.cli_skew()) < 5, f"bad msg_id {msg_id:#x}"
        return R(pkt[20:])

    def cli_skew(self):
        return getattr(self, "skew_seen", 0)

    def handle(self, pkt):
        r = self.unwrap(pkt)
        cid = r.u32()
        return getattr(self, {0xbe7e8ef1: "req_pq", 0xd712e4be: "req_dh", 0xf5045f1f: "set_client"}[cid])(r)

    def req_pq(self, r):
        self.nonce = r.raw(16)
        if self.bug == "transport":
            return struct.pack("<i", -404)
        self.snonce = self.rng.randbytes(16)
        p1, p2 = rand_prime32(self.rng), rand_prime32(self.rng)
        self.pq_p, self.pq_q = sorted((p1, p2))
        self.pq = be(p1 * p2)
        fps = [0x1122334455667788, fingerprint(self.key.n)]
        if self.bug == "no_key":
            fps = fps[:1]
        nonce = bytes(16) if self.bug == "res_nonce" else self.nonce
        body = struct.pack("<I", 0x05162463) + nonce + self.snonce + tl_bytes(self.pq)
        body += struct.pack("<II", 0x1cb5c415, len(fps)) + b"".join(struct.pack("<Q", f) for f in fps)
        return self.wrap(body)

    def req_dh(self, r):
        assert r.raw(16) == self.nonce and r.raw(16) == self.snonce
        assert r.bytes() == be(self.pq_p) and r.bytes() == be(self.pq_q), "p/q"
        assert r.u64() == fingerprint(self.key.n)
        enc = r.bytes()
        assert len(enc) == 256
        # RSA_PAD, decrypted
        x = be(pow(int.from_bytes(enc, "big"), self.key.d, self.key.n), 256)
        aes_enc = x[32:]
        tkey = bytes(a ^ b for a, b in zip(x[:32], hashlib.sha256(aes_enc).digest()))
        dwh = ige(tkey, bytes(32), aes_enc, False)
        data = dwh[:192][::-1]
        assert hashlib.sha256(tkey + data).digest() == dwh[192:], "RSA_PAD hash"
        ir = R(data)
        assert ir.u32() == 0xa9f55f95
        assert ir.bytes() == self.pq and ir.bytes() == be(self.pq_p) and ir.bytes() == be(self.pq_q)
        assert ir.raw(16) == self.nonce and ir.raw(16) == self.snonce
        self.new_nonce = ir.raw(32)
        assert ir.u32() == self.dc, "dc"
        if self.bug == "dh_fail":
            return self.wrap(struct.pack("<I", 0x79cb045d) + self.nonce + self.snonce + bytes(16))
        # server_DH_inner_data
        g, prime = 3, be(self.p, 256)
        self.a = self.rng.getrandbits(2048)
        ga = pow(g, self.a, self.p)
        if self.bug == "g2":
            g = 2
        if self.bug == "prime":
            prime = prime[:-1] + bytes([prime[-1] ^ 2])
        if self.bug == "ga_small":
            ga = 1 << 1000
        if self.bug == "ga_big":
            ga = self.p - 1
        inner = struct.pack("<I", 0xb5890dba) + (bytes(16) if self.bug == "inner_nonce" else self.nonce) + self.snonce
        inner += struct.pack("<I", g) + tl_bytes(prime) + tl_bytes(be(ga, 256))
        inner += struct.pack("<I", int(time.time()) + self.skew)
        h = hashlib.sha1(inner).digest()
        if self.bug == "hash":
            h = bytes([h[0] ^ 1]) + h[1:]
        awh = h + inner
        awh += self.rng.randbytes(-len(awh) % 16)
        k, iv = kdf_tmp(self.snonce, self.new_nonce)
        enc = ige(k, iv, awh, True)
        self.skew_seen = self.skew
        return self.wrap(struct.pack("<I", 0xd0e8075c) + self.nonce + self.snonce + tl_bytes(enc))

    def set_client(self, r):
        assert r.raw(16) == self.nonce and r.raw(16) == self.snonce
        enc = r.bytes()
        assert len(enc) % 16 == 0
        k, iv = kdf_tmp(self.snonce, self.new_nonce)
        d = ige(k, iv, enc, False)
        ir = R(d[20:])
        assert ir.u32() == 0x6643b654
        assert ir.raw(16) == self.nonce and ir.raw(16) == self.snonce
        assert ir.u64() == 0, "retry_id"
        gb = ir.bytes()
        assert hashlib.sha1(d[20:20 + ir.p]).digest() == d[:20], "client_DH_inner_data hash"
        assert len(d) - 20 - ir.p < 16, "pad"
        gbi = int.from_bytes(gb, "big")
        assert 1 << 1984 <= gbi <= self.p - (1 << 1984)
        self.auth_key = be(pow(gbi, self.a, self.p), 256)
        aux = hashlib.sha1(self.auth_key).digest()[:8]
        n = {"gen_retry": 2, "gen_fail": 3}.get(self.bug, 1)
        h = hashlib.sha1(self.new_nonce + bytes([n]) + aux).digest()[4:20]
        if self.bug == "gen_hash":
            h = bytes(16)
        cid = {1: 0x3bcbf734, 2: 0x46dc1fb9, 3: 0xa69dae02}[n]
        sn = bytes(16) if self.bug == "gen_nonce" else self.snonce
        return self.wrap(struct.pack("<I", cid) + self.nonce + sn + h)


def run(exe, server, seed, budget, dc=2):
    p = subprocess.Popen([exe, seed.hex(), str(dc), str(budget)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True)
    sends = 0
    while True:
        line = p.stdout.readline()
        if not line:
            break
        if line.startswith("SEND "):
            sends += 1
            reply = server(bytes.fromhex(line[5:].strip()))
            p.stdin.write("IN " + reply.hex() + "\n")
            p.stdin.flush()
        else:
            res = line.split()
            break
    p.stdin.close()
    stats = [tuple(int(float(x)) for x in l.split()[1:]) for l in p.stderr.read().splitlines() if l.startswith("STAT")]
    p.wait()
    return res, sends, stats


STATE_NAMES = ("IDLE SEND_PQ WAIT_PQ RES_PQ FACTOR INNER RSA_PAD RSA SEND_DH WAIT_DH DH_PARAMS GB KEY "
               "SEND_CLIENT WAIT_GEN GEN DONE ERROR").split()

BUGS = [("transport", "TRANSPORT", -404), ("res_nonce", "NONCE", 1), ("no_key", "NO_KEY", None),
        ("dh_fail", "DH_FAIL", 0), ("hash", "HASH", 0), ("inner_nonce", "NONCE", 3), ("prime", "DH_PRIME", 0),
        ("g2", "DH_PRIME", 2), ("ga_small", "DH_RANGE", 1), ("ga_big", "DH_RANGE", 1),
        ("gen_retry", "RETRY", 0), ("gen_fail", "GEN", 0), ("gen_hash", "GEN", 1), ("gen_nonce", "NONCE", 4)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=6)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    dh_p = check_constants()
    rng = random.Random(a.seed)
    key = RSA.generate(2048, randfunc=rng.randbytes)
    test_key = RSA.generate(2048, randfunc=rng.randbytes)
    build_all(key, test_key, dh_p)
    fails = 0

    worst = {}
    for i in range(a.runs):
        budget = [1, 8, 64, 100000][i % 4]
        srv = FakeServer(key, dh_p, rng)
        try:
            res, sends, stats = run(FAKE_EXE, srv.handle, rng.randbytes(32), budget)
        except AssertionError as ex:
            print(f"run {i}: server rejected the client: {ex}")
            fails += 1
            continue
        ok = (res[0] == "DONE" and res[1] == srv.auth_key.hex()
              and res[2] == hashlib.sha1(srv.auth_key).digest()[12:20].hex()
              and res[3] == bytes(x ^ y for x, y in zip(srv.new_nonce[:8], srv.snonce[:8])).hex()
              and abs(int(res[4]) - srv.skew) <= 1)
        fails += not ok
        busy = {STATE_NAMES[s]: n for s, n, _ in stats if n > 1}
        print(f"run {i} budget {budget:6d}: {'OK' if ok else 'FAIL ' + ' '.join(res)[:120]}  polls {busy}")
        if budget == 64:
            for s, n, us in stats:
                worst[STATE_NAMES[s]] = max(worst.get(STATE_NAMES[s], 0), us)
    if worst:
        print("slowest single poll at budget 64 (host us):", worst)

    for budget in (1, 64):                          # test DC: dc + 10000 and the test key
        srv = FakeServer(test_key, dh_p, rng, dc=10002)
        res, _, _ = run(FAKE_EXE, srv.handle, rng.randbytes(32), budget, dc=10002)
        ok = res[0] == "DONE" and res[1] == srv.auth_key.hex()
        fails += not ok
        print(f"test DC 10002 budget {budget:5d}: {'OK' if ok else 'FAIL ' + ' '.join(res)[:120]}")
    for dc, k, name in ((10002, key, "production key to a test-DC client"), (2, test_key, "test key to a production client")):
        res, _, _ = run(FAKE_EXE, FakeServer(k, dh_p, rng, dc=dc).handle, rng.randbytes(32), 1000, dc=dc)
        ok = res[0] == "ERR" and int(res[1]) == E["NO_KEY"]
        fails += not ok
        print(f"{name:36s} -> {' '.join(res):12s} {'OK' if ok else 'FAIL (want NO_KEY)'}")

    for bug, err, arg in BUGS:
        srv = FakeServer(key, dh_p, rng, bug)
        res, _, _ = run(FAKE_EXE, srv.handle, rng.randbytes(32), 1000)
        ok = res[0] == "ERR" and int(res[1]) == E[err] and (arg is None or int(res[2]) == arg)
        fails += not ok
        print(f"bad server {bug:12s} -> {' '.join(res):20s} {'OK' if ok else 'FAIL (want ' + err + ')'}")
    print("ALL OK" if not fails else f"{fails} FAILURES")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
