"""check_session.py - test tg_net.c + tg_session.c against an offline fake DC (sess_lib.Server, the
server side of MTProto 2.0 written from core.telegram.org with check_mtp.py's reference crypto).

    python tests/check_session.py

Covers: framing (magic, split and merged stream slices, quick acks, oversize and short frames),
outgoing headers (salt, session_id, msg_id rules, seq_no), ping/pong, new_session_created, containers,
acks (incl. partial sends), rpc_result / rpc_error / gzip_packed, updates and their duplicate check,
bad_server_salt recovery, bad_msg_notification, inbound checks (session, parity, duplicates, too old,
time window), server time offset updates and resets, transport error codes, and malformed input.
"""
import os
import random
import struct
import sys

import sess_lib as L
from sess_lib import u32, i32, u64

T = 1_790_000_000
UPD = 0x74ae4240                                   # updates#74ae4240: any non-service constructor
CASES = []


def case(f):
    CASES.append(f)
    return f


def setup(rng, offset=0, **kw):
    key = L.rand_key(rng)
    salt = rng.randbytes(8)
    h = L.Host()
    cap = h.init(key, salt, offset, T, seed=rng.randbytes(32), **kw)
    return h, L.Server(key, rng), salt, cap


def one(srv, stream):
    m = srv.recv(stream)
    assert len(m) == 1, m
    return m[0]


def pkts(out):
    return [(e[1], e[2]) for e in out if isinstance(e, tuple) and e[0] == "PKT"]


@case
def ping_pong_new_session(rng):
    h, srv, salt, _ = setup(rng)
    mid, seq, stream = h.ping(0x1122334455667788)
    m = one(srv, stream)
    assert m["salt"] == salt and m["msg_id"] == mid and mid % 4 == 0 and seq == 1 == m["seq_no"]
    assert (mid >> 32) == T, hex(mid)
    assert m["body"] == u32(L.PING) + u64(0x1122334455667788)
    sid = m["session_id"]
    new_salt = rng.randbytes(8)
    a, b, c = srv.msg_id(T, 3), srv.msg_id(T, 1), srv.msg_id(T, 1)
    body = L.container([(a, 1, u32(L.NEW_SESSION_CREATED) + u64(mid) + u64(0xabcdef) + new_salt),
                        (b, 1, u32(L.PONG) + u64(mid) + u64(0x1122334455667788))])
    out = h.rx(srv.packet(sid, c, 2, body))
    ev = L.events(out)
    assert pkts(out) == [(0, 0)], out
    assert [e.kind for e in ev] == ["NEWSESSION", "PONG"], ev
    assert int(ev[0].args[0], 16) == mid and int(ev[0].args[1], 16) == 0xabcdef
    assert int(ev[1].args[0], 16) == mid and int(ev[1].args[1], 16) == 0x1122334455667788
    st = h.state()
    assert st["salt"] == new_salt and st["acks"] == 2 and st["synced"] == 1 and st["offset"] == 0, st
    _, aseq, stream = h.acks()
    m = one(srv, stream)
    assert m["body"] == u32(L.MSGS_ACK) + u32(L.VECTOR) + u32(2) + u64(a) + u64(b), m["body"].hex()
    assert aseq == 2 and m["seq_no"] == 2 and m["salt"] == new_salt
    assert h.acks() is None and h.state()["acks"] == 0
    # ping_delay_disconnect
    _, _, stream = h.ping(5, 75)
    assert one(srv, stream)["body"] == u32(L.PING_DELAY_DISCONNECT) + u64(5) + u32(75)
    h.close()


@case
def bad_server_salt_recovers(rng):
    h, srv, salt, _ = setup(rng)
    stale = rng.randbytes(8)
    h.salt(stale)
    req = u32(L.HELP_GET_CONFIG)
    mid, _, stream = h.call(req)
    m = one(srv, stream)
    assert m["salt"] == stale
    good = rng.randbytes(8)
    out = h.rx(srv.packet(m["session_id"], srv.msg_id(T, 1), 1,
                          u32(L.BAD_SERVER_SALT) + u64(mid) + u32(m["seq_no"]) + u32(48) + good))
    ev = L.events(out)
    assert [e.kind for e in ev] == ["RESEND"] and int(ev[0].args[0], 16) == mid and ev[0].args[1] == "48", ev
    mid2, seq2, stream = h.call(req)
    m2 = one(srv, stream)
    assert m2["salt"] == good and mid2 > mid and seq2 == 3 and m2["body"] == req
    config = u32(0xcc1a241e) + rng.randbytes(64)
    out = h.rx(srv.packet(m["session_id"], srv.msg_id(T, 1), 3, u32(L.RPC_RESULT) + u64(mid2) + config))
    ev = L.events(out)
    assert [e.kind for e in ev] == ["RESULT"], ev
    assert int(ev[0].args[0], 16) == mid2 and ev[0].args[1] == "0" and bytes.fromhex(ev[0].args[2]) == config
    h.close()


@case
def rpc_error_and_gzip(rng):
    h, srv, _, _ = setup(rng)
    mid, _, stream = h.call(u32(L.HELP_GET_CONFIG))
    sid = one(srv, stream)["session_id"]
    packed = rng.randbytes(300)
    body = L.container([(srv.msg_id(T), 1, u32(L.RPC_RESULT) + u64(mid) + u32(L.RPC_ERROR) + i32(420)
                         + L.tl_bytes(b"FLOOD_WAIT_7")),
                        (srv.msg_id(T), 1, u32(L.RPC_RESULT) + u64(mid + 4) + u32(L.GZIP_PACKED) + L.tl_bytes(packed)),
                        (srv.msg_id(T, 3), 0, u32(L.FUTURE_SALTS) + u64(mid) + u32(T) + u32(L.VECTOR) + u32(0))])
    ev = L.events(h.rx(srv.packet(sid, srv.msg_id(T), 4, body)))
    assert [e.kind for e in ev] == ["ERROR", "RESULT"], ev
    assert ev[0].args[1] == "420" and bytes.fromhex(ev[0].args[2]) == b"FLOOD_WAIT_7"
    assert ev[1].args[1] == "1" and bytes.fromhex(ev[1].args[2]) == packed
    assert h.state()["acks"] == 2
    h.close()


@case
def updates_and_duplicates(rng):
    h, srv, _, _ = setup(rng)
    _, _, stream = h.ping(1)
    sid = one(srv, stream)["session_id"]
    u1, u2 = srv.msg_id(T, 3), srv.msg_id(T, 3)
    b1, b2 = u32(UPD) + rng.randbytes(40), u32(UPD) + rng.randbytes(8)
    pkt1 = srv.packet(sid, u1, 1, b1)
    ev = L.events(h.rx(pkt1))
    assert [e.kind for e in ev] == ["UPDATE"] and bytes.fromhex(ev[0].args[1]) == b1, ev
    # the same packet again: ignored by the packet duplicate check, acked again
    out = h.rx(pkt1)
    assert pkts(out) == [(1, 0)] and not L.events(out), out
    # same update msg_id inside a new container: skipped by the update duplicate check
    gz = rng.randbytes(20)
    body = L.container([(u1, 1, b1), (u2, 1, b2), (srv.msg_id(T, 3), 1, u32(L.GZIP_PACKED) + L.tl_bytes(gz))])
    ev = L.events(h.rx(srv.packet(sid, srv.msg_id(T, 3), 2, body)))
    assert [e.kind for e in ev] == ["UPDATE", "GZIP"] and bytes.fromhex(ev[0].args[1]) == b2, ev
    assert bytes.fromhex(ev[1].args[1]) == gz
    h.close()


@case
def inbound_rejects(rng):
    h, srv, _, _ = setup(rng)
    _, _, stream = h.ping(1)
    sid = one(srv, stream)["session_id"]
    body = u32(UPD) + b"\0" * 4
    assert pkts(h.rx(srv.packet(sid, srv.msg_id(T) & ~1, 1, body))) == [(-4, 0)]          # even msg_id
    assert pkts(h.rx(srv.packet(rng.randbytes(8), srv.msg_id(T), 1, body))) == [(-3, 0)]  # other session
    p = bytearray(srv.packet(sid, srv.msg_id(T), 1, body))
    p[40] ^= 4
    assert pkts(h.rx(bytes(p))) == [(-2, -3)]                                             # tampered
    p = bytearray(srv.packet(sid, srv.msg_id(T), 1, body))
    p[4] ^= 1
    assert pkts(h.rx(bytes(p))) == [(-2, -2)]                                             # other key id
    assert pkts(h.rx(u32(4) + i32(-404))) == [(-1, -404)]                                 # transport error
    assert pkts(h.rx(u32(4) + i32(-429))) == [(-1, -429)]
    # malformed messages inside a valid packet
    bad = [u32(L.MSG_CONTAINER) + u32(1) + struct.pack("<QII", srv.msg_id(T), 1, 6) + b"\0" * 8,  # len % 4
           L.container([(srv.msg_id(T), 1, L.container([]))]),                            # nested container
           L.container([(srv.msg_id(T), 1, b"\0" * 8)])[:-4],                             # runs past the end
           u32(L.RPC_RESULT) + u64(0) + u32(UPD),                                         # update in rpc_result
           u32(L.RPC_RESULT) + u64(5) + u32(L.RPC_ERROR) + u32(400),                       # truncated rpc_error
           u32(L.PONG) + u64(1),                                                          # short pong
           u32(L.BAD_SERVER_SALT) + u64(1) + u32(0) + u32(48) + b"\0" * 12]               # long bad_server_salt
    for b in bad:
        ev = L.events(h.rx(srv.packet(sid, srv.msg_id(T), 1, b)))
        assert ev and ev[-1].kind == "FATAL" and ev[-1].args[0] == "-7", (b.hex(), ev)
    h.close()


@case
def bad_msg_notifications(rng):
    h, srv, _, _ = setup(rng)
    mid, _, stream = h.call(u32(L.HELP_GET_CONFIG))
    sid = one(srv, stream)["session_id"]

    def notify(code):
        return L.events(h.rx(srv.packet(sid, srv.msg_id(T), 1, u32(L.BAD_MSG_NOTIFICATION) + u64(mid) + u32(1) + u32(code))))
    for code in (16, 20):
        ev = notify(code)
        assert [e.kind for e in ev] == ["RESEND"] and ev[0].args[1] == str(code), ev
    for code in (18, 19, 32, 33, 34, 35, 64, 99):
        ev = notify(code)
        assert ev[0].kind == "FATAL" and ev[0].args == ["-8", str(code)], ev
    ev = notify(17)
    assert ev[0].kind == "FATAL" and ev[0].args == ["-9", "17"], ev
    assert h.state()["synced"] == 0
    h.close()


@case
def time_offsets(rng):
    h, srv, _, _ = setup(rng, offset=3)
    mid, _, stream = h.ping(1)
    assert mid >> 32 == T + 3                        # handshake offset until the first packet
    sid = one(srv, stream)["session_id"]
    ev = L.events(h.rx(srv.packet(sid, srv.msg_id(T + 100), 1, u32(L.PONG) + u64(mid) + u64(1))))
    assert ev[0].kind == "PONG" and h.state()["offset"] == 100
    mid, _, _ = h.call(u32(L.HELP_GET_CONFIG))
    assert mid >> 32 == T + 100
    # lower ids do not lower the offset; outside [server_time - 300, +30) is rejected
    assert pkts(h.rx(srv.packet(sid, (T + 90) << 32 | 1, 1, u32(UPD) + u32(0)))) == [(0, 0)]
    assert h.state()["offset"] == 100
    assert pkts(h.rx(srv.packet(sid, (T - 250) << 32 | 1, 1, u32(UPD) + u32(0)))) == [(-6, 0)]
    # an answer stamped > 15 s before the request resets the offset (our clock ran ahead)
    ev = L.events(h.rx(srv.packet(sid, (T + 80) << 32 | 5, 1, u32(L.RPC_RESULT) + u64(mid) + u32(UPD))))
    assert ev[0].kind == "RESULT"
    st = h.state()
    assert st["offset"] == 80 and st["synced"] == 0, st
    # 2*64 newer packets, then one older than everything remembered: too old
    for i in range(130):
        assert pkts(h.rx(srv.packet(sid, (T + 81) << 32 | (4 * i + 1), 0, u32(L.MSGS_ACK) + u32(L.VECTOR) + u32(0)))) == [(0, 0)]
    assert pkts(h.rx(srv.packet(sid, (T + 80) << 32 | 9, 0, u32(UPD)))) == [(-5, 0)]
    h.close()


@case
def outgoing_ids_and_seq(rng):
    h, srv, _, _ = setup(rng)
    last, expect_seq = 0, 1
    for i in range(300):
        content = rng.random() < 0.6
        mid, seq, stream = h.call(u32(UPD) + rng.randbytes(4 * rng.randrange(0, 50)), content)
        m = one(srv, stream)
        assert mid > last and mid % 4 == 0 and m["msg_id"] == mid and (mid >> 32) in (T, T + 1), hex(mid)
        if content:
            assert seq == expect_seq, (i, seq, expect_seq)
            expect_seq += 2
        else:
            assert seq == expect_seq - 1, (i, seq, expect_seq)
        last = mid
    h.new_session()
    mid, seq, stream = h.call(u32(UPD))
    m = one(srv, stream)
    assert seq == 1 and mid > last
    h.close()


@case
def framing(rng):
    h, srv, _, cap = setup(rng, rx_cap=600, tx_cap=600)
    srv.max_pad = 200
    mid, _, stream = h.ping(7)
    assert len(stream) <= 600 + 4 and stream[:4] == b"\xee\xee\xee\xee"
    sid = one(srv, stream)["session_id"]
    _, _, stream = h.ping(8)
    assert stream[:4] != b"\xee\xee\xee\xee"        # magic only once
    one(srv, stream)
    # one packet fed in small random slices, with a quick-ack word in front
    p = u32(0x80000000 | 1234) + srv.packet(sid, srv.msg_id(T), 1, u32(L.PONG) + u64(mid) + u64(7))
    got, i = [], 0
    while i < len(p):
        n = rng.randrange(1, 9)
        got += h.rx(p[i:i + n])
        i += n
    assert [e.kind for e in L.events(got)] == ["PONG"] and h.state()["quick_acks"] == 1, got
    # three packets in one slice
    p = b"".join(srv.packet(sid, srv.msg_id(T, 3), 1, u32(UPD) + u32(k)) for k in range(3))
    assert [e.kind for e in L.events(h.rx(p))] == ["UPDATE"] * 3
    # body size limit: body_cap fits tx_cap exactly, one more word does not
    r = h.call(b"\0" * cap)
    assert r and len(r[2]) <= 600 - 4, len(r[2])
    one(srv, r[2])
    assert h.call(b"\0" * (cap + 4)) is None
    h.close()
    h, srv, _, _ = setup(rng, rx_cap=256)
    out = h.rx(u32(400) + b"\0" * 8)
    assert out == [("NETERR", 1, 400)], out
    h.close()
    h, srv, _, _ = setup(rng)
    assert h.rx(u32(2) + b"\0" * 8) == [("NETERR", 2, 2)]
    h.close()


@case
def partial_acks(rng):
    h, srv, _, cap = setup(rng, tx_cap=160)          # small body: acks go out in several messages
    _, _, stream = h.ping(1)
    sid = one(srv, stream)["session_id"]
    ids = [srv.msg_id(T, 3) for _ in range(70)]
    body = L.container([(i, 1, u32(UPD) + u32(k)) for k, i in enumerate(ids)])
    out = h.rx(srv.packet(sid, srv.msg_id(T), 2, body))
    assert len(L.events(out)) == 70
    assert h.state()["acks"] == 64                   # TG_SESS_ACKS, the rest is dropped
    acked = []
    while (r := h.acks()):
        b = one(srv, r[2])["body"]
        assert b[:8] == u32(L.MSGS_ACK) + u32(L.VECTOR)
        n = struct.unpack("<I", b[8:12])[0]
        assert 0 < n and len(b) == 12 + 8 * n <= cap
        acked += list(struct.unpack(f"<{n}Q", b[12:]))
    assert acked == ids[:64], len(acked)
    h.close()


@case
def fuzz(rng):
    h, srv, _, _ = setup(rng)
    _, _, stream = h.ping(1)
    sid = one(srv, stream)["session_id"]
    ids = [L.MSG_CONTAINER, L.RPC_RESULT, L.RPC_ERROR, L.GZIP_PACKED, L.PONG, L.BAD_SERVER_SALT,
           L.BAD_MSG_NOTIFICATION, L.NEW_SESSION_CREATED, L.MSGS_ACK, UPD]
    for _ in range(400):
        parts = []
        for _ in range(rng.randrange(1, 6)):
            parts.append(u32(rng.choice(ids)) if rng.random() < 0.7 else rng.randbytes(4))
            parts.append(rng.randbytes(4) if rng.random() < 0.5 else u32(rng.randrange(0, 40)))
        b = b"".join(parts)
        b += b"\0" * ((-len(b)) % 4)
        out = h.rx(srv.packet(sid, srv.msg_id(T), rng.randrange(0, 3), b))
        assert pkts(out) == [(0, 0)], out
    _, _, stream = h.ping(2)                         # still alive and consistent
    one(srv, stream)
    h.close()


def main():
    L.build()
    rng = random.Random(int(os.environ.get("SEED", "11")))
    fails = 0
    for f in CASES:
        try:
            f(rng)
            print(f"ok    {f.__name__}")
        except AssertionError as e:
            fails += 1
            import traceback
            print(f"FAIL  {f.__name__}: {e!r}\n{traceback.format_exc(limit=-2)}")
    print("ALL OK" if not fails else f"{fails} FAILURES")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
