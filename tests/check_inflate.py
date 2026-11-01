"""check_inflate.py - tg_inflate.c against Python's zlib/gzip.

    python tests/check_inflate.py [--n 300]

Inputs: random, text-like and highly repetitive data, 0..200 KB, every zlib level and strategy
(default, filtered, Huffman-only, RLE, fixed), gzip headers with FNAME/FEXTRA/FCOMMENT/FHCRC, raw
DEFLATE, step budgets 1..1e6. Must reject: bit flips (CRC or data error), truncation, a too-small
output buffer, bad headers. A corrupted input may only ever give an error or the original data. Every case must also end in a bounded number of steps.
"""
import argparse
import gzip
import random
import struct
import subprocess
import sys
import zlib

import common

EXE = common.exe("inflate_host")
ERR = {"HEADER": -1, "DATA": -2, "SPACE": -3, "INPUT": -4, "CHECK": -5}


def build():
    common.build("inflate_host", "inflate_host.c", ["tg_inflate.c", "tg_sha.c"])

def sample(rng):
    kind = rng.choice(["random", "text", "repeat", "tl", "empty"])
    n = rng.choice([0, 1, 10, 100, 1000, 5000, 40000, 200000]) if kind != "empty" else 0
    if kind == "random":
        return rng.randbytes(n)
    if kind == "text":
        words = [rng.randbytes(rng.randrange(1, 8)).hex() for _ in range(50)]
        return " ".join(rng.choice(words) for _ in range(n // 5))[:n].encode()
    if kind == "repeat":
        unit = rng.randbytes(rng.randrange(1, 40))
        return (unit * (n // max(1, len(unit)) + 1))[:n]
    if kind == "tl":                                   # TL-like: small ints, ids, short strings
        out = b""
        while len(out) < n:
            out += struct.pack("<II", rng.choice([0x1cb5c415, 0x38116ee0, 0x56730bcc]), rng.randrange(100))
            out += rng.randbytes(8) + bytes([5]) + b"hello" + b"\0\0"
        return out[:n]
    return b""


def deflate(data, rng, raw=False):
    level = rng.randrange(0, 10)
    strategy = rng.choice([zlib.Z_DEFAULT_STRATEGY, zlib.Z_FILTERED, zlib.Z_HUFFMAN_ONLY, zlib.Z_RLE, zlib.Z_FIXED])
    c = zlib.compressobj(level, zlib.DEFLATED, -15 if raw else 31, rng.randrange(1, 10), strategy)
    out = c.compress(data) + c.flush()
    if not raw and rng.random() < 0.3:                 # header with every optional field
        body = out[10:]
        flg = 2 | 4 | 8 | 16
        hdr = b"\x1f\x8b\x08" + bytes([flg]) + b"\0" * 6 + struct.pack("<H", 5) + b"extra" + b"name.tl\0" + b"comment\0"
        hdr += struct.pack("<H", zlib.crc32(hdr) & 0xffff)
        out = hdr + body
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300)
    a = ap.parse_args()
    build()
    rng = random.Random(5)
    reqs, want = [], []

    def add(budget, cap, raw, blob, expect, label):
        reqs.append(f"Z {budget} {cap} {int(raw)} {blob.hex()}")
        want.append((label, expect, len(blob)))

    for _ in range(a.n):
        data, raw = sample(rng), rng.random() < 0.15
        blob = deflate(data, rng, raw)
        budget = rng.choice([1, 3, 64, 256, 4096, 1000000])
        add(budget, len(data) if raw else -1, raw, blob, data, "ok")
    for _ in range(a.n // 3):                          # python's own gzip module, mtime/filename header
        data = sample(rng)
        add(rng.choice([1, 256]), -1, False, gzip.compress(data, rng.randrange(0, 10)), data, "gzip-module")
    for _ in range(a.n // 2):                          # corruptions
        data = sample(rng) or b"x"
        blob = bytearray(deflate(data, rng))
        i = rng.randrange(10, len(blob))
        blob[i] ^= 1 << rng.randrange(8)
        add(256, -1, False, bytes(blob), ("fail", data), "bitflip")
        blob = deflate(data, rng)
        add(256, len(data), False, blob[:rng.randrange(0, len(blob))], ("fail", data), "truncated")
        if len(data) > 1:
            add(256, len(data) - 1, False, blob, ("err", ERR["SPACE"]), "small-out")
    for bad in (b"\x1f\x8c\x08\0" + b"\0" * 20, b"\x1f\x8b\x07\0" + b"\0" * 20, b"\x1f\x8b\x08\x20" + b"\0" * 20):
        add(256, 100, False, bad, ("err", ERR["HEADER"]), "header")
    add(256, 100, True, b"\x07", ("err", ERR["DATA"]), "type3")      # BTYPE 11

    r = subprocess.run([EXE], input="\n".join(reqs) + "\n", capture_output=True, text=True)
    outs = r.stdout.splitlines()
    if len(outs) != len(reqs):
        sys.exit(f"driver returned {len(outs)} lines for {len(reqs)}\n{r.stderr[-2000:]}")
    counts, fails = {}, 0
    for (label, expect, inlen), out in zip(want, outs):
        f = out.split()
        if isinstance(expect, bytes):
            good = f[0] == "OK" and bytes.fromhex(f[2] if len(f) > 2 else "") == expect
            good = good and int(f[1]) <= 4 * (len(expect) + inlen) + 16          # bounded steps
        elif expect[0] == "err":
            good = f == ["ERR", str(expect[1])]
        else:                  # an error, or (a flip in an unchecked field: mtime, name, pad bits) the right data
            good = f[0] == "ERR" or (f[0] == "OK" and bytes.fromhex(f[2] if len(f) > 2 else "") == expect[1])
        c = counts.setdefault(label, [0, 0])
        c[0 if good else 1] += 1
        if not good:
            fails += 1
            if fails <= 5:
                print(f"FAIL {label}: {out[:120]}")
    for label, (ok, bad) in counts.items():
        print(f"{label:12s} ok {ok:4d}  fail {bad}")
    print("ALL OK" if not fails else f"{fails} FAILURES")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
