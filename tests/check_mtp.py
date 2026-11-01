"""check_mtp.py - test the TDLib KDF/Transport port (tg_mtp.c) against a Python reference written
from the formulas on core.telegram.org/mtproto/description (MTProto 2.0).

    python tests/check_mtp.py [--n 100]

C encrypts -> Python decrypts and checks msg_key, header and padding rules; Python encrypts ->
C decrypts; tampered packets must be rejected with the right error code.
"""
import argparse
import hashlib
import random
import subprocess
import sys

import check                                           # build() and ige_ref() of the crypto test



def sha1(b): return hashlib.sha1(b).digest()
def sha256(b): return hashlib.sha256(b).digest()


def kdf_tmp(sn, nn):
    key = sha1(nn + sn) + sha1(sn + nn)[:12]
    iv = sha1(sn + nn)[12:20] + sha1(nn + nn) + nn[:4]
    return key, iv


def kdf2(ak, mk, x):
    a = sha256(mk + ak[x:x + 36])
    b = sha256(ak[40 + x:40 + x + 36] + mk)
    return a[:8] + b[8:24] + a[24:32], b[:8] + a[8:24] + b[24:32]


def ref_encrypt(ak, x, plain):
    mk = sha256(ak[88 + x:88 + x + 32] + plain)[8:24]
    key, iv = kdf2(ak, mk, x)
    return sha1(ak)[-8:] + mk + check.ige_ref(key, iv, plain, True)


def ref_decrypt(ak, x, pkt):
    mk = pkt[8:24]
    key, iv = kdf2(ak, mk, x)
    plain = check.ige_ref(key, iv, pkt[24:], False)
    ok = sha256(ak[88 + x:88 + x + 32] + plain)[8:24] == mk
    return ok, plain


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=100)
    a = ap.parse_args()
    check.build()
    rng = random.Random(7)
    reqs, checks = [], []

    for _ in range(a.n):
        sn, nn = rng.randbytes(16), rng.randbytes(32)
        k, i = kdf_tmp(sn, nn)
        reqs.append(f"kdftmp {sn.hex()} {nn.hex()}")
        checks.append(("kdftmp", f"{k.hex()} {i.hex()}"))
        ak, mk, x = rng.randbytes(256), rng.randbytes(16), rng.choice([0, 8])
        k, i = kdf2(ak, mk, x)
        reqs.append(f"kdf2 {ak.hex()} {mk.hex()} {x}")
        checks.append(("kdf2", f"{k.hex()} {i.hex()}"))

    for _ in range(a.n):                                # C encrypts, Python checks
        ak, x = rng.randbytes(256), rng.choice([0, 8])
        akid = sha1(ak)[-8:]
        body = rng.randbytes(4 * rng.randrange(0, 600))
        hdr = rng.randbytes(28) + len(body).to_bytes(4, "little")   # salt, session, msg_id, seq, len
        reqs.append(f"mtpenc {ak.hex()} {akid.hex()} {x} {rng.randbytes(16).hex()} {(hdr + body).hex()}")
        checks.append(("mtpenc", (ak, x, hdr + body)))

    for _ in range(a.n):                                # Python encrypts, C decrypts (+ tampering)
        ak, x = rng.randbytes(256), rng.choice([0, 8])
        akid = sha1(ak)[-8:]
        body = rng.randbytes(4 * rng.randrange(0, 300))
        pad = rng.randrange(12, 1024)
        pad += (16 - (32 + len(body) + pad) % 16) % 16
        if pad > 1024:
            pad -= 16
        plain = rng.randbytes(28) + len(body).to_bytes(4, "little") + body + rng.randbytes(pad)
        pkt = ref_encrypt(ak, x, plain)
        reqs.append(f"mtpdec {ak.hex()} {akid.hex()} {x} {pkt.hex()}")
        checks.append(("mtpdec", "OK " + body.hex()))
        t = bytearray(pkt)
        t[rng.randrange(24, len(t))] ^= 1 << rng.randrange(8)
        reqs.append(f"mtpdec {ak.hex()} {akid.hex()} {x} {bytes(t).hex()}")
        checks.append(("mtpdec-tamper", "ERR -3"))
        reqs.append(f"mtpdec {ak.hex()} {akid.hex()} {8 - x} {pkt.hex()}")
        checks.append(("mtpdec-wrongx", "ERR -3"))
        bad_id = bytes([akid[0] ^ 1]) + akid[1:]
        reqs.append(f"mtpdec {ak.hex()} {bad_id.hex()} {x} {pkt.hex()}")
        checks.append(("mtpdec-keyid", "ERR -2"))
        # a valid msg_key over a plaintext whose length field is too large
        lie = plain[:28] + (len(body) + 2048).to_bytes(4, "little") + plain[32:]
        reqs.append(f"mtpdec {ak.hex()} {akid.hex()} {x} {ref_encrypt(ak, x, lie).hex()}")
        checks.append(("mtpdec-len", "ERR -4"))

    r = subprocess.run([check.EXE], input="\n".join(reqs) + "\n", capture_output=True, text=True)
    outs = r.stdout.splitlines()
    if len(outs) != len(reqs):
        sys.exit(f"driver returned {len(outs)} lines for {len(reqs)}\n{r.stderr}")
    counts, fails = {}, 0
    for (label, exp), out in zip(checks, outs):
        if label == "mtpenc":
            ak, x, plain_start = exp
            pkt = bytes.fromhex(out)
            ok, plain = ref_decrypt(ak, x, pkt)
            pad = len(plain) - len(plain_start)
            good = (ok and pkt[:8] == sha1(ak)[-8:] and plain.startswith(plain_start) and 12 <= pad <= 1024
                    and len(plain) % 16 == 0)
        else:
            good = out == exp
        c = counts.setdefault(label, [0, 0])
        c[0 if good else 1] += 1
        if not good:
            fails += 1
            if fails <= 5:
                print(f"FAIL {label}: got {out[:100]}")
    for label, (ok, bad) in counts.items():
        print(f"{label:14s} ok {ok:4d}  fail {bad}")
    print("ALL OK" if not fails else f"{fails} FAILURES")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
