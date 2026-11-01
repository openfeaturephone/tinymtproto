"""check.py - build the crypto core for the PC and compare it with Python reference code.

    python tests/check.py [--n 200]

References: hashlib (SHA), `cryptography` AES-ECB composed into IGE, pow() (modexp), and a known
FIPS-197 AES-256 vector. Also runs modexp with the real Telegram DH prime and an RSA-2048 key
(e = 65537) at several step budgets, and PQ products of two random 32-bit primes.
"""
import argparse
import hashlib
import random
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import common

EXE = common.exe("host_test")

# the 2048-bit safe prime every Telegram DC returns in server_DH_inner_data (g = 3)
TG_DH_PRIME = int(
    "c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c37"
    "20fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f642477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4"
    "a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4"
    "e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b", 16)


def build():
    common.build("host_test", "host_test.c", common.CORE)

def ige_ref(key, iv, data, enc):
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


def be(x, n=None):
    n = n or max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(n, "big")


def is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def rand_prime(rng, bits):
    while True:
        p = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(p):
            return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200, help="random cases per primitive")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    build()
    rng = random.Random(a.seed)
    cases = []   # (request line, expected answer or checker, label)

    for _ in range(a.n):
        d = rng.randbytes(rng.randrange(0, 300))
        cases.append((f"sha1 {d.hex()}", hashlib.sha1(d).hexdigest(), "sha1"))
        cases.append((f"sha256 {d.hex()}", hashlib.sha256(d).hexdigest(), "sha256"))
    for d in (b"", b"abc", b"a" * 55, b"a" * 56, b"a" * 64, b"a" * 119, b"a" * 120):
        cases.append((f"sha256 {d.hex()}", hashlib.sha256(d).hexdigest(), "sha256-edge"))
        cases.append((f"sha1 {d.hex()}", hashlib.sha1(d).hexdigest(), "sha1-edge"))

    fips_key = bytes(range(32))
    fips_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    cases.append((f"igeenc {fips_key.hex()} {'00' * 32} {fips_pt.hex()}", "8ea2b7ca516745bfeafc49904b496089", "aes-fips197"))
    for _ in range(a.n):
        k, iv, d = rng.randbytes(32), rng.randbytes(32), rng.randbytes(16 * rng.randrange(1, 40))
        c = ige_ref(k, iv, d, True)
        cases.append((f"igeenc {k.hex()} {iv.hex()} {d.hex()}", c.hex(), "ige-enc"))
        cases.append((f"igedec {k.hex()} {iv.hex()} {c.hex()}", d.hex(), "ige-dec"))

    p = TG_DH_PRIME
    for i in range(max(4, a.n // 20)):
        b = rng.getrandbits(2048) % p
        e = rng.randbytes(256)
        budget = rng.choice([1, 3, 7, 50, 100000])
        cases.append((f"modexp {budget} {be(b).hex()} {e.hex()} {be(p).hex()}", be(pow(b, int.from_bytes(e, 'big'), p), 256).hex(), "dh-2048"))
    cases.append((f"modexp 1000 03 {rng.randbytes(256).hex()} {be(p).hex()}", None, "dh-g3"))
    for _ in range(3):                       # RSA-2048 with e = 65537, as for the server's public key
        n = rand_prime(rng, 1024) * rand_prime(rng, 1024)
        m = rng.getrandbits(2040)
        cases.append((f"modexp 1000 {be(m).hex()} 010001 {be(n).hex()}", be(pow(m, 65537, n), (n.bit_length() + 7) // 8).hex(), "rsa-2048"))
    for _ in range(a.n):                     # odd moduli of any size
        bits = rng.randrange(2, 2049)
        n = rng.getrandbits(bits) | 1 | (1 << (bits - 1))
        if n < 3:
            continue
        b = rng.getrandbits(bits) % n
        e = rng.getrandbits(rng.randrange(0, 300))
        nl = (n.bit_length() + 7) // 8
        cases.append((f"modexp {rng.choice([1, 9, 100000])} {be(b).hex()} {be(e).hex() if e else ''} {be(n).hex()}",
                      be(pow(b, e, n), nl).hex(), "modexp-any"))
    for _ in range(max(10, a.n // 4)):
        p1, p2 = rand_prime(rng, 32), rand_prime(rng, rng.choice([31, 32]))
        if p1 == p2:
            continue
        lo, hi = sorted((p1, p2))
        cases.append((f"pq {p1 * p2:x}", f"{lo} {hi}", "pq"))

    # an empty exponent field would be eaten by the tokenizer: give it explicitly as 00
    lines = []
    for req, exp, label in cases:
        parts = req.split(" ")
        if parts[0] == "modexp" and parts[3] == "":
            parts[3] = "00"
        lines.append(" ".join(parts))
    r = subprocess.run([EXE], input="\n".join(lines) + "\n", capture_output=True, text=True)
    outs = r.stdout.splitlines()
    if len(outs) != len(cases):
        sys.exit(f"driver returned {len(outs)} lines for {len(cases)} requests\n{r.stderr}")

    fails, counts, steps = 0, {}, {}
    for (req, exp, label), out in zip(cases, outs):
        got = out.split(" ")
        if label.startswith("dh") or label.startswith("rsa") or label == "modexp-any":
            steps.setdefault(label, []).append(int(got[1]) if len(got) > 1 else -1)
            got = got[0]
            if exp is None:                  # g = 3: just check it equals pow
                parts = req.split(" ")
                exp = be(pow(3, int(parts[3], 16), p), 256).hex()
        elif label == "pq":
            got = " ".join(got[:2])
        else:
            got = out
        ok = got == exp
        counts[label] = counts.get(label, [0, 0])
        counts[label][0 if ok else 1] += 1
        if not ok:
            fails += 1
            if fails <= 5:
                print(f"FAIL {label}: {req[:120]}...\n  want {exp[:80]}\n  got  {got[:80]}")
    for label, (ok, bad) in counts.items():
        extra = ""
        if label in steps:
            s = steps[label]
            extra = f"  step calls {min(s)}..{max(s)}"
        print(f"{label:12s} ok {ok:4d}  fail {bad}{extra}")
    print("ALL OK" if not fails else f"{fails} FAILURES")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
