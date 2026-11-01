"""check_tlwalk.py - tg_tlwalk.c + the generated tables against a Python model written from
telegram_api.tl directly (gen_tl.parse): random objects of every result type the app reads, nested
up to ~8 levels, random flags (so random optional fields), boxed and bare vectors, root vectors.
The C walker's event stream must equal the model's, byte for byte. Also: truncation, unknown
constructors, skip().

    python tests/check_tlwalk.py [--n 400]
"""
import argparse
import os
import random
import re
import struct
import subprocess
import sys

import common

sys.path.insert(0, os.path.join(common.ROOT, "tools"))
import gen_tl                                        # noqa: E402

EXE = common.exe("walk_host")
TT = gen_tl.T
ROOT_TYPES = ["Config", "auth.SentCode", "auth.Authorization", "messages.Dialogs", "messages.Messages",
              "Updates", "updates.Difference", "updates.State", "User", "Message", "Chat", "help.AppConfig",
              "messages.StickerSet", "payments.PaymentForm", "messages.BotResults", "stories.AllStories"]


def build():
    common.build("walk_host", "walk_host.c", ["tg_tlwalk.c", "tg_schema.c", "tg_tl.c", "tg_sha.c"])

class Model:
    def __init__(self, cons):
        self.by_type = {}
        for name, cid, fields, result in cons:
            self.by_type.setdefault(result, []).append((name, cid, fields))
        # height of each type when every optional field is left out and every vector is empty
        h = {t: None for t in self.by_type}
        for _ in range(60):
            for t, cl in self.by_type.items():
                best = None
                for _, _, fields in cl:
                    need = [self.base(ft) for _, ft in fields if not re.match(r"^\w+\.\d+\?", ft)]
                    sub = [h.get(x) for x in need if x and x in self.by_type]
                    if any(s is None for s in sub) or any(x and x not in self.by_type and x not in TT for x in need):
                        continue
                    v = 1 + max(sub, default=0)
                    best = v if best is None else min(best, v)
                h[t] = best
        self.h = h

    @staticmethod
    def base(ft):
        """the object type a required field needs (None for scalars and vectors, which can be empty)"""
        if ft.startswith(("Vector<", "vector<")) or ft in TT or ft == "#":
            return None
        return ft

    def pick(self, typ, depth, rng):
        cl = self.by_type[typ]
        if depth < 6:
            return rng.choice(cl)
        # deep: a constructor whose required objects all bottom out
        ok = []
        for c in cl:
            need = [self.base(ft) for _, ft in c[2] if not re.match(r"^\w+\.\d+\?", ft)]
            if all(x is None or (self.h.get(x) is not None) for x in need):
                ok.append(c)
        return min(ok, key=lambda c: max([self.h[self.base(ft)] for _, ft in c[2]
                                          if not re.match(r"^\w+\.\d+\?", ft) and self.base(ft)] or [0]))

    def obj(self, typ, depth, rng, pcid, pfield, ev):
        name, cid, fields = self.pick(typ, depth, rng)
        ev.append(f"O {cid:08x} {pcid:08x} {pfield}")
        out = struct.pack("<I", cid)
        flags = {}
        for i, (fname, ftype) in enumerate(fields):
            m = re.match(r"^(\w+)\.(\d+)\?(.+)$", ftype)
            if m:
                if not flags.get(m.group(1), 0) >> int(m.group(2)) & 1:
                    continue
                ftype = m.group(3)
            if ftype == "#":
                v = rng.getrandbits(31) if depth < 5 else 0
                flags[fname] = v
                out += struct.pack("<I", v)
                ev.append(f"F {cid:08x} {i} {TT['#']} 0 {struct.pack('<I', v).hex()}")
                continue
            out += self.value(ftype, depth, rng, cid, i, 0, ev)
        ev.append(f"E {cid:08x}")
        return out

    def value(self, ftype, depth, rng, owner, field, in_vec, ev):
        pre = f"F {owner:08x} {field}"
        if ftype.startswith(("Vector<", "vector<")):
            inner = ftype[7:-1]
            n = rng.randrange(0, 4) if depth < 5 else 0
            ev.append(f"V {owner:08x} {field} {n}")
            out = (struct.pack("<I", 0x1cb5c415) if ftype[0] == "V" else b"") + struct.pack("<I", n)
            for _ in range(n):
                out += self.value(inner, depth + 1, rng, owner, field, 1, ev)
            ev.append(f"X {owner:08x} {field}")
            return out
        if ftype in ("int", "long", "double", "int128", "int256"):
            b = rng.randbytes({"int": 4, "int128": 16, "int256": 32}.get(ftype, 8))
            ev.append(f"{pre} {TT[ftype]} {in_vec} {b.hex()}")
            return b
        if ftype in ("string", "bytes"):
            b = rng.randbytes(rng.choice([0, 1, 3, 20, 253, 254, 300]))
            ev.append(f"{pre} {TT[ftype]} {in_vec} {b.hex()}")
            return gen_tl_bytes(b)
        if ftype == "Bool":
            v = rng.random() < 0.5
            ev.append(f"{pre} {TT['Bool']} {in_vec} v{int(v)}")
            return struct.pack("<I", 0x997275b5 if v else 0xbc799737)
        if ftype == "true":
            ev.append(f"{pre} {TT['true']} {in_vec} v1")
            return b""
        return self.obj(ftype, depth + 1, rng, owner, field, ev)


def gen_tl_bytes(b):
    h = bytes([len(b)]) if len(b) <= 253 else bytes([254]) + len(b).to_bytes(3, "little")
    return h + b + b"\0" * ((-(len(h) + len(b))) % 4)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=400)
    a = ap.parse_args()
    build()
    cons, _ = gen_tl.parse(os.environ.get("TL_SCHEMA", gen_tl.DEFAULT_TL))
    cons = [c for c in cons if c[0] != "true"]
    m = Model(cons)
    rng = random.Random(3)
    cases = []
    types = ROOT_TYPES + rng.sample(sorted(t for t in m.by_type if m.h.get(t)), 60)
    for i in range(a.n):
        typ = types[i % len(types)]
        ev = []
        if i % 17 == 0:                                   # root vector of objects (e.g. users.getUsers)
            n = rng.randrange(0, 4)
            ev.append(f"V 00000000 -1 {n}")
            blob = struct.pack("<II", 0x1cb5c415, n)
            for _ in range(n):
                blob += m.obj("User", 0, rng, 0, -1, ev)
            ev.append("X 00000000 -1")
        else:
            blob = m.obj(typ, 0, rng, 0, -1, ev)
        ev.append(f"END {len(blob)}")
        cases.append((typ, blob, ev))

    reqs, want = [], []
    for typ, blob, ev in cases:
        reqs.append("W " + blob.hex())
        want.append(("walk", ev))
        reqs.append("S " + blob.hex())
        want.append(("skip", [f"SKIP 0 {len(blob)}"]))
        if len(blob) > 8:
            cut = rng.randrange(4, len(blob))
            reqs.append("W " + blob[:cut].hex())
            want.append(("truncated", None))
    for _ in range(20):
        reqs.append("W " + struct.pack("<I", 0x12345678).hex() + "00" * 8)
        want.append(("unknown", ["ERR 2 12345678"]))

    r = subprocess.run([EXE], input="\n".join(reqs) + "\n", capture_output=True, text=True)
    lines, pos, fails, counts, events = r.stdout.splitlines(), 0, 0, {}, 0
    for (label, ev), req in zip(want, reqs):
        got = []
        while pos < len(lines):
            got.append(lines[pos])
            pos += 1
            if got[-1].startswith(("END", "ERR", "SKIP")):
                break
        if label == "truncated":
            good = len(got) > 0 and got[-1].split()[:2] in (["ERR", "1"], ["ERR", "4"])
        else:
            good = got == ev
            events += len(got)
        c = counts.setdefault(label, [0, 0])
        c[0 if good else 1] += 1
        if not good:
            fails += 1
            if fails <= 3:
                diff = next((i for i, (x, y) in enumerate(zip(got, ev or [])) if x != y), None)
                print(f"FAIL {label}: first difference at event {diff}: got {got[diff] if diff is not None else got[-3:]} want {ev[diff] if diff is not None and ev else ''}")
    for label, (ok, bad) in counts.items():
        print(f"{label:10s} ok {ok:4d}  fail {bad}")
    print(f"{events} events compared, {len(set(t for t, _, _ in cases))} root types")
    print("ALL OK" if not fails else f"{fails} FAILURES")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
