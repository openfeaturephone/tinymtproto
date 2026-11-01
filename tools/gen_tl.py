"""gen_tl.py - generate src/tg_schema.c / src/tg_schema.h from telegram_api.tl for the TL walker (tg_tlwalk.c).

    python tools/gen_tl.py [--tl schema/telegram_api.tl] [--out src]

The default .tl is the copy in schema/ (from TDLib, see THIRD_PARTY.md). To move to a newer layer,
point --tl at td/generate/scheme/telegram_api.tl of a TDLib checkout and update LAYER.

Every constructor of the type section goes into the walker tables, so any server object can be walked
or skipped. Named ids, field indices and flag bits are emitted only for the constructors and functions
in USED, the ones the client reads or builds. Layer: LAYER below must match the .tl file (TDLib commit
4c6377a, td/telegram/Version.h MTPROTO_LAYER).

Tables (all plain numbers, -fropi safe):
  TL_IDS[n]   sorted constructor ids
  TL_OFF[n]   offset of each constructor's descriptor in TL_DESC
  TL_DESC[]   per constructor: field count, then one descriptor per field:
              byte = type (low 4 bits) | 0x80 conditional | 0x40 condition on flags2 | 0x20 this '#' is flags2
              conditional: + bit number byte;  T_VECTOR / T_BVECTOR: + element descriptor
"""
import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_TL = os.path.join(ROOT, "schema", "telegram_api.tl")
LAYER = 232

T = {"int": 0, "long": 1, "double": 2, "string": 3, "bytes": 4, "Bool": 5, "true": 6, "#": 7,
     "OBJ": 8, "VECTOR": 9, "BVECTOR": 10, "int128": 11, "int256": 12}

# constructors / functions the app reads or builds: these get TL_x ids, TLF_x_field indices, TLB_x_field bits
USED = """
config dcOption
auth.sentCode auth.sentCodeSuccess auth.sentCodeTypeApp auth.sentCodeTypeSms auth.sentCodeTypeCall
auth.authorization auth.authorizationSignUpRequired codeSettings
user userEmpty chat chatEmpty chatForbidden channel channelForbidden
peerUser peerChat peerChannel
inputPeerEmpty inputPeerSelf inputPeerUser inputPeerChat inputPeerChannel inputUserSelf
messages.dialogs messages.dialogsSlice messages.dialogsNotModified dialog dialogFolder
message messageService messageEmpty messageMediaEmpty
messages.messages messages.messagesSlice messages.channelMessages messages.messagesNotModified
updates updatesCombined updateShort updateShortMessage updateShortChatMessage updateShortSentMessage
updatesTooLong updateNewMessage updateNewChannelMessage updateMessageID updateReadHistoryInbox
updates.state updates.difference updates.differenceEmpty updates.differenceSlice updates.differenceTooLong
initConnection invokeWithLayer help.getConfig help.getNearestDc nearestDc
auth.sendCode auth.signIn auth.signUp auth.logOut
messages.getDialogs messages.getHistory messages.sendMessage messages.readHistory
updates.getState updates.getDifference users.getUsers
""".split()


def parse(path):
    sec, cons, funcs = "types", [], []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line.startswith("---"):
            sec = line.strip("-")
            continue
        m = re.match(r"^([a-zA-Z0-9_.]+)#([0-9a-f]+)(.*)=\s*([^;]+);", line)
        if not m or line.startswith("//"):
            continue
        name, cid, body, result = m.group(1), int(m.group(2), 16), m.group(3), m.group(4).strip()
        if name in ("vector", "boolTrue", "boolFalse", "true") and sec == "types":
            if name != "true":
                continue
        fields = []
        for f in body.split():
            if f.startswith("{"):
                continue                                         # {X:Type}: functions only
            fname, ftype = f.split(":", 1)
            fields.append((fname, ftype))
        (cons if sec == "types" else funcs).append((name, cid, fields, result))
    return cons, funcs


def descriptor(ftype, flag_names):
    """-> (bytes, cond_word or None, bit or None)"""
    cond, bit, word = 0, None, None
    m = re.match(r"^(\w+)\.(\d+)\?(.+)$", ftype)
    if m:
        word, bit, ftype = m.group(1), int(m.group(2)), m.group(3)
        assert word in flag_names, ftype
        cond = 0x80 | (0x40 if flag_names.index(word) == 1 else 0)
    if ftype.startswith("!"):
        raise ValueError("generic !X in a constructor")
    if ftype.startswith("Vector<") or ftype.startswith("vector<"):
        inner = ftype[7:-1]
        el, _, _ = descriptor(inner, flag_names)
        code = T["VECTOR"] if ftype[0] == "V" else T["BVECTOR"]
        out = bytes([code | cond]) + (bytes([bit]) if cond else b"") + el
        return out, word, bit
    if ftype in T and ftype not in ("OBJ", "VECTOR", "BVECTOR"):
        code = T[ftype]
    elif ftype[0].isupper() or "." in ftype:
        code = T["OBJ"]
    else:
        raise ValueError(f"unknown type {ftype}")
    out = bytes([code | cond]) + (bytes([bit]) if cond else b"")
    return out, word, bit


def cname(name):
    return name.replace(".", "_")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tl", default=DEFAULT_TL, help="telegram_api.tl (default: schema/telegram_api.tl)")
    ap.add_argument("--out", default=os.path.join(ROOT, "src"), help="where tg_schema.c/.h go (default: src)")
    a = ap.parse_args()
    cons, funcs = parse(a.tl)
    by_name = {c[0]: c for c in cons + funcs}
    missing = [u for u in USED if u not in by_name]
    if missing:
        sys.exit(f"USED names not in the schema: {missing}")

    ids, desc, offs = [], bytearray(), {}
    for name, cid, fields, _ in sorted(cons, key=lambda c: c[1]):
        flag_names = [f for f, t in fields if t == "#"]
        assert len(flag_names) <= 2, name
        if cid in offs:
            continue
        offs[cid] = len(desc)
        ids.append(cid)
        assert len(fields) < 256
        desc.append(len(fields))
        for fname, ftype in fields:
            d, _, _ = descriptor(ftype, flag_names)
            if ftype == "#" and flag_names.index(fname) == 1:
                d = bytes([d[0] | 0x20])
            desc += d
    assert len(desc) < 65536, len(desc)

    h = [f"/* tg_schema.h - generated by gen_tl.py from telegram_api.tl (layer {LAYER}). Do not edit. */",
         "#ifndef TG_SCHEMA_H", "#define TG_SCHEMA_H", "#include <stdint.h>", "",
         f"#define TL_LAYER {LAYER}", f"#define TL_N_CONS {len(ids)}", "",
         "extern const uint32_t TL_IDS[TL_N_CONS];", "extern const uint16_t TL_OFF[TL_N_CONS];",
         f"extern const uint8_t TL_DESC[{len(desc)}];", "",
         "#define TL_vector 0x1cb5c415u", "#define TL_boolTrue 0x997275b5u", "#define TL_boolFalse 0xbc799737u", ""]
    for u in USED:
        name, cid, fields, result = by_name[u]
        kind = "function" if (name, cid, fields, result) in funcs else "constructor"
        h.append(f"/* {kind} {name} -> {result} */")
        h.append(f"#define TL_{cname(name)} 0x{cid:08x}u")
        flag_names = [f for f, t in fields if t == "#"]
        for i, (fname, ftype) in enumerate(fields):
            h.append(f"#define TLF_{cname(name)}_{fname} {i}")
            m = re.match(r"^(\w+)\.(\d+)\?", ftype)
            if m:
                h.append(f"#define TLB_{cname(name)}_{fname} {m.group(2)}  /* in {m.group(1)} */")
        h.append("")
    h.append("#endif")

    def rows(vals, fmt, per):
        return ",\n".join("    " + ", ".join(fmt(v) for v in vals[i:i + per]) for i in range(0, len(vals), per))
    c = [f"/* tg_schema.c - generated by gen_tl.py from telegram_api.tl (layer {LAYER}). Do not edit. */",
         '#include "tg_schema.h"', "",
         "const uint32_t TL_IDS[TL_N_CONS] = {", rows(ids, lambda v: f"0x{v:08x}u", 8), "};", "",
         "const uint16_t TL_OFF[TL_N_CONS] = {", rows([offs[i] for i in ids], str, 16), "};", "",
         f"const uint8_t TL_DESC[{len(desc)}] = {{", rows(list(desc), str, 24), "};", ""]
    open(os.path.join(a.out, "tg_schema.h"), "w", newline="\n").write("\n".join(h) + "\n")
    open(os.path.join(a.out, "tg_schema.c"), "w", newline="\n").write("\n".join(c))
    print(f"{len(ids)} constructors, descriptors {len(desc)} B, tables {4 * len(ids) + 2 * len(ids) + len(desc)} B; "
          f"{len(USED)} named")


if __name__ == "__main__":
    main()
