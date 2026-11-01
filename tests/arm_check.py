"""arm_check.py - build the whole library for a freestanding 32-bit ARM target (Cortex-A7, Thumb-2,
-Os, -fropi, strict alignment) and check the rules src/ must keep: it links with no libc and no
compiler runtime (only arm_rt.c's memcpy/memset), and has no writable data. Prints the code size
per function and in total, and the sizeof of the main structs on the target.

    python tests/arm_check.py

Needs `python -m ziglang` (pip install ziglang) and pyelftools. The image goes to build/tmt_arm.elf.
"""
import os
import subprocess
import sys

from elftools.elf.elffile import ELFFile

import common

CFLAGS = ["-target", "thumb-freestanding-eabi", "-mcpu=cortex_a7", "-mthumb", "-Os",
          "-ffreestanding", "-fno-builtin", "-nostdlib", "-fno-stack-protector",
          "-mno-unaligned-access", "-ffunction-sections", "-fdata-sections", "-fno-unwind-tables",
          "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror",
          "-g",                     # zig strips the symbol table at -Os otherwise
          "-fropi",
          # zig cc ignores -mno-unaligned-access (it still emits str.w/ldr.w to odd addresses);
          # the LLVM feature is what really turns unaligned accesses off
          "-Xclang", "-target-feature", "-Xclang", "+strict-align",
          "-I", common.SRC]


def zig(*args):
    r = subprocess.run([sys.executable, "-m", "ziglang", *args], capture_output=True, text=True)
    if r.returncode:
        sys.exit("ARM build FAILED (undefined runtime symbol, writable data, or a warning):\n" + r.stdout + r.stderr)


def main():
    os.makedirs(common.BUILD, exist_ok=True)
    elf = os.path.join(common.BUILD, "tmt_arm.elf")
    zig("cc", *CFLAGS, "-T", os.path.join(common.HERE, "arm.ld"), "-Wl,--gc-sections", "-Wl,-e,tmt_entry",
        "-o", elf, os.path.join(common.HERE, "arm_entry.c"), os.path.join(common.HERE, "arm_rt.c"),
        *[os.path.join(common.SRC, s) for s in common.CORE])
    with open(elf, "rb") as f:
        e = ELFFile(f)
        secs = {s.name: s.header.sh_size for s in e.iter_sections() if s.header.sh_flags & 2}
        sizes, objs = {}, {}
        for s in e.get_section_by_name(".symtab").iter_symbols():
            if s["st_info"]["type"] == "STT_FUNC" and s.name.startswith("tg_"):
                sizes[s.name] = s["st_size"]
            elif s["st_info"]["type"] == "STT_OBJECT" and s["st_size"]:
                objs[s.name] = s["st_size"]
    assert secs.get(".data", 0) == 0, "writable data present"
    for k in sorted(sizes):
        print(f"  {k:28s} {sizes[k]:6d} B")
    tables = sum(v for k, v in objs.items() if k.startswith("TL_"))
    print(f"schema tables (TL_IDS/TL_OFF/TL_DESC): {tables} B")
    print(f"total image {secs.get('.text', 0)} B ({secs.get('.text', 0):#x}), no .data")

    obj = os.path.join(common.BUILD, "arm_sizes.o")
    zig("cc", *CFLAGS, "-c", "-o", obj, os.path.join(common.HERE, "arm_sizes.c"))
    with open(obj, "rb") as f:
        e = ELFFile(f)
        print("struct sizes on the target:")
        for s in e.get_section_by_name(".symtab").iter_symbols():
            if s.name.startswith("sz_"):
                print(f"  {s.name[3:]:16s} {s['st_size']:6d} B")
    print("OK")


if __name__ == "__main__":
    main()
