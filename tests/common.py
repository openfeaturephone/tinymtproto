"""common.py - paths and the host C build shared by the tests.

The host compiler is $CC if set (e.g. CC=gcc or CC="clang"), else `python -m ziglang cc`
(pip install ziglang). Test binaries go to build/ at the repository root.
"""
import os
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
BUILD = os.path.join(ROOT, "build")
EXE = ".exe" if os.name == "nt" else ""

# every library source, in link order
CORE = ["tg_sha.c", "tg_aes.c", "tg_bn.c", "tg_pq.c", "tg_tl.c", "tg_mtp.c", "tg_auth.c", "tg_net.c",
        "tg_session.c", "tg_inflate.c", "tg_tlwalk.c", "tg_schema.c", "tg_client.c"]


def cc():
    v = os.environ.get("CC")
    return shlex.split(v) if v else [sys.executable, "-m", "ziglang", "cc"]


def exe(name):
    return os.path.join(BUILD, name + EXE)


def build(name, harness, srcs, extra=(), libs=()):
    """Compiles tests/<harness> + src/<srcs> into build/<name>; exits on any warning or error."""
    os.makedirs(BUILD, exist_ok=True)
    out = exe(name)
    cmd = cc() + ["-O2", "-Wall", "-Wextra", "-Werror", "-I", SRC, *extra, "-o", out,
                  os.path.join(HERE, harness)] + [os.path.join(SRC, s) for s in srcs] + list(libs)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        sys.exit("build failed:\n" + " ".join(cmd) + "\n" + r.stdout + r.stderr)
    return out
