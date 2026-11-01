"""live_client.py - the whole client (tg_client.c on the tg_* stack) against Telegram's TEST DC 2.

    python tests/live_client.py [--phone 999662XXXX] [--fresh]       (Windows only, see cl_host.c)

Test accounts need no SIM: 99966XYYYY with X = DC id, login code = X five times
(core.telegram.org/api/auth, "Test accounts"). Steps:
  A: login (sendCode, signIn, signUp if the number is new) -> getDialogs -> send to Saved Messages
     -> getHistory of Saved Messages shows it
  B: a second session of the same account logs in and sends to Saved Messages
  A: receives it as a pushed update (NEW_MESSAGE), then getDifference
api_id/api_hash come from $TG_API_ID / $TG_API_HASH or the keyring (sess_lib.credential); the
sessions are saved DPAPI-encrypted under %LOCALAPPDATA%\\tinymtproto\\.
"""
import argparse
import os
import queue
import random
import subprocess
import sys
import threading
import time

import common
import sess_lib as L

EXE = common.exe("cl_host")
STATE_DIR = os.path.join(os.environ.get("LOCALAPPDATA", "."), "tinymtproto")


def build():
    if os.name != "nt":
        sys.exit("cl_host.c uses Winsock and DPAPI: Windows only for now")
    common.build("cl_host", "cl_host.c", common.CORE, libs=["-lws2_32", "-lcrypt32", "-lbcrypt"])


class Client:
    def __init__(self, name, state):
        self.name = name
        self.p = subprocess.Popen([EXE, "--test", "--state", state], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  text=True, encoding="utf-8", errors="replace", bufsize=1)
        self.q = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self.p.stdin.write(f"API {L.credential('api_id')} {L.credential('api_hash')}\n")
        self.p.stdin.flush()

    def _read(self):
        for line in self.p.stdout:
            self.q.put(line.rstrip("\n"))
        self.q.put(None)

    def cmd(self, line):
        print(f"  {self.name} > {line}")
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def wait(self, *names, timeout=60):
        """-> (event line, rows) for the first EV line whose name is in names; EV ERROR fails"""
        end = time.time() + timeout
        rows, ev = [], None
        while time.time() < end:
            try:
                line = self.q.get(timeout=max(0.1, end - time.time()))
            except queue.Empty:
                break
            if line is None:
                sys.exit(f"{self.name}: cl_host exited")
            if not line.startswith("EV ") or line.split()[1] not in ("PERSIST",):
                print(f"  {self.name} < {line}")
            if line.startswith(("DLG ", "MSG ", "NEW ")):
                rows.append(line)
                continue
            if line == "END":
                return ev, rows
            parts = line.split()
            if parts[0] == "EV" and parts[1] in names:
                ev = line
                if parts[1] in ("DIALOGS", "HISTORY"):
                    continue                          # rows follow until END
                return line, rows
            if parts[0] == "EV" and parts[1] == "ERROR" and "ERROR" not in names:
                sys.exit(f"{self.name}: {line}")
        sys.exit(f"{self.name}: timeout waiting for {names}")

    def login(self, phone):
        ready, _ = self.wait("READY")
        if " logged_in 1" in ready:
            return
        self.cmd(f"PHONE {phone}")
        ev, _ = self.wait("CODE_SENT", timeout=120)
        n = int(ev.split("length ")[1].split()[0]) if "length " in ev else 5
        # test DCs: the DC digit repeated; core.telegram.org says 5 times, Telethon notes it has been 6
        for k in sorted({n or 5, 5, 6}):
            self.cmd("CODE " + phone[5] * k)
            ev, _ = self.wait("LOGGED_IN", "SIGNUP_REQUIRED", "ERROR", timeout=120)
            if "PHONE_CODE_INVALID" not in ev:
                break
        if "ERROR" in ev:
            sys.exit(f"{self.name}: {ev}")
        if "SIGNUP_REQUIRED" in ev:
            self.cmd("SIGNUP Test User")
            self.wait("LOGGED_IN", timeout=120)

    def quit(self):
        self.cmd("QUIT")
        self.p.wait(timeout=10)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phone", help="test number 999662XXXX (default: remembered, or a new random one)")
    ap.add_argument("--fresh", action="store_true", help="forget the saved test sessions first")
    a = ap.parse_args()
    build()
    os.makedirs(STATE_DIR, exist_ok=True)
    sa, sb = os.path.join(STATE_DIR, "live_test_a.bin"), os.path.join(STATE_DIR, "live_test_b.bin")
    phone_file = os.path.join(STATE_DIR, "live_test_phone.txt")
    if a.fresh:
        for f in (sa, sb, phone_file):
            if os.path.exists(f):
                os.remove(f)
    phone = a.phone or (open(phone_file).read().strip() if os.path.exists(phone_file) else f"999662{random.randrange(10000):04d}")
    open(phone_file, "w").write(phone)
    print(f"test account {phone} on test DC 2")

    A = Client("A", sa)
    A.login(phone)
    A.cmd("DIALOGS")
    _, rows = A.wait("DIALOGS")
    print(f"  A: {len(rows)} chats")
    text = f"hello from tg_client {time.strftime('%H:%M:%S')} é中"
    A.cmd(f"SEND -1 {text}")
    A.wait("SENT")
    A.cmd("HISTORY -1")
    _, rows = A.wait("HISTORY")
    assert any(r.endswith("|" + text) for r in rows), "sent message not in Saved Messages history"
    print("  A: history of Saved Messages has the message")

    B = Client("B", sb)
    B.login(phone)
    text2 = f"pushed from session B {time.strftime('%H:%M:%S')}"
    B.cmd(f"SEND -1 {text2}")
    B.wait("SENT")
    _, rows = A.wait("NEW_MESSAGE", timeout=30)
    print("  A: received B's message as a pushed update")
    B.quit()
    A.cmd("DIFF")
    A.wait("DIFF_DONE")
    A.quit()
    print("ALL OK")


if __name__ == "__main__":
    main()
