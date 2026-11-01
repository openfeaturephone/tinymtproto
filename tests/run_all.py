"""run_all.py - run every offline test (no network, no account) and the ARM build check.

    python tests/run_all.py [--no-arm]

Exit code 0 only if all of them pass.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = ["check.py", "check_mtp.py", "check_auth.py", "check_session.py", "check_inflate.py", "check_tlwalk.py"]


def main():
    tests = TESTS + ([] if "--no-arm" in sys.argv else ["arm_check.py"])
    failed = []
    for t in tests:
        print(f"==== {t}", flush=True)
        r = subprocess.run([sys.executable, os.path.join(HERE, t)], cwd=HERE)
        if r.returncode:
            failed.append(t)
    print("ALL PASSED" if not failed else "FAILED: " + " ".join(failed))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
