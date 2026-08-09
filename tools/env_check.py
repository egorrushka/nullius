"""Checks that the toolchain this project expects is actually present."""

import shutil
import subprocess
import sys


def check(name, ok, detail=""):
    mark = "ok  " if ok else "MISS"
    print(f"[{mark}] {name}" + (f"  {detail}" if detail else ""))
    return ok


def probe(exe, args):
    path = shutil.which(exe)
    if not path:
        return False, "not on PATH"
    try:
        out = subprocess.run(
            [path, *args], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    text = (out.stdout or out.stderr).strip().splitlines()
    return True, text[0] if text else path


def main():
    results = []

    v = sys.version_info
    results.append(
        check("python >= 3.10", v >= (3, 10), f"{v.major}.{v.minor}.{v.micro}")
    )

    for name, exe, args, required in [
        ("PARI/GP (gp)", "gp", ["--version"], True),
        ("cargo (rustup)", "cargo", ["--version"], True),
        ("node", "node", ["--version"], False),
    ]:
        found, detail = probe(exe, args)
        ok = check(name, found, detail)
        if required:
            results.append(ok)

    print()
    if all(results):
        print("Toolchain looks complete.")
        return 0
    print("Something required is missing; see the marks above.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
