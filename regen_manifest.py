"""Regenerate the integrity manifest embedded in check_integrity.py.

The manifest is not a separate file: it is the REFERENCE dict inside
check_integrity.py. This script rebuilds that dict from the same git-tracked
set the checker uses and splices it back in, leaving every other line of
check_integrity.py — docstring, imports, EXCLUDE, tracked_paths, _hashes and
main — untouched.

It imports check_integrity and calls its tracked_paths and _hashes, so there
is one definition of the set and one definition of the hashing, and the two
tools cannot drift apart. For each file `raw` is the SHA-256 of the bytes on
disk and `norm` the SHA-256 after CRLF is normalised to LF: an LF file has
raw == norm and reads clean, a file pinned to CRLF on purpose (a .bat) keeps
raw != norm and still reads clean, so real line endings are recorded, not
hidden.

Nothing is written unless the rebuilt file is valid Python whose REFERENCE
equals what was just computed — a round trip, so a botched splice fails
loudly instead of leaving a broken checker behind.

Run from E:\\EK:  python regen_manifest.py
"""

import importlib.util
import pathlib
import sys

CHECKER = "check_integrity.py"


def load_checker(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("_ci_regen", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def render(ref: dict) -> str:
    out = ["REFERENCE = {\n"]
    for rel in sorted(ref):
        out.append(
            f'"{rel}": {{\n"norm": "{ref[rel]["norm"]}",\n"raw": "{ref[rel]["raw"]}"\n}},\n'
        )
    out.append("}\n")
    return "".join(out)


def splice(source: str, ref: dict) -> str:
    before, marker, rest = source.partition("REFERENCE = {")
    if not marker:
        raise SystemExit("check_integrity.py: no REFERENCE block found")
    tail_at = rest.find("def _hashes")
    if tail_at < 0:
        raise SystemExit("check_integrity.py: no _hashes function after REFERENCE")
    return before + render(ref) + "\n\n" + rest[tail_at:]


def main() -> int:
    root = pathlib.Path(".")
    if not (root / "verifier" / "src").is_dir():
        print("run this from the E:\\EK project root", file=sys.stderr)
        return 2
    checker = root / CHECKER
    if not checker.is_file():
        print(f"{CHECKER} not found in the project root", file=sys.stderr)
        return 2

    ci = load_checker(checker)
    old = set(ci.REFERENCE)

    ref = {}
    for rel in ci.tracked_paths(root):
        try:
            data = (root / rel).read_bytes()
        except FileNotFoundError:
            print(f"tracked but missing on disk: {rel}\nnothing written; "
                  f"resolve the working tree first", file=sys.stderr)
            return 3
        raw, norm = ci._hashes(data)
        ref[rel] = {"norm": norm, "raw": raw}

    rebuilt = splice(checker.read_text(encoding="utf-8"), ref)

    # Round trip: valid Python, and its REFERENCE is exactly what we built.
    ns = {"__name__": "_ci_regen_check"}
    exec(compile(rebuilt, CHECKER, "exec"), ns)
    if ns.get("REFERENCE") != ref:
        print("round-trip check failed; check_integrity.py left untouched", file=sys.stderr)
        return 3

    tmp = checker.with_suffix(".py.tmp")
    tmp.write_text(rebuilt, encoding="utf-8", newline="\n")
    tmp.replace(checker)

    added = sorted(set(ref) - old)
    removed = sorted(old - set(ref))
    print(f"manifest regenerated: {len(ref)} files tracked")
    if added:
        print(f"\nadded ({len(added)}):")
        for k in added:
            print(f"  {k}")
    if removed:
        print(f"\nremoved ({len(removed)}):")
        for k in removed:
            print(f"  {k}")
    if not added and not removed:
        print("no set change; hashes refreshed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
