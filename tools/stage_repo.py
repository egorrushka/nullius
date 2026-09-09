"""Collects exactly the files that belong in the repository, and nothing else.

Uploading through a browser means dragging a folder in, and that folder has
to contain exactly what should be published — no more, no less. The working
tree is not that folder: `web/node_modules` alone is tens of thousands of
files, a build directory or a vendored package would be worse than noise,
and a context note meant to be deleted before publication must never ship.

The source of truth is git. `git ls-files` is the set of tracked files, and
tracked is the definition of published: it already honours `.gitignore`, so
anything ignored — vendored packages, build output, the handoff docs under
`docs/`, a stray probe artefact — is absent by construction rather than by a
hand-maintained skip list that drifts. An earlier version of this script
walked the tree with its own exclusions and drifted both ways at once: it
would have shipped the context docs that `.gitignore` hides, and dropped
`web/src/wasm`, which git tracks and a clone needs to build the page. Asking
git removes the whole class of mismatch.

    python tools\\stage_repo.py

Drag the contents of release\\repo into GitHub and the repository is correct
on the first try.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def tracked_files() -> list[str]:
    """The repository's tracked files, in posix form, from git itself."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=str(ROOT), capture_output=True, check=True,
        ).stdout
    except FileNotFoundError:
        raise SystemExit("git is not on PATH; staging needs it to know what "
                         "is tracked")
    except subprocess.CalledProcessError:
        raise SystemExit("`git ls-files` failed; run this inside the E:\\EK "
                         "git working tree")
    return [chunk.decode("utf-8") for chunk in out.split(b"\x00") if chunk]


def stage(out: Path) -> int:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    copied: list[str] = []
    missing: list[str] = []
    for rel in tracked_files():
        source = ROOT / rel
        if not source.is_file():
            # Tracked but absent from the working tree — a deletion not yet
            # staged. Report it rather than shipping a repository that does
            # not match what git believes is there.
            missing.append(rel)
            continue
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied.append(rel)

    if missing:
        print("refusing to stage: these files are tracked but missing from the "
              "working tree,\nso the staged repository would not match git:",
              file=sys.stderr)
        for rel in missing:
            print(f"  {rel}", file=sys.stderr)
        shutil.rmtree(out)
        return 1

    size = sum(f.stat().st_size for f in out.rglob("*") if f.is_file())
    print(f"staged {len(copied)} file(s), {size / 1024:.0f} KB, into {out}\n")

    tops: dict[str, int] = {}
    for rel in copied:
        parts = rel.split("/")
        key = parts[0] if len(parts) > 1 else "(root)"
        tops[key] = tops.get(key, 0) + 1
    for key in sorted(tops):
        print(f"  {key:<24}{tops[key]} file(s)")

    if len(copied) > 100:
        print(
            "\nMore than 100 files. A browser upload commits at most 100 at a\n"
            "time, so drag the top-level folders in two or three goes."
        )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage the repository contents.")
    parser.add_argument("--out", default=str(ROOT / "release" / "repo"))
    args = parser.parse_args()
    return stage(Path(args.out))


if __name__ == "__main__":
    raise SystemExit(main())
