"""Collects the files that belong in the repository, and nothing else.

Uploading through a browser means dragging a folder in, and the folder has
to contain exactly what should be published. The working tree does not:
`web/node_modules` alone is tens of thousands of files, and a build
directory or a vendored package would be worse than noise, because
somebody would eventually mistake it for source.

So this copies the tracked files into a clean folder, following the same
exclusions as .gitignore. Drag the contents of that folder into GitHub and
the repository is correct on the first try.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Anything under these never ships.
SKIP_DIRS = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
    "target",
    "dist",
    "release",
    "vendor",
    ".venv",
    "venv",
}

SKIP_SUFFIXES = {".pyc", ".pyo", ".log", ".zip"}

# Generated: the build makes these, and a stale copy in the repository is
# worse than none.
SKIP_FILES = {
    "corpus.generated.js",
}

SKIP_PATHS = {
    Path("corpus"),
    Path("web/public/data"),
}


def wanted(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if any(part in SKIP_DIRS for part in relative.parts):
        return False
    if path.suffix in SKIP_SUFFIXES:
        return False
    if path.name in SKIP_FILES:
        return False
    for skip in SKIP_PATHS:
        if relative.is_relative_to(skip):
            return False
    # Certificates ship as test vectors under spec/, not as build output.
    if relative.parts[0] == "corpus":
        return False
    return True


def stage(out: Path) -> int:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    copied = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or not wanted(path):
            continue
        if out in path.parents:
            continue
        target = out / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        copied.append(path.relative_to(ROOT))

    size = sum(f.stat().st_size for f in out.rglob("*") if f.is_file())
    print(f"staged {len(copied)} file(s), {size / 1024:.0f} KB, into {out}\n")

    tops: dict[str, int] = {}
    for item in copied:
        key = item.parts[0] if len(item.parts) > 1 else "(root)"
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
