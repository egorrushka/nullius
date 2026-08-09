"""Assembles the viewer release.

Two audiences, two artefacts. Almost everyone who opens this project wants
to read a certificate and check it; only a few want to make one. Making one
needs PARI, its data package and a Python runtime, which is a hundred and
fifty megabytes. Reading one needs a page and a small binary.

So this builds the small artefact: a single HTML file with the corpus
inlined, the certificates themselves, and the verifier. No installer, no
server, no runtime. Double-click the page and it opens; drop a certificate
on the verifier and it answers.

The certificates are copied verbatim. The page shows the digest of each
file, and that has to be the digest of the file sitting next to it.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bundle import canonical  # noqa: E402

READ_ME = """\
Curve certificates
==================

Every claim about a curve in here arrives with the evidence for it, and a
separate program re-checks that evidence without redoing the work that
produced it. Producing the evidence took minutes. Checking it takes under a
second, and you do not have to trust us for any of it.

What is in this folder
----------------------

  curve-certificates.html   The dossiers. Open it in a browser; it needs
                            no server and no internet.
  certificates\\             The certificate files themselves.
  ccert-verify.exe          The verifier. Run it on a certificate.
  check-all.bat             Runs the verifier over every certificate here.

Checking a certificate yourself
-------------------------------

    ccert-verify.exe certificates\\secp256k1.ccert

It prints one line per claim and exits 0 only if the document is sound and
every claim's evidence holds. Try editing a digit in a certificate with a
text editor and running it again: it will refuse, and say where.

Reading the results
-------------------

  proved      The evidence establishes the claim outright.
  derived     Follows from other claims here, and only if those hold.
  not proved  A program reported it. That is all it means.

A certificate says what is true, not whether the curve is a good choice.
That second question belongs to a policy, and different policies disagree:
secp256k1 fails the SafeCurves discriminant criterion for exactly the
property that makes it pass the GLV one. Switch policies in the page and
watch the same numbers get judged both ways.

Where this comes from
---------------------

The evidence is produced with PARI/GP and assembled in Python. The verifier
is written in Rust, deliberately in a different language, so that a bug in
one is unlikely to be a matching bug in the other. Both read the same
format, which is specified in full and rejects anything ambiguous.
"""

CHECK_ALL = """\
@echo off
rem Runs the verifier over every certificate in this folder.
setlocal
pushd "%~dp0"
set FAILED=0

for %%F in (certificates\\*.ccert) do (
    echo === %%~nxF ===
    ccert-verify.exe "%%F"
    if errorlevel 1 set FAILED=1
    echo.
)

if "%FAILED%"=="1" (
    echo One or more certificates did not verify.
) else (
    echo All certificates verified.
)

popd
endlocal
pause
"""


def find_verifier() -> Path | None:
    for name in ("ccert-verify.exe", "ccert-verify"):
        candidate = ROOT / "verifier" / "target" / "release" / name
        if candidate.is_file():
            return candidate
    return None


def build(out: Path, corpus: Path, page: Path) -> int:
    if not page.is_file():
        print(f"no page at {page}; run tools\\web_build.bat first", file=sys.stderr)
        return 2
    certificates = sorted(corpus.glob("*.ccert"))
    if not certificates:
        print(f"no certificates in {corpus}; run tools\\corpus.bat first", file=sys.stderr)
        return 2
    verifier = find_verifier()
    if verifier is None:
        print("no verifier built; run tools\\build_verifier.bat first", file=sys.stderr)
        return 2

    if out.exists():
        shutil.rmtree(out)
    (out / "certificates").mkdir(parents=True)

    shutil.copyfile(page, out / "curve-certificates.html")
    shutil.copyfile(verifier, out / verifier.name)
    (out / "README.txt").write_text(READ_ME, encoding="utf-8", newline="\r\n")
    (out / "check-all.bat").write_text(CHECK_ALL, encoding="utf-8", newline="\r\n")

    lines = ["digest                                                                    file"]
    for path in certificates:
        raw = path.read_bytes()
        shutil.copyfile(path, out / "certificates" / path.name)
        digest = canonical.digest_bytes(raw.rstrip(b"\n"))
        lines.append(f"{digest}  {path.name}")
    (out / "DIGESTS.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8", newline="\r\n"
    )

    archive = out.with_suffix(".zip")
    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for item in sorted(out.rglob("*")):
            if item.is_file():
                bundle.write(item, item.relative_to(out.parent))

    size = sum(f.stat().st_size for f in out.rglob("*") if f.is_file())
    print(f"assembled {out}")
    print(f"  {len(certificates)} certificate(s), {size / 1024:.0f} KB unpacked")
    print(f"  archive: {archive} ({archive.stat().st_size / 1024:.0f} KB)")
    print("\nOpen curve-certificates.html to read it, or run check-all.bat.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Assemble the viewer release.")
    parser.add_argument("--out", default=str(ROOT / "release" / "ccert-viewer"))
    parser.add_argument("--corpus", default=str(ROOT / "corpus"))
    parser.add_argument("--page", default=str(ROOT / "web" / "dist" / "index.html"))
    args = parser.parse_args()
    return build(Path(args.out), Path(args.corpus), Path(args.page))


if __name__ == "__main__":
    raise SystemExit(main())
