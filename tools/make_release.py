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
import hashlib
import os
import subprocess
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bundle import canonical
from tools import wasm_stamp  # noqa: E402

READ_ME = """\
Curve certificates
==================

Every claim about a curve in here arrives with the evidence for it, and a
separate program re-checks that evidence without redoing the work that
produced it. Producing the evidence took minutes. Checking it takes under a
second, and you do not have to trust us for any of it.

Eight curves are covered. Four are prime-field: secp256k1 and NIST P-256,
and the Edwards pair Curve25519 and Ed25519. Four are pairing-friendly:
BLS12-381 and BN254, underneath Ethereum's signatures and precompiles,
and BLS24-315 and BLS24-509. The pairing curves carry claims about a
second group living over an extension field — degree two for BLS12 and
BN, degree four for the BLS24 pair — which is where most of the evidence
in those files goes, and its order is settled without factoring a
thousand-bit cofactor.

What is in this folder
----------------------

  curve-certificates.html   The dossiers. Open it in a browser; it needs
                            no server and no internet.
  certificates\\             The certificate files themselves.
  ccert-verify.exe          The verifier. Run it on a certificate.
  check-all.bat             Runs the verifier over every certificate here.
  DIGESTS.txt               A SHA-256 for every file here.
  DIGESTS.txt.minisig       Its minisign signature (see below).

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

The sharpest case in this folder is BN254, the curve behind Ethereum's
pairing precompiles. Nothing about it has changed since it was
standardised: the order in its certificate is the same number it always
was, and every claim there holds today. What changed was an estimate.
Work on the tower number field sieve after 2016 applies to exactly the
kind of field a pairing lands in, and the security this curve offers was
revised downward without a single digit of the curve moving.

You can see it in the page. Judge bn254.ccert by pairing-security-pre-tnfs
and it passes; judge the same file by pairing-security-tnfs-2016 and it
fails, on one criterion, with the same number on the left of the
comparison and a different threshold on the right. Each threshold names
the model it came from. That separation is the whole reason this format
keeps facts and verdicts in different files: a fact that needed reissuing
every time an estimate moved would not be worth writing down.

BLS12-381 is here beside it, and passes both. Which is why it replaced
BN254 for new work.

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



def sign_digests(digests: Path) -> bool:
    """Sign DIGESTS.txt with minisign, if a secret key is configured.

    The whole release hashes down to this one file, so one signature over
    it authenticates the lot: a reader verifies the signature, then checks
    each file against a line it now trusts. The key is never in the tree —
    its path comes from MINISIGN_KEY — and without it the release still
    assembles, just unsigned, because building and signing are different
    acts by different people at different times.

    minisign prompts for the key's password on the terminal; its output is
    left visible so the prompt is not swallowed.
    """
    key = os.environ.get("MINISIGN_KEY")
    if not key:
        print("DIGESTS.txt not signed (set MINISIGN_KEY to a minisign secret "
              "key to sign the release)")
        return False
    if not Path(key).is_file():
        print(f"MINISIGN_KEY points at {key}, which is not a file; not signed",
              file=sys.stderr)
        return False
    result = subprocess.run(
        ["minisign", "-S", "-s", key, "-m", str(digests)],
    )
    if result.returncode != 0:
        print("minisign failed; DIGESTS.txt not signed", file=sys.stderr)
        return False
    print(f"signed {digests.name} -> {digests.name}.minisig")
    return True


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

    # The page and the binary must be the same program.
    #
    # A release ships both, and the page's whole claim is that it
    # re-checks rather than displays. Nothing enforced that they agreed,
    # and a release went out whose browser module predated the
    # certificates beside it: two valid BLS24 certificates were refused in
    # the page and accepted by the binary. Refusing to assemble is the
    # right answer — a reader cannot be expected to suspect the page.
    state, sentence = wasm_stamp.status()
    if state in ("stale", "unstamped"):
        print(f"refusing to assemble: {sentence}", file=sys.stderr)
        return 2
    print(f"browser verifier: {state} — {sentence}")

    # And the same question again, about the artefact actually shipped.
    #
    # The check above compares the browser module in `web/src` against the
    # verifier's sources. The release is assembled from `web/dist`, which
    # is built from that module by a step nobody is obliged to re-run —
    # so rebuilding the wasm and assembling without rebuilding the page
    # produces a fresh stamp on a page carrying the previous verifier.
    # That is the original failure wearing the check meant to catch it.
    page_state, page_sentence = wasm_stamp.page_status(page)
    if page_state == "stale":
        print(f"refusing to assemble: {page_sentence}", file=sys.stderr)
        return 2
    print(f"shipped page: {page_state} — {page_sentence}")

    # The binary must be the deterministic one.
    #
    # The release ships whatever build_verifier.bat last produced, and only
    # a build through that script — which sets the flags that pin code
    # generation and zero the linker timestamp — is byte-for-byte
    # reproducible (docs/DESIGN.md, "The verifier binary"). A plain
    # `cargo build` would ship a binary that hashes differently on every
    # rebuild, so DIGESTS would pin bytes nobody else could reproduce.
    #
    # The check is opt-in, because the expected hash holds only for a build
    # at this tree's path: set CCERT_EXPECT_HASH to that hash to have the
    # release refuse a binary that does not match, and leave it unset to
    # simply record whichever hash was built. The hash is printed either
    # way, so a release master always sees what shipped.
    binary_hash = hashlib.sha256(verifier.read_bytes()).hexdigest()
    print(f"verifier sha256: {binary_hash}")
    expected = os.environ.get("CCERT_EXPECT_HASH")
    if expected and binary_hash != expected.strip().lower():
        print(
            f"refusing to assemble: the verifier hashes to {binary_hash}, not the\n"
            f"  expected {expected.strip().lower()}. Build it with "
            f"tools\\build_verifier.bat, which sets the deterministic flags.",
            file=sys.stderr,
        )
        return 2

    if out.exists():
        shutil.rmtree(out)
    (out / "certificates").mkdir(parents=True)

    shutil.copyfile(page, out / "curve-certificates.html")
    # copy2 rather than copyfile, and it matters: copyfile drops the
    # permission bits, so the shipped binary arrives without its execute
    # bit. On Windows nothing notices, because there an .exe runs on its
    # extension. On Linux and macOS the release simply refuses to start,
    # and the person who downloaded it has no reason to suspect a missing
    # chmod rather than a broken program.
    shutil.copy2(verifier, out / verifier.name)
    (out / verifier.name).chmod(0o755)
    (out / "check-all.bat").write_text(CHECK_ALL, encoding="utf-8", newline="\r\n")

    # The digest manifest covers the whole release, not only the
    # certificates. The two artefacts a reader actually runs — the page
    # and the binary — are the ones most worth pinning: a tampered
    # verifier could pass a forged certificate, and a reader who can hash
    # the .exe against this line would catch a swapped one. Their bytes
    # are hashed as they ship, whole, since neither is a canonical bundle
    # with a trailing newline to trim.
    lines = ["digest                                                                    file"]
    for name in ("curve-certificates.html", verifier.name):
        digest = canonical.digest_bytes((out / name).read_bytes())
        lines.append(f"{digest}  {name}")
    for path in certificates:
        raw = path.read_bytes()
        shutil.copyfile(path, out / "certificates" / path.name)
        digest = canonical.digest_bytes(raw.rstrip(b"\n"))
        lines.append(f"{digest}  certificates/{path.name}")
    (out / "DIGESTS.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8", newline="\r\n"
    )
    signed = sign_digests(out / "DIGESTS.txt")
    readme = READ_ME + ("""
Verifying this download
-----------------------

The whole release is pinned by DIGESTS.txt: one line per file, each the
SHA-256 of the bytes shipped. DIGESTS.txt itself is signed with minisign,
so a tampered file — a swapped verifier, an edited certificate — cannot be
hidden without breaking the signature.

Check the signature, then the files, on Windows, macOS or Linux:

    minisign -Vm DIGESTS.txt -P RWQ/j9uY50lkb6j4e0tLmPusJmmiNCY/dhWUBBu05uWgC6CBUTl0gho+

A valid signature means DIGESTS.txt is the one that was released. Then
compare any file against its line in it; on Linux or macOS:

    sha256sum -c <(sed 's/^sha256://' DIGESTS.txt | tail -n +2)

The public key above is this release's; it is also in the project's
README on GitHub, so the two can be compared before it is trusted.
""" if signed else "")
    (out / "README.txt").write_text(readme, encoding="utf-8", newline="\r\n")


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
