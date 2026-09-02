"""Time the one number that is the point: how long a certificate takes to
verify.

Producing a certificate is minutes of point counting, factoring and
primality proving. Checking one is far cheaper, and this measures that
half — the verifier, run the way anyone runs it, on the bytes of a
finished `.ccert`, process start included, because that is the cost a
reader actually pays. How cheap depends on the curve: a prime-field
certificate verifies in a fraction of a second, a pairing-friendly one
over an extension field takes longer — order of seconds for the degree-4
BLS24 curves, whose second group is settled by elimination — but every one
of them is orders of magnitude below the minutes its construction cost.
The producer side is not timed here: it needs PARI/GP and runs long enough
that a single number is beside the point.

Not a gate and not part of the trusted base. A slow verify is not a broken
one, so nothing here fails a build; it reports, and the numbers are for
the README and for noticing a regression, nothing more.

    python -m tools.bench
    python -m tools.bench --repeat 20 --verifier verifier/target/release/ccert-verify
"""

from __future__ import annotations

import argparse
import statistics
import subprocess
import sys
import time
from pathlib import Path


def default_verifier() -> Path:
    exe = "ccert-verify.exe" if sys.platform == "win32" else "ccert-verify"
    return Path("verifier") / "target" / "release" / exe


def time_one(verifier: Path, cert: Path, repeat: int) -> list[float]:
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        result = subprocess.run(
            [str(verifier), "--require-proved", str(cert)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        elapsed = time.perf_counter() - start
        if result.returncode != 0:
            raise SystemExit(
                f"{cert.name}: verifier exited {result.returncode}; "
                f"benchmark a corpus that verifies"
            )
        samples.append(elapsed)
    return samples


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Time certificate verification.")
    parser.add_argument("--corpus", default="spec/vectors/valid",
                        help="directory of .ccert files to time")
    parser.add_argument("--verifier", type=Path, default=None,
                        help="path to the ccert-verify binary")
    parser.add_argument("--repeat", type=int, default=10,
                        help="runs per certificate (min and median are reported)")
    args = parser.parse_args(argv)

    verifier = args.verifier or default_verifier()
    if not verifier.exists():
        raise SystemExit(f"verifier not found at {verifier}; build it first "
                         f"(tools\\build_verifier.bat) or pass --verifier")

    corpus = Path(args.corpus)
    certs = sorted(corpus.glob("*.ccert"))
    if not certs:
        raise SystemExit(f"no .ccert files in {corpus}")

    print(f"verifying {len(certs)} certificate(s), {args.repeat} run(s) each\n")
    print(f"{'curve':<16}{'bytes':>8}{'min ms':>10}{'median ms':>12}")
    print("-" * 46)

    all_medians = []
    for cert in certs:
        samples = time_one(verifier, cert, args.repeat)
        best = min(samples) * 1000
        mid = statistics.median(samples) * 1000
        all_medians.append(mid)
        size = cert.stat().st_size
        print(f"{cert.stem:<16}{size:>8}{best:>10.1f}{mid:>12.1f}")

    print("-" * 46)
    print(f"median across the corpus: {statistics.median(all_medians):.1f} ms")
    print("\nProducing any one of these is minutes of work; checking it is the "
          "number above — a fraction of a second for a prime field, seconds for "
          "a pairing curve over an extension.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
