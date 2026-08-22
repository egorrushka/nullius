"""Builds any known curve, whichever module knows how.

Two builders exist because the arguments genuinely differ: a prime-field
curve needs `a`, `b` and `p`, a pairing-friendly one needs a twist and an
extension as well. Threading both through one function would leave half
the parameters unused on every call.

But *which* builder a name belongs to is not a fact worth repeating. It
was written down in three places — the corpus script, the CI rebuild step
and by hand in the tests — and the CI copy called the prime-field builder
for every certificate it found, which would have failed the moment a
pairing curve was published beside the others. So the mapping lives here
and nowhere else.

    python -m tools.build_curve --curve bls12-381 --out corpus
    python -m tools.build_curve --all --out corpus
    python -m tools.build_curve --list

`--list` prints the names one per line, which is what a shell loop in CI
wants: the workflow no longer needs its own list either.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core.backends.gp import GpBackend, GpConfig, GpError
from core.bundle.builder import KNOWN_CURVES, build_curve_bundle, write_bundle
from core.bundle.pairing import KNOWN_PAIRING_CURVES, build_pairing_bundle

__all__ = ["ALL_CURVES", "ALIASES", "resolve", "is_pairing", "build"]

# The union, and the answer to "which builder". A name in both would be an
# outright bug, so it is caught at import rather than resolved by
# precedence.
_OVERLAP = set(KNOWN_CURVES) & set(KNOWN_PAIRING_CURVES)
if _OVERLAP:
    raise RuntimeError(
        f"these curves are defined in both builders: {', '.join(sorted(_OVERLAP))}"
    )

ALL_CURVES: tuple[str, ...] = tuple(sorted(set(KNOWN_CURVES) | set(KNOWN_PAIRING_CURVES)))

# Names people actually type, mapped to the ones the corpus uses.
#
# A curve has one canonical name here because a file is named after it and
# a vector is compared byte for byte against that file. But the same curve
# has several names in the literature and in other libraries, and a tool
# that answers "unknown curve: bls12381" to someone who meant `bls12-381`
# is being unhelpful about a hyphen.
#
# Aliases resolve; they never appear in output. The canonical name is what
# gets printed and what the file is called, so nobody can end up with two
# certificates for one curve under different names.
ALIASES: dict[str, str] = {
    "bls12381": "bls12-381",
    "bls12_381": "bls12-381",
    "bls381": "bls12-381",
    "bn128": "bn254",          # the name Ethereum's precompiles use
    "alt_bn128": "bn254",      # and the one in the EVM opcode tables
    "bn_254": "bn254",
    "k256": "secp256k1",
    "secp256r1": "p-256",
    "prime256v1": "p-256",     # the OpenSSL spelling
    "nistp256": "p-256",
    "p256": "p-256",
}


def resolve(name: str) -> str:
    """The canonical name for whatever the caller typed.

    Case and separators are normalised first, so `BLS12_381`, `bls12-381`
    and `bls12381` all arrive at the same place.
    """
    if name in ALL_CURVES:
        return name
    folded = name.strip().lower()
    if folded in ALL_CURVES:
        return folded
    if folded in ALIASES:
        return ALIASES[folded]
    # Try again with separators normalised, which catches the common case
    # of an underscore where the corpus uses a hyphen.
    for separator in ("_", " "):
        candidate = folded.replace(separator, "-")
        if candidate in ALL_CURVES:
            return candidate
        if candidate in ALIASES:
            return ALIASES[candidate]
    stripped = folded.replace("-", "").replace("_", "")
    if stripped in ALIASES:
        return ALIASES[stripped]
    raise KeyError(name)


def is_pairing(name: str) -> bool:
    return name in KNOWN_PAIRING_CURVES


def build(name: str, backend: GpBackend, progress=lambda _msg: None,
          skip_twist: bool = False, skip_cm: bool = False):
    """The bundle for a known curve, from whichever builder owns it."""
    name = resolve(name)
    if name in KNOWN_PAIRING_CURVES:
        params = KNOWN_PAIRING_CURVES[name]
        return build_pairing_bundle(
            name=params["label"],
            p=params["p"],
            a=params["a"],
            b=params["b"],
            r=params["r"],
            beta=params["beta"],
            family=params.get("family"),
            u=params.get("u"),
            twist_degree=params.get("twist_degree", 2),
            xi=params.get("xi"),
            published_order2=params.get("published_order2"),
            skip_g2_cofactor=params.get("skip_g2_cofactor", False),
            twist_a=params["twist_a"],
            twist_b=params["twist_b"],
            backend=backend,
            source=params.get("source"),
            progress=progress,
            published_order=params.get("published_order"),
            embedding_degree=params.get("embedding_degree"),
        )
    if name in KNOWN_CURVES:
        params = KNOWN_CURVES[name]
        # Keyword arguments on purpose. The two builders take their
        # parameters in a different order, and passing them positionally
        # is how the first version of this file silently handed p to the
        # slot meant for a. It failed loudly, but only because a curve
        # built from the wrong numbers has a composite order; a quieter
        # mix-up would have produced a certificate about nothing.
        return build_curve_bundle(
            name=params.get("label", name),
            a=params["a"],
            b=params["b"],
            p=params["p"],
            backend=backend,
            source=params.get("source"),
            progress=progress,
            published_order=params.get("published_order"),
            seed=params.get("seed"),
            model=params.get("model"),
            # The table decides, not the caller. An optional step chosen
            # at the command line would make a certificate's bytes depend
            # on who built it, and content addressing would stop meaning
            # anything. The flag below only ever adds skipping, never
            # removes it.
            skip_cm=params.get("skip_cm", False) or skip_cm,
        )
    raise KeyError(name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a certificate for a known curve.")
    parser.add_argument("--curve", help=f"one of: {', '.join(ALL_CURVES)}")
    parser.add_argument("--all", action="store_true", help="build every known curve")
    parser.add_argument("--list", action="store_true", help="print the names and exit")
    parser.add_argument(
        "--aliases", action="store_true", help="print the accepted spellings and exit"
    )
    parser.add_argument("--out", default="corpus", help="output directory")
    parser.add_argument("--gp", help="full path to gp.exe")
    parser.add_argument("--quiet", action="store_true", help="no progress lines")
    parser.add_argument(
        "--skip-cm",
        action="store_true",
        help="omit the CM discriminant; it factors a number as large as itself",
    )
    args = parser.parse_args(argv)

    if args.list:
        print("\n".join(ALL_CURVES))
        return 0

    if args.aliases:
        for alias, canonical in sorted(ALIASES.items()):
            print(f"{alias:<14} {canonical}")
        return 0

    if args.all:
        names = list(ALL_CURVES)
    elif args.curve:
        try:
            names = [resolve(args.curve)]
        except KeyError:
            print(f"unknown curve: {args.curve}", file=sys.stderr)
            print(f"known: {', '.join(ALL_CURVES)}", file=sys.stderr)
            print(f"aliases: {', '.join(sorted(ALIASES))}", file=sys.stderr)
            return 2
        if names[0] != args.curve:
            print(f"{args.curve} is {names[0]}", file=sys.stderr)
    else:
        parser.error("give --curve, --all or --list")
        return 2

    def progress(message: str) -> None:
        if not args.quiet:
            print(f"  {message}...", flush=True)

    try:
        backend = GpBackend(GpConfig(exe=Path(args.gp) if args.gp else None))
    except GpError as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        return 1

    out = Path(args.out)
    for name in names:
        if not args.quiet:
            print(f"=== {name}")
        try:
            bundle = build(name, backend, progress, skip_cm=args.skip_cm)
        except (GpError, ValueError) as exc:
            print(f"FAIL  {name}: {exc}", file=sys.stderr)
            return 1
        path = write_bundle(bundle, out, name)
        counts = bundle.tier_counts()
        print(
            f"{name}: {path} ({path.stat().st_size} bytes)\n"
            f"  {bundle.digest()}\n"
            f"  {counts['A']} proved, {counts['D']} derived, {counts['X']} candidate"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
