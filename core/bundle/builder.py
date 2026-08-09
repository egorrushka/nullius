"""Builds a bundle for a short Weierstrass curve over a prime field.

The expensive computation is no longer trusted at all. Point counting only
*proposes* a number; what makes it into the bundle is a chain of evidence
that stands without it. If SEA returned a wrong order, the order claim
would simply fail to verify rather than quietly becoming a fact.

Claims produced here:

    field.characteristic  p is prime                  Atkin-Morain chain
    curve.order.prime     n is prime                  Atkin-Morain chain
    curve.order           #E = n, cofactor 1          a point of order n
    curve.embedding       embedding degree            an exact element order
    curve.cm              CM field discriminant       a proved factorisation
    param.rigidity        b follows from a seed       the derivation, rerun
    curve.hasse           n lies in the Hasse window  integer arithmetic
    twist.cardinality     #E' = 2p + 2 - n            an identity
"""

from __future__ import annotations

import argparse
import sys
from math import isqrt
from pathlib import Path
from typing import Any

from core.backends.gp import (
    GpBackend,
    GpConfig,
    GpError,
    hasse_interval,
    twist_cardinality,
)
from core.bundle import canonical
from core.bundle.model import Bundle
from core.claims import rigidity

__all__ = ["build_curve_bundle", "KNOWN_CURVES"]

# Every constant here is one we can point at a standard for. A wrong digit
# produces a confident certificate about a curve nobody uses, so each entry
# also carries the order the standard publishes. That number is not
# evidence and never enters the bundle: it is a transcription check, and a
# disagreement with the computed order means a typo, not a discovery.
KNOWN_CURVES: dict[str, dict[str, Any]] = {
    "secp256k1": {
        "a": 0,
        "b": 7,
        "p": 2**256 - 2**32 - 977,
        "label": "secp256k1",
        "source": "SEC 2 v2",
        "published_order": int(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
        ),
    },
    "p-256": {
        "a": int(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16
        )
        - 3,
        "b": int(
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16
        ),
        "p": int(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16
        ),
        "label": "P-256",
        "source": "NIST SP 800-186, also SEC 2 as secp256r1",
        "seed": "C49D360886E704936A6678E1139D26B7819F7E90",
        "published_order": int(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
        ),
    },
}


# Below this a prime is settled by the verifier directly, so shipping a
# chain for it would be bulk with no content. The bound matches the one the
# verifier uses; they must not drift apart.
SMALL_PRIME_LIMIT = 10**24


def _prime_entries(
    factors: list[tuple[int, int]], backend: GpBackend, progress
) -> list[dict[str, Any]]:
    """Factors with a chain attached to each one the verifier cannot settle."""
    entries: list[dict[str, Any]] = []
    for prime, exponent in factors:
        entry: dict[str, Any] = {
            "prime": canonical.as_str(prime),
            "exponent": canonical.as_str(exponent),
        }
        if prime >= SMALL_PRIME_LIMIT:
            progress(f"proving a {prime.bit_length()}-bit factor prime")
            entry["steps"] = _certificate_payload(
                prime, backend.primality_certificate(prime)
            )["steps"]
        entries.append(entry)
    return entries


def _certificate_payload(subject: int, steps: list[dict[str, int]]) -> dict[str, Any]:
    return {
        "subject": canonical.as_str(subject),
        "steps": [
            {key: canonical.as_str(value) for key, value in step.items()}
            for step in steps
        ],
    }


def build_curve_bundle(
    name: str,
    a: int,
    b: int,
    p: int,
    backend: GpBackend,
    source: str | None = None,
    progress=lambda _msg: None,
    published_order: int | None = None,
    seed: str | None = None,
) -> Bundle:
    """Compute claims about y^2 = x^3 + ax + b over F_p."""
    a, b = a % p, b % p
    subject: dict[str, Any] = {
        "kind": "elliptic-curve",
        "model": "short-weierstrass",
        "field": {"kind": "prime", "p": canonical.as_str(p)},
        "a": canonical.as_str(a),
        "b": canonical.as_str(b),
    }
    if name:
        subject["label"] = name
    if source:
        subject["source"] = source

    bundle = Bundle(subject=subject)

    progress("proving p prime")
    bundle.add_claim(
        "field.characteristic",
        {"p": canonical.as_str(p), "prime": "proved"},
        "proof.ecpp",
        _certificate_payload(p, backend.primality_certificate(p)),
    )

    progress("counting points")
    order = backend.curve_cardinality(a, b, p)
    if published_order is not None and order != published_order:
        raise ValueError(
            "the computed order differs from the one the standard publishes; "
            "a parameter was mistyped"
        )

    progress("proving the order prime")
    bundle.add_claim(
        "curve.order.prime",
        {"n": canonical.as_str(order), "prime": "proved"},
        "proof.ecpp",
        _certificate_payload(order, backend.primality_certificate(order)),
    )

    progress("finding a witness point")
    x, y = backend.first_point(a, b, p)
    if order * order <= 16 * p:
        raise ValueError(
            "n is not larger than the Hasse window, so the order is not pinned "
            "down; this curve needs a cofactor argument we do not support yet"
        )
    bundle.add_claim(
        "curve.order",
        {"n": canonical.as_str(order), "cofactor": "1"},
        "check.order-unique",
        {"point": {"x": canonical.as_str(x), "y": canonical.as_str(y)}},
        depends_on=("curve.order.prime",),
    )

    low, high = hasse_interval(p)
    if not low <= order <= high:
        raise ValueError("cardinality outside the Hasse interval")
    bundle.add_claim(
        "curve.hasse",
        {
            "low": canonical.as_str(low),
            "high": canonical.as_str(high),
            "contains": canonical.as_str(order),
        },
        "check.hasse",
        depends_on=("curve.order",),
    )

    progress("factoring n - 1")
    factors = backend.factorization(order - 1)
    degree = backend.multiplicative_order(p, order)
    if (order - 1) % degree != 0:
        raise ValueError("the reported order does not divide n - 1")

    entries = _prime_entries(factors, backend, progress)

    bundle.add_claim(
        "curve.embedding",
        {"degree": canonical.as_str(degree)},
        "proof.multiplicative-order",
        {
            "base": canonical.as_str(p),
            "modulus": canonical.as_str(order),
            "order": canonical.as_str(degree),
            "factors": entries,
        },
        depends_on=("curve.order.prime",),
    )

    progress("finding the CM discriminant")
    trace = p + 1 - order
    discriminant = trace * trace - 4 * p
    fundamental = backend.core_discriminant(discriminant)
    square = discriminant // fundamental
    conductor = isqrt(square)
    if fundamental >= 0 or conductor * conductor != square:
        raise ValueError("the discriminant does not split as conductor^2 times D")

    cm_factors = backend.factorization(abs(fundamental)) if abs(fundamental) > 1 else []
    bundle.add_claim(
        "curve.cm",
        {
            "trace": canonical.as_str(trace),
            "fundamental": canonical.as_str(fundamental),
            "conductor": canonical.as_str(conductor),
        },
        "proof.cm-discriminant",
        {
            "fundamental": canonical.as_str(fundamental),
            "conductor": canonical.as_str(conductor),
            "factors": _prime_entries(cm_factors, backend, progress),
        },
        depends_on=("curve.order",),
    )

    if seed is not None:
        progress("rerunning the seed derivation")
        raw = bytes.fromhex(seed)
        c = rigidity.derive_c(raw, p)
        if not rigidity.relation_holds(c, b, p):
            raise ValueError(
                "the published seed does not reproduce b; either the seed or a "
                "curve parameter is wrong"
            )
        bundle.add_claim(
            "param.rigidity",
            {"reproduced": "1", "method": rigidity.METHOD},
            "check.seed-derivation",
            {"method": rigidity.METHOD, "seed": seed.upper()},
        )
    # A curve without a published seed simply has no such claim. Absence of
    # a seed is not a fact about numbers and cannot be proved; it is a fact
    # about the literature, and the bundle stays silent about it.

    twist = twist_cardinality(p, order)
    bundle.add_claim(
        "twist.cardinality",
        {"n_twist": canonical.as_str(twist), "identity": "n + n_twist = 2p + 2"},
        "derive.twist-sum",
        depends_on=("curve.order",),
    )

    bundle.validate()
    return bundle


def write_bundle(bundle: Bundle, out_dir: Path, stem: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{stem}.ccert"
    path.write_bytes(bundle.encode() + b"\n")
    return path


def _report(bundle: Bundle, path: Path) -> None:
    counts = bundle.tier_counts()
    size = path.stat().st_size
    print(f"\nwritten:  {path}  ({size} bytes)")
    print(f"digest:   {bundle.digest()}")
    print(f"claims:   {len(bundle.claims)}")
    print(f"  proved (A):     {counts['A']}")
    print(f"  derived (D):    {counts['D']}")
    print(f"  candidate (X):  {counts['X']}")
    print("\nNow check it with something that did not produce it:")
    print(f"  tools\\verify.bat {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a curve bundle.")
    parser.add_argument("--curve", help=f"one of: {', '.join(KNOWN_CURVES)}")
    parser.add_argument("--a", type=int, help="curve coefficient a")
    parser.add_argument("--b", type=int, help="curve coefficient b")
    parser.add_argument("--p", type=int, help="field characteristic")
    parser.add_argument("--name", default="", help="label for a custom curve")
    parser.add_argument("--out", default="corpus", help="output directory")
    parser.add_argument("--gp", help="full path to gp.exe")
    parser.add_argument("--seed", help="hex seed for a verifiably random curve")
    parser.add_argument("--quiet", action="store_true", help="no progress lines")
    args = parser.parse_args(argv)

    if args.curve:
        if args.curve not in KNOWN_CURVES:
            print(f"unknown curve: {args.curve}", file=sys.stderr)
            return 2
        params = KNOWN_CURVES[args.curve]
        a, b, p = params["a"], params["b"], params["p"]
        # The file is named by the command-line key; the label inside is the
        # name the standard uses, and those differ in case.
        name = params.get("label", args.curve)
        source = params.get("source")
        published = params.get("published_order")
        seed = params.get("seed")
    elif args.a is not None and args.b is not None and args.p is not None:
        name, a, b, p, source = args.name, args.a, args.b, args.p, None
        published, seed = None, args.seed
    else:
        parser.error("give --curve, or all of --a --b --p")
        return 2

    def progress(message: str) -> None:
        if not args.quiet:
            print(f"  {message}...", flush=True)

    try:
        backend = GpBackend(GpConfig(exe=Path(args.gp) if args.gp else None))
        bundle = build_curve_bundle(
            name, a, b, p, backend, source, progress, published, seed
        )
    except (GpError, ValueError) as exc:
        print(f"FAIL  {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    stem = args.curve if args.curve else (args.name or "curve")
    path = write_bundle(bundle, Path(args.out), stem)
    _report(bundle, path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
