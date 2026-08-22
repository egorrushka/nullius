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
from core.bundle.assembly import (
    SMALL_PRIME_LIMIT,
    SMALL_PRIME_LIMIT_EXP,
    cardinality_deps as _cardinality_deps,
    certificate_payload as _certificate_payload,
    largest_prime_factor,
    prime_entries as _prime_entries,
)
from core.bundle.model import Bundle
from core.claims import rigidity
from core.claims.models import to_weierstrass
from core.claims.point_order import (
    build_point_order_evidence,
    find_witness,
    make_curve,
    make_field,
)

__all__ = ["build_curve_bundle", "KNOWN_CURVES"]

# Every constant here is one we can point at a standard for. A wrong digit
# produces a confident certificate about a curve nobody uses, so each entry
# also carries the order the standard publishes. That number is not
# evidence and never enters the bundle: it is a transcription check, and a
# disagreement with the computed order means a typo, not a discovery.
# Curves published in a model other than short Weierstrass. The subject
# still carries the Weierstrass coefficients, because that is the shape
# every other claim is about; the model claim is what ties those numbers
# to the equation people actually cite.
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
    "curve25519": {
        # Published as the Montgomery curve y^2 = x^3 + 486662 x^2 + x.
        # The Weierstrass coefficients below are what that equation gives,
        # and `curve.model` is the claim that ties the two together rather
        # than leaving a reader to take the conversion on faith.
        "a": 19298681539552699237261830834781317975544997444273427339909597334573241639236,
        "b": 55751746669818908907645289078257140818241103727901012315294400837956729358436,
        "p": 2**255 - 19,
        "label": "Curve25519",
        "source": "RFC 7748, section 4.1",
        "model": {"model": "montgomery", "A": "486662", "B": "1"},
        # The CM discriminant is 257 bits with no small structure, and
        # factoring it takes minutes. Recorded here rather than left to a
        # command-line flag, because a flag would make the bytes depend on
        # who ran the build: the same curve would hash differently
        # depending on whether the producer was in a hurry, and the whole
        # format rests on that not being so.
        "skip_cm": True,
        "published_order": 8 * (7237005577332262213973186563042994240857116359379907606001950938285454250989),
    },
    "ed25519": {
        # The twisted Edwards curve -x^2 + y^2 = 1 + d x^2 y^2, birationally
        # equivalent to Curve25519. Its Montgomery form has B = 4/(a - d)
        # rather than 1, which gives different Weierstrass coefficients for
        # an isomorphic curve — the ratio is a square, so the orders agree,
        # and both are certified separately rather than one standing in for
        # the other.
        "a": 42204101795669822316448953119945047945709099015225996174933988943478124189485,
        "b": 13148341720542919587570920744190446479425344491440436116213316435534172959396,
        "p": 2**255 - 19,
        "label": "Ed25519",
        "source": "RFC 8032, section 5.1",
        # Same discriminant as Curve25519, same cost. See the note there.
        "skip_cm": True,
        "model": {
            "model": "twisted-edwards",
            "a": "-1",
            "d": "37095705934669439343138083508754565189542113879843219016388785533085940283555",
        },
        "published_order": 8 * (7237005577332262213973186563042994240857116359379907606001950938285454250989),
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




def _add_cm_claim(bundle, backend, p, order, progress, cofactor: int = 1) -> None:
    """The CM discriminant, and the factorisation showing it fundamental.

    Split out because it is the one step whose cost is not bounded by the
    size of the curve: it factors a number as large as the discriminant,
    and on a curve with no small CM structure that can run into minutes.
    """
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
        depends_on=_cardinality_deps(cofactor),
    )


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
    model: dict[str, str] | None = None,
    skip_cm: bool = False,
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
    # What the producer actually did, not what it was asked to do.
    #
    # Two steps are optional because their cost is unbounded: factoring
    # the quadratic twist, and the CM discriminant. Recording the choice
    # in the curve table kept the bytes from depending on who ran the
    # build, but it left a reader unable to tell "the twist was not
    # factored" from "there is no twist claim for some other reason".
    #
    # Stating it makes the dependency visible instead of removing it. Two
    # producers who chose differently now write honestly different
    # certificates, and a reader sees which steps were taken rather than
    # inferring it from what is missing.
    subject["optional_steps"] = sorted(
        step
        for step, taken in (("cm", not skip_cm), ("twist", True))
        if taken
    )
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

    # The subgroup the protocol uses, and whatever surrounds it. For most
    # of this corpus the cofactor is one and the two coincide; Curve25519
    # and Ed25519 have cofactor 8, which the older path refused outright
    # rather than certifying wrongly. The refusal was right and the
    # remedy is the argument the pairing curves already use, not a
    # weakening of this one.
    subgroup, cofactor = order, 1
    cofactor_factors: list[tuple[int, int]] = []
    if order > 1:
        factors = backend.factorization(order)
        subgroup = max(prime for prime, _ in factors)
        cofactor = order // subgroup
        cofactor_factors = [
            (prime, exponent - (1 if prime == subgroup else 0))
            for prime, exponent in factors
            if exponent - (1 if prime == subgroup else 0) > 0
        ]

    progress("proving the subgroup order prime")
    bundle.add_claim(
        "curve.order.prime",
        {"n": canonical.as_str(subgroup), "prime": "proved"},
        "proof.ecpp",
        _certificate_payload(subgroup, backend.primality_certificate(subgroup)),
    )

    if cofactor == 1:
        # The original argument, kept for the curves it fits: a point of
        # prime order n with n above the Hasse window admits one multiple
        # and no other. Smaller and easier to read than the general one,
        # and there is no reason to retire it.
        progress("finding a witness point")
        x, y = backend.first_point(a, b, p)
        if order * order <= 16 * p:
            raise ValueError(
                "n is not larger than the Hasse window, so the order is not "
                "pinned down"
            )
        # The argument needs n prime, and the producer says so rather than
        # relying on the verifier to catch it. Without primality `n·P = O`
        # shows only that order(P) divides n, and a point of order 2
        # confirms every even n in the window.
        if order != subgroup:
            raise ValueError(
                "check.order-unique needs n to be the proved prime; this "
                "curve has a cofactor and belongs on the cofactor path"
            )
        bundle.add_claim(
            "curve.order",
            {"n": canonical.as_str(order), "cofactor": "1"},
            "check.order-unique",
            {"point": {"x": canonical.as_str(x), "y": canonical.as_str(y)}},
            depends_on=("curve.order.prime", "field.characteristic"),
        )
    else:
        progress("finding a witness point")
        all_factors = cofactor_factors + [(subgroup, 1)]
        chains = {
            prime: backend.primality_certificate(prime)
            for prime, _ in all_factors
            if prime >= SMALL_PRIME_LIMIT
        }
        field = make_field(p, 1)
        curve = make_curve(field, (a,), (b,))
        point, witness_order = find_witness(curve, order, all_factors)
        # The exponent as it appears in the *witness* order, not in the
        # group order. Filtering by divisibility alone keeps the full
        # exponent, so a witness of order 4r would arrive carrying 2^3
        # and the product would not match what it claims to factor.
        witness_factors = []
        for prime, _ in all_factors:
            exponent, rest = 0, witness_order
            while rest % prime == 0:
                rest //= prime
                exponent += 1
            if exponent:
                witness_factors.append((prime, exponent))

        payload, pinned = build_point_order_evidence(
            p, 1, (a,), (b,), point, witness_order, witness_factors,
            chains={
                prime: chain
                for prime, chain in chains.items()
                if witness_order % prime == 0
            },
        )
        if pinned != order:
            raise ValueError("the witness pins an order the count disagrees with")
        bundle.add_claim(
            "curve.cardinality",
            {"n": canonical.as_str(order)},
            "proof.point-order",
            payload,
            depends_on=("field.characteristic",),
        )
        bundle.add_claim(
            "curve.order",
            {
                "n": canonical.as_str(subgroup),
                "cofactor": canonical.as_str(cofactor),
                "largest_prime_factor": canonical.as_str(
                    max((prime for prime, _ in cofactor_factors), default=1)
                ),
            },
            "check.cofactor",
            {"factors": _prime_entries(cofactor_factors, backend, progress)},
            depends_on=("curve.cardinality", "curve.order.prime"),
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
        # curve.cardinality when the bundle has one, because that is what
        # the handler reads. A cofactor-1 curve has no such claim and the
        # handler falls back to curve.order, so the declaration follows
        # the bundle rather than the claim type.
        depends_on=_cardinality_deps(cofactor),
    )

    # The embedding degree is the order of p modulo the *subgroup* order,
    # not the group order. On a curve with cofactor one they are the same
    # number, which is why this read `order` and was right until a curve
    # with cofactor 8 arrived. The pairing transfer that this criterion is
    # about lands in the subgroup, so the subgroup is what it is about.
    progress("factoring n - 1")
    factors = backend.factorization(subgroup - 1)
    degree = backend.multiplicative_order(p, subgroup)
    if (subgroup - 1) % degree != 0:
        raise ValueError("the reported order does not divide n - 1")

    entries = _prime_entries(factors, backend, progress)
    two_adicity = next((exponent for prime, exponent in factors if prime == 2), 0)

    bundle.add_claim(
        "curve.embedding",
        {
            "degree": canonical.as_str(degree),
            "two_adicity": canonical.as_str(two_adicity),
        },
        "proof.multiplicative-order",
        {
            "base": canonical.as_str(p),
            "modulus": canonical.as_str(subgroup),
            "order": canonical.as_str(degree),
            "factors": entries,
        },
        # Both, because both are read: the modulus is curve.order.n and
        # the handler binds it to the prime proved in curve.order.prime.
        # A declaration that names only one of them is a graph nobody can
        # follow.
        depends_on=("curve.order", "curve.order.prime"),
    )

    if model is not None:
        # The producer recomputes before it writes, as everywhere else:
        # nothing is published that was not checked here first, and a
        # conversion is exactly the kind of thing a reader would take on
        # sight.
        derived_a, derived_b = to_weierstrass(
            model["model"],
            {
                key: int(value)
                for key, value in model.items()
                if key != "model"
            },
            p,
        )
        if (derived_a, derived_b) != (a, b):
            raise ValueError(
                "the model parameters do not give the stated Weierstrass "
                "coefficients"
            )
        bundle.add_claim(
            "curve.model",
            dict(model),
            "check.curve-model",
            {"model": model["model"]},
            depends_on=("field.characteristic",),
        )

    if skip_cm:
        # Absent rather than weakened. A policy asking about complex
        # multiplication returns undecided, which blocks a pass, and that
        # is the correct reading: nobody established the discriminant.
        #
        # The step is optional because its cost is unbounded in a way the
        # others are not. It factors a number the size of the
        # discriminant, and for Curve25519 that is 257 bits taking some
        # minutes. A producer that cannot afford it should be able to
        # publish everything else rather than nothing.
        progress("skipping the CM discriminant")
    else:
        _add_cm_claim(bundle, backend, p, order, progress, cofactor)



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

    # The twist order alone establishes nothing about twist security: an
    # implementation that skips point validation can be handed a point on
    # the twist, and what that buys an attacker is bounded by the largest
    # prime factor of this number rather than by its size. So the
    # factorisation goes in, and the largest factor is asserted where a
    # policy can read it.
    progress("factoring the quadratic twist")
    twist = twist_cardinality(p, order)
    twist_factors = backend.factorization(twist)
    largest = max((prime for prime, _ in twist_factors), default=1)
    bundle.add_claim(
        "twist.cardinality",
        {
            "n_twist": canonical.as_str(twist),
            "identity": "n + n_twist = 2p + 2",
            "largest_prime_factor": canonical.as_str(largest),
        },
        "derive.twist-sum",
        {"factors": _prime_entries(twist_factors, backend, progress)},
        depends_on=_cardinality_deps(cofactor),
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
