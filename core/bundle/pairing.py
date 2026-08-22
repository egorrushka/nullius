"""Builds a bundle for a pairing-friendly curve.

Separate from :mod:`core.bundle.builder` rather than a branch inside it.
The prime-field builder makes an assumption this one cannot keep — that
the group order is prime and the cofactor is one — and threading a flag
through it would leave two paths tangled in one file. The shared parts are
imported; the rest is written out.

Claims produced here:

    field.characteristic  p is prime                   Atkin-Morain chain
    curve.cardinality     #E over F_p                  a point of large order
    curve.order.prime     r is prime                   Atkin-Morain chain
    curve.order           r and the cofactor h1        exact division
    curve.embedding       embedding degree             an exact element order
    g2.cardinality        #E' over F_p^2               a point of large order
    g2.order              r and the cofactor h2        exact division

What the G2 claims do and do not say, stated here because the certificate
must not imply more than it establishes.

They do now tie the curve in the G2 evidence to the subject. That curve
has `a' = 0` and is non-singular, so `b' != 0`; the subject has `a = 0`;
and `q = 1 mod 3`. Over such a field every `y^2 = x^3 + b'` with
`b' != 0` is one of the six sextic twists of `y^2 = x^3 + b`, so the
curve is a twist of the subject by arithmetic rather than by citation.
The elimination then says which of the six it is, and the census on `r`
says that one is the second group rather than the subject's own curve
over the extension.

The class label follows at every degree: `g2.twist` asserts the degree
beside the index, so the six it indexes are named rather than assumed. A
policy asking for the twist relation now gets an answer for BLS24 as well
as BLS12 and BN.

Point counting is used only to propose a number. What makes it into the
bundle is a witness that stands without it: if the count were wrong, the
order claim would fail to verify rather than quietly becoming a fact.
"""

from __future__ import annotations

import argparse
import sys
from math import isqrt
from pathlib import Path
from typing import Any

from core.backends.gp import GpBackend, GpConfig, GpError
from core.backends.gp_fp2 import curve_cardinality_fp2
from core.bundle import canonical
from core.bundle.builder import SMALL_PRIME_LIMIT, write_bundle
from core.bundle.assembly import (
    SMALL_PRIME_LIMIT,
    certificate_payload as _certificate_payload,
    chains_for as _chains_for,
    factor_entries as _factor_entries,
    largest_prime_factor as _largest_prime_factor,
)
from core.bundle.model import Bundle
from core.claims.family import FamilyError, check_against
from core.claims.elimination import points_in_order, settle_group_order
from core.claims.twist import TwistError, classify, twist_candidates
from core.claims.point_order import (
    EVIDENCE_TYPE as POINT_ORDER_EVIDENCE,
    build_point_order_evidence,
    find_witness,
    make_curve,
    make_field,
)

__all__ = ["build_pairing_bundle", "KNOWN_PAIRING_CURVES"]


# Every constant here can be pointed at a standard. The published orders
# are transcription checks, not evidence: they never enter the bundle, and
# a disagreement means a mistyped digit rather than a discovery.
KNOWN_PAIRING_CURVES: dict[str, dict[str, Any]] = {
    "bls12-381": {
        "label": "BLS12-381",
        "source": "draft-irtf-cfrg-pairing-friendly-curves",
        "p": 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB,
        "a": 0,
        "b": 4,
        "r": 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001,
        # The sextic twist over F_p^2 = F_p[u]/(u^2 + 1): y^2 = x^3 + 4(1 + u).
        "beta": -1,
        "family": "bls12",
        "u": -0xD201000000010000,
        "twist_a": (0, 0),
        "twist_b": (4, 4),
        "published_order": 0x396C8C005555E1568C00AAAB0000AAAB
        * 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001,
        "embedding_degree": 12,
    },
    # The curve in Ethereum's pairing precompiles, and the reason this
    # project cares about separating facts from verdicts. Nothing below has
    # changed since it was standardised; the security estimate has, because
    # tower-field discrete logarithm work moved the model rather than the
    # curve. A certificate for it is identical before and after; a policy
    # that cites its model is not.
    # BLS24-315, the curve this format could not reach until the
    # elimination argument existed. Its second group lives over F_p^4 and
    # has a 1005-bit cofactor whose composite part is 983 bits: no witness
    # argument can touch it, because proving a witness's exact order needs
    # that factorisation and nobody is producing it.
    #
    # Everything below is checked at build time rather than trusted. The
    # family polynomials regenerate p and r from u; the elimination
    # settles the G2 order against six candidates derived from the
    # base-field cardinality; and the published order is compared if one
    # is given.
    "bls24-315": {
        "label": "BLS24-315",
        "source": "Costello-Lauter-Naehrig family; parameters as used in gnark",
        "p": 39705142709513438335025689890408969744933502416914749335064285505637884093126342347073617133569,
        "a": 0,
        "b": 1,
        "r": 11502027791375260645628074404575422495959608200132055716665986169834464870401,
        "family": "bls24",
        "u": -3218079743,
        # F_p^2 = F_p[w]/(w^2 - 13): 13 is the smallest non-residue here,
        # since p = 1 mod 4 rules out the usual -1.
        "beta": 13,
        # F_p^4 = F_p^2[v]/(v^2 - w).
        "twist_degree": 4,
        "xi": (0, 1),
        "twist_a": (0, 0, 0, 0),
        # b' = w + 2v. Found by search over the tower rather than taken
        # from a standard, and recorded as such: what makes it right is
        # that the elimination settles on a candidate divisible by r which
        # is not the base curve's own order over F_p^4. Constants from F_p
        # are all sixth powers here and give the base curve back, which is
        # the trap this coefficient exists to avoid.
        "twist_b": (0, 1, 2, 0),
        "embedding_degree": 24,
        # 983 bits of it are composite. Absent rather than guessed.
        "skip_g2_cofactor": True,
    },
    # BLS24-509, the curve built for the 192-bit level — and the one that
    # shows what a policy verdict is and is not.
    #
    # Its subgroup clears the generic bound comfortably at 409 bits. Its
    # embedding field is 12202 bits against the 12871 Barbulescu and
    # Duquesne give for 192, so under that model it does not clear the
    # bar, in the same way BLS12-381 does not at 128.
    #
    # What that means, stated carefully because the difference is the
    # whole reason facts and verdicts are kept apart here. The certificate
    # says 12202 bits, which is arithmetic. The policy says 12871, which
    # is one model's generic worst-case figure. Neither says the curve
    # fails to reach 192: per-curve analyses published since place it at
    # that level, and a reader who reads a failed criterion as a verdict
    # on the curve has read the wrong document.
    #
    # Reachable at all only through the elimination argument: the G2
    # cofactor is 1626 bits.
    "bls24-509": {
        "label": "BLS24-509",
        "source": "BLS24 family at u = -(2^51 + 2^28 - 2^11 + 1); used in RELIC and gnark",
        "p": 1117318659431823073025636112714290574287578746665891511499955392105017110575797004141301693204826524521038882935620747403220713415070534542877391675445931,
        "a": 0,
        "b": 1,
        "r": 661056599217803307416979259129202170418127684497598259050418817435227475023902005302150447222742727792149508033234329395201,
        "family": "bls24",
        "u": -2251800082118657,
        # p = 3 mod 4, so -1 is a non-residue and the usual choice works.
        "beta": -1,
        "twist_degree": 4,
        # F_p^4 = F_p^2[v]/(v^2 - (1 + w)).
        "xi": (1, 1),
        "twist_a": (0, 0, 0, 0),
        # b' = 2v. Found by search over the tower, and what makes it right
        # is that elimination settles on a candidate divisible by r which
        # is not the base curve's own order over F_p^4 — the trap that
        # divisibility alone would walk into.
        "twist_b": (0, 0, 2, 0),
        "embedding_degree": 24,
        # 1626 bits, and not going to factor.
        "skip_g2_cofactor": True,
    },
    "bn254": {
        "label": "BN254",
        "source": "Barreto-Naehrig curve as used in EIP-197",
        "p": 21888242871839275222246405745257275088696311157297823662689037894645226208583,
        "a": 0,
        "b": 3,
        "r": 21888242871839275222246405745257275088548364400416034343698204186575808495617,
        # F_p^2 = F_p[u]/(u^2 + 1); p = 3 mod 4, so -1 is a non-residue.
        "beta": -1,
        "family": "bn",
        "u": 4965661367192848881,
        "twist_a": (0, 0),
        # The sextic twist is y^2 = x^3 + 3/(9 + u). The quotient is given
        # here already evaluated, because the format carries coefficients
        # rather than expressions; the derivation is the line above, and
        # the build refuses if the resulting order disagrees with the
        # published one.
        "twist_b": (
            19485874751759354771024239261021720505790618469301721065564631296452457478373,
            266929791119991161246907387137283842545076965332900288569378510910307636690,
        ),
        # #E(F_p) = r exactly: unlike BLS12-381 the cofactor here is one.
        "published_order": 21888242871839275222246405745257275088548364400416034343698204186575808495617,
        "embedding_degree": 12,
    },
}






def _subgroup_factors(group_factors: list[tuple[int, int]], order: int):
    """The factorisation of ``order``, taken from that of the group order."""
    trimmed = []
    for prime, _ in group_factors:
        exponent, rest = 0, order
        while rest % prime == 0:
            rest //= prime
            exponent += 1
        if exponent:
            trimmed.append((prime, exponent))
    return trimmed


def _cofactor_factors(
    cofactor: int, backend: GpBackend
) -> list[tuple[int, int]]:
    return backend.factorization(cofactor) if cofactor > 1 else []


def build_pairing_bundle(
    name: str,
    p: int,
    a: int,
    b: int,
    r: int,
    beta: int,
    family: str | None,
    u: int | None,
    twist_a: tuple[int, ...],
    twist_b: tuple[int, ...],
    backend: GpBackend,
    source: str | None = None,
    progress=lambda _msg: None,
    published_order: int | None = None,
    embedding_degree: int | None = None,
    skip_twist: bool = False,
    twist_degree: int = 2,
    xi: tuple[int, int] | None = None,
    published_order2: int | None = None,
    skip_g2_cofactor: bool = False,
) -> Bundle:
    """Compute claims about a pairing-friendly curve and its G2."""
    a, b = a % p, b % p
    subject: dict[str, Any] = {
        "kind": "elliptic-curve",
        "model": "short-weierstrass",
        "field": {"kind": "prime", "p": canonical.as_str(p)},
        "a": canonical.as_str(a),
        "b": canonical.as_str(b),
    }
    # See the note in builder.py: the choice is stated rather than left
    # to be inferred from an absent claim.
    subject["optional_steps"] = sorted(
        step
        for step, taken in (("cm", True), ("twist", not skip_twist))
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

    progress("proving r prime")
    bundle.add_claim(
        "curve.order.prime",
        {"n": canonical.as_str(r), "prime": "proved"},
        "proof.ecpp",
        _certificate_payload(r, backend.primality_certificate(r)),
    )

    # -- G1 ----------------------------------------------------------

    progress("counting points over F_p")
    order = backend.curve_cardinality(a, b, p)
    if published_order is not None and order != published_order:
        raise ValueError(
            "the computed order differs from the one the standard publishes; "
            "a parameter was mistyped"
        )
    if order % r != 0:
        raise ValueError("r does not divide the group order")
    cofactor = order // r

    progress("factoring the G1 cofactor")
    factors = _cofactor_factors(cofactor, backend) + [(r, 1)]
    chains = _chains_for(factors, backend, progress)

    progress("finding a witness point over F_p")
    field = make_field(p, 1)
    curve = make_curve(field, (a,), (b,))
    point, witness_order = find_witness(curve, order, factors)

    payload, pinned = build_point_order_evidence(
        p,
        1,
        (a,),
        (b,),
        point,
        witness_order,
        _subgroup_factors(factors, witness_order),
        chains={
            prime: chain
            for prime, chain in chains.items()
            if witness_order % prime == 0
        },
    )
    if pinned != order:
        raise ValueError("the witness pins an order the count disagrees with")

    # The whole point-order argument assumes p is prime: the field, the
    # Euler criterion on beta, the Hasse window. The verifier requires
    # that to be established by a proved claim in the same bundle, so the
    # dependency is declared rather than left implicit.
    #
    # The coefficients handed to build_point_order_evidence above must be
    # the subject's own. The verifier now refuses a mismatch, so a future
    # refactor that passes something else fails loudly rather than
    # producing a certificate about a different curve.
    bundle.add_claim(
        "curve.cardinality",
        {"n": canonical.as_str(order)},
        POINT_ORDER_EVIDENCE,
        payload,
        depends_on=("field.characteristic",),
    )
    cofactor_factors = _cofactor_factors(cofactor, backend)
    bundle.add_claim(
        "curve.order",
        {
            "n": canonical.as_str(r),
            "cofactor": canonical.as_str(cofactor),
            "largest_prime_factor": canonical.as_str(
                _largest_prime_factor(cofactor_factors)
            ),
        },
        "check.cofactor",
        {"factors": _factor_entries(cofactor_factors, chains)},
        depends_on=("curve.cardinality", "curve.order.prime"),
    )

    if family is not None:
        progress("checking the family polynomials")
        # The producer recomputes before it writes: the general rule of
        # this project is that nothing is published which was not checked
        # here first, and a family claim is exactly the kind of thing that
        # would be believed on sight.
        try:
            check_against(family, u, p, r, order)
        except FamilyError as exc:
            raise ValueError(f"family check failed: {exc}") from exc
        bundle.add_claim(
            "curve.family",
            {"family": family, "u": canonical.as_str(u)},
            "check.family",
            {"family": family, "u": canonical.as_str(u)},
            depends_on=(
                "field.characteristic",
                "curve.order.prime",
                "curve.cardinality",
            ),
        )

    if not skip_twist:
        # The quadratic twist of G1. An implementation that accepts a
        # point without checking it is on the right curve can be handed
        # one on the twist instead, and what that buys an attacker is
        # bounded by the largest prime factor of the twist's order.
        #
        # The number is around 2p and factoring it is not always cheap —
        # BLS12-381 takes the better part of a minute. Producers that
        # cannot afford it may pass --skip-twist, and the claim is then
        # absent rather than weakened: a policy asking about twist
        # security returns undecided, which blocks a pass. Silence is not
        # consent, and a timeout must not quietly become one.
        progress("factoring the quadratic twist")
        twist_order = 2 * p + 2 - order
        twist_factors = backend.factorization(twist_order)
        largest = _largest_prime_factor(twist_factors)
        bundle.add_claim(
            "twist.cardinality",
            {
                "identity": "n + n_twist = 2p + 2",
                "n_twist": canonical.as_str(twist_order),
                "largest_prime_factor": canonical.as_str(largest),
            },
            "derive.twist-sum",
            {
                "factors": _factor_entries(
                    twist_factors, _chains_for(twist_factors, backend, progress)
                )
            },
            # Both: the handler reads the cardinality, and the required
            # table keys on the claim name rather than the bundle shape,
            # so `curve.order` has to appear for prime-field bundles as
            # well. Declaring the one actually read alongside it costs
            # nothing and says what is true.
            depends_on=("curve.cardinality", "curve.order"),
        )

    progress("finding the CM discriminant")
    # Both families here have j = 0 and therefore D = -3, which is what
    # makes the GLV endomorphism available and what the sextic twists
    # rest on. The prime-field builder has emitted this claim from the
    # start; a pairing curve had no way to state it, so a policy about
    # endomorphisms could not be decided for one.
    trace = p + 1 - order
    discriminant = trace * trace - 4 * p
    fundamental = backend.core_discriminant(discriminant)
    square = discriminant // fundamental
    conductor = isqrt(square)
    if fundamental >= 0 or conductor * conductor != square:
        raise ValueError("the discriminant does not split as conductor^2 times D")
    cm_factors = (
        backend.factorization(abs(fundamental)) if abs(fundamental) > 1 else []
    )
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
            "factors": _factor_entries(
                cm_factors, _chains_for(cm_factors, backend, progress)
            ),
        },
        depends_on=("curve.cardinality", "curve.order"),
    )

    progress("finding the embedding degree")
    degree = backend.multiplicative_order(p, r)
    if embedding_degree is not None and degree != embedding_degree:
        raise ValueError(
            "the computed embedding degree differs from the published one"
        )
    minus_one = backend.factorization(r - 1)
    # The exponent of two in r - 1, taken from a factorisation the
    # verifier already re-establishes for the order argument. It decides
    # how large an FFT domain the subgroup admits, which is the property
    # SNARK work selects these curves for, and it was sitting in the
    # evidence unusable by a policy because policies read assertions.
    two_adicity = next((e for prime, e in minus_one if prime == 2), 0)
    bundle.add_claim(
        "curve.embedding",
        {
            "degree": canonical.as_str(degree),
            "two_adicity": canonical.as_str(two_adicity),
        },
        "proof.multiplicative-order",
        {
            "base": canonical.as_str(p),
            "modulus": canonical.as_str(r),
            "order": canonical.as_str(degree),
            "factors": _factor_entries(
                minus_one, _chains_for(minus_one, backend, progress)
            ),
        },
        # Both, because both are read: the modulus is curve.order.n and
        # the handler binds it to the prime proved in curve.order.prime.
        # A declaration that names only one of them is a graph nobody can
        # follow.
        depends_on=("curve.order", "curve.order.prime"),
    )

    # -- G2 ----------------------------------------------------------

    # The order of the second group, by elimination rather than by
    # counting or by a witness.
    #
    # Nothing here asks a backend how many points there are. The six
    # candidates follow from the base-field cardinality by exact integer
    # arithmetic — Weil's recurrence for the trace, then the sextic twist
    # formulas — and points rule out five of them. That is what lets the
    # same code reach degree 4, where counting is impractical and the
    # witness argument is impossible: BLS24-315's G2 cofactor has a
    # 983-bit composite part, and nobody is factoring that.
    #
    # Narrow on purpose — only G2, where six candidates exist. Over the
    # base field there is nothing to enumerate, so G1 keeps
    # proof.point-order, which has no ceiling there anyway.
    progress(f"eliminating twist candidates over F_p^{twist_degree}")
    if a != 0:
        # Sextic twists exist only for j = 0. Refused rather than skipped:
        # producing a bundle without a G2 claim for the one case the
        # argument does not cover would read as coverage.
        raise ValueError(
            "the subject has a != 0, so it has no sextic twists and no "
            "second group this argument can settle"
        )
    field2 = make_field(p, twist_degree, beta, xi)
    curve2 = make_curve(field2, twist_a, twist_b)

    candidates, _t2, _v = twist_candidates(p, order, twist_degree)
    # Not `eliminate`. Two of the six can be divisible by r, and only one
    # of them is the second group: the base curve extended to the larger
    # field is itself a candidate, and r divides its order because r
    # divides #E(F_p) which divides #E(F_p^n). It is not G2, because the
    # pairing needs the eigenvalue-p subgroup, which lives on the twist.
    #
    # This used to be guarded here, by hand, and only for twist_degree > 2
    # — which switched the guard off for exactly the two curves in the
    # corpus where it could fire. The census now lives beside the argument
    # in `core/claims/elimination.py` and is mirrored in the verifier, so
    # it holds for every degree and holds for a reader who never runs this
    # file.
    index2, used_points = settle_group_order(
        curve2, candidates, points_in_order(curve2, field2), r
    )
    order2 = candidates[index2]

    if published_order2 is not None and order2 != published_order2:
        raise ValueError("the settled G2 order differs from the published one")
    cofactor2 = order2 // r

    payload2 = {
        "field": {
            "p": canonical.as_str(p),
            "degree": canonical.as_str(twist_degree),
            "beta": canonical.as_str(beta % p),
        },
        "curve": {
            "a": [canonical.as_str(c % p) for c in twist_a],
            "b": [canonical.as_str(c % p) for c in twist_b],
        },
        "points": [
            {
                "x": [canonical.as_str(c) for c in field2.coefficients(point[0])],
                "y": [canonical.as_str(c) for c in field2.coefficients(point[1])],
            }
            for point in used_points
        ],
    }
    if xi is not None:
        # The tower's second parameter. Without it a reader cannot rebuild
        # the field, and every coefficient in the payload means something
        # else.
        payload2["field"]["xi"] = [canonical.as_str(c % p) for c in xi]

    bundle.add_claim(
        "g2.cardinality",
        {"n": canonical.as_str(order2)},
        "derive.order-elimination",
        payload2,
        # `curve.order.prime` is new here and it is not decoration: the
        # census that separates the twist from the base curve over the
        # extension reads r, and a handler that reads a claim rests on it
        # whether or not an edge says so.
        depends_on=(
            "field.characteristic",
            "curve.cardinality",
            "curve.order.prime",
        ),
    )
    # The cofactor's factorisation, when it is affordable.
    #
    # Recorded in the curve table rather than chosen at the command line,
    # for the reason every optional step is: bytes that depend on who ran
    # the build cannot be addressed by their hash. BLS24-315 sets it
    # because a 983-bit composite is not going to factor; the claim is
    # then absent, and a subgroup-security policy returns undecided rather
    # than a pass.
    asserts2 = {
        "n": canonical.as_str(r),
        "cofactor": canonical.as_str(cofactor2),
    }
    evidence2: dict = {}
    if not skip_g2_cofactor:
        progress("factoring the G2 cofactor")
        cofactor2_factors = _cofactor_factors(cofactor2, backend)
        asserts2["largest_prime_factor"] = canonical.as_str(
            _largest_prime_factor(cofactor2_factors)
        )
        evidence2 = {
            "factors": _factor_entries(
                cofactor2_factors, _chains_for(cofactor2_factors, backend, progress)
            )
        }

    bundle.add_claim(
        "g2.order",
        asserts2,
        "check.cofactor",
        evidence2,
        depends_on=("g2.cardinality", "curve.order.prime"),
    )

    # The twist relation, if the subject admits sextic twists at all.
    # Only j = 0 curves do, and both families here are j = 0; a future
    # curve with a != 0 simply carries no such claim, and the absence is
    # visible rather than papered over.
    # `g2.twist` names which of six classes the second group sits in, at
    # every degree the format reaches. It was confined to F_p^2 because
    # the six over F_p^4 are a different set and an unlabelled index would
    # have meant one thing for BLS12 and another for BLS24. The label is
    # the fix: the degree is asserted beside the class, so the index says
    # which set it indexes and BLS24 gets an answer instead of silence.
    if a == 0:
        progress("classifying the twist")
        try:
            index, _t2, v = classify(p, order, order2, twist_degree)
        except TwistError as exc:
            raise ValueError(f"twist classification failed: {exc}") from exc
        bundle.add_claim(
            "g2.twist",
            {
                "related": "sextic-twist",
                "class": canonical.as_str(index),
                # The degree is asserted, not left to convention. An index
                # into six classes says nothing until the field it indexes
                # is named, and the six over F_p^4 are not the six over
                # F_p^2.
                "degree": canonical.as_str(twist_degree),
            },
            "derive.twist-class",
            {"v": canonical.as_str(v), "index": canonical.as_str(index)},
            depends_on=(
                "field.characteristic",
                "curve.cardinality",
                "g2.cardinality",
            ),
        )

    bundle.validate()
    return bundle


def _report(bundle: Bundle, path: Path) -> None:
    counts = bundle.tier_counts()
    print(f"\nwritten:  {path}  ({path.stat().st_size} bytes)")
    print(f"digest:   {bundle.digest()}")
    print(f"claims:   {len(bundle.claims)}")
    print(f"  proved (A):     {counts['A']}")
    print(f"  derived (D):    {counts['D']}")
    print(f"  candidate (X):  {counts['X']}")
    print("\nNow check it with something that did not produce it:")
    print(f"  tools\\verify.bat {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a pairing-curve bundle.")
    parser.add_argument(
        "--curve", default="bls12-381",
        help=f"one of: {', '.join(KNOWN_PAIRING_CURVES)}",
    )
    parser.add_argument("--out", default="corpus", help="output directory")
    parser.add_argument("--gp", help="full path to gp.exe")
    parser.add_argument("--quiet", action="store_true", help="no progress lines")
    parser.add_argument(
        "--skip-twist",
        action="store_true",
        help="omit the quadratic twist claim; factoring it is the slow step",
    )
    args = parser.parse_args(argv)

    if args.curve not in KNOWN_PAIRING_CURVES:
        print(f"unknown curve: {args.curve}", file=sys.stderr)
        return 2
    params = KNOWN_PAIRING_CURVES[args.curve]

    def progress(message: str) -> None:
        if not args.quiet:
            print(f"  {message}...", flush=True)

    try:
        backend = GpBackend(GpConfig(exe=Path(args.gp) if args.gp else None))
        bundle = build_pairing_bundle(
            params["label"],
            params["p"],
            params["a"],
            params["b"],
            params["r"],
            params["beta"],
            params.get("family"),
            params.get("u"),
            params["twist_a"],
            params["twist_b"],
            backend,
            params.get("source"),
            progress,
            params.get("published_order"),
            params.get("embedding_degree"),
            args.skip_twist,
        )
    except (GpError, ValueError) as exc:
        print(f"FAIL  {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    path = write_bundle(bundle, Path(args.out), args.curve)
    _report(bundle, path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
