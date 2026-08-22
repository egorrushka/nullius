"""Evidence that pins the order of a curve group over F_p^2.

The problem this solves. Over a prime field the project proves a group
order by exhibiting a point of prime order n and observing that the Hasse
window holds no other multiple of n. That argument needs n to be larger
than the window, and for G2 of a pairing-friendly curve it is not: the
subgroup order r is around 2^255 while the window over F_p^2 is around
4p, some 2^383 wide. A point of order r says only that r divides the
group order.

The fix is not a weaker claim but a bigger witness. Take a point whose
*exact* order m exceeds the window, prove the order exactly from a
factorisation of m, and the group order is then the one multiple of m the
window admits. For BLS12-381 the available m runs past 2^700, so the
window admits exactly one and the claim stands at tier A.

The payload assembled here is deliberately everything a checker needs and
nothing more:

    field    beta, so the checker can rebuild F_p[u]/(u^2 - beta)
    curve    the coefficients, as pairs
    point    the witness, as two pairs
    order    m, the exact order of that point
    factors  the complete factorisation of m, with chains where needed

What is *not* in it is how m was found. That is the point of the format:
the argument stands on its own, and a reader never has to trust the search
that produced it.

Everything written here is re-checked here before it is returned. A
producer that emits a payload it did not verify is a producer that emits
certificates nobody should read.
"""

from __future__ import annotations

from typing import Any

from core.bundle import canonical
from core.field.fp import CurveFp, Fp
from core.field.fp2 import CurveFp2, Fp2
from core.field.order import OrderError, point_order

__all__ = [
    "EVIDENCE_TYPE",
    "make_field",
    "make_curve",
    "CLAIM_TYPE",
    "PointOrderError",
    "unique_multiple_in_window",
    "find_witness",
    "build_point_order_evidence",
]

EVIDENCE_TYPE = "proof.point-order"
# The claim this evidence supports. One, now: `proof.point-order` is
# confined to the base field and to the subject's own curve, and group
# orders over an extension are settled by `derive.order-elimination`.
#
# This constant said `g2.cardinality` long after the producer had stopped
# attaching it there — the pairing builder has used it for
# `curve.cardinality` since elimination arrived. A constant naming the
# wrong claim is the same defect as a handler reading the wrong one, minus
# the consequences.
CLAIM_TYPE = "curve.cardinality"


def make_field(
    p: int,
    degree: int,
    beta: int | None = None,
    xi: tuple[int, int] | None = None,
):
    """The field of the given degree, or a refusal.

    Degree is explicit rather than inferred from whether beta was passed:
    a caller that forgets beta should get an error, not a silently
    different field.
    """
    if degree == 1:
        if beta is not None:
            raise PointOrderError("a prime field takes no beta")
        return Fp(p)
    if degree == 2:
        if beta is None:
            raise PointOrderError("an extension of degree 2 needs a beta")
        if xi is not None:
            raise PointOrderError("a degree 2 extension takes no xi")
        return Fp2(p, beta)
    if degree == 4:
        # A tower, so it needs both parameters: F_p^2 = F_p[u]/(u^2 - beta)
        # and then F_p^4 = F_p^2[v]/(v^2 - xi), with xi an element of the
        # first extension rather than an integer.
        if beta is None or xi is None:
            raise PointOrderError(
                "an extension of degree 4 needs both a beta and an xi"
            )
        from core.field.fp4 import Fp4

        return Fp4(p, beta, xi)
    raise PointOrderError(f"unsupported extension degree: {degree}")


def make_curve(field, a: tuple[int, ...], b: tuple[int, ...]):
    """The curve over that field, with coefficients as coefficient lists."""
    if len(a) != field.degree or len(b) != field.degree:
        raise PointOrderError(
            f"a curve over a degree {field.degree} field needs "
            f"{field.degree} coefficient(s) per parameter"
        )
    if field.degree == 1:
        cls = CurveFp
    elif field.degree == 2:
        cls = CurveFp2
    else:
        from core.field.fp4 import CurveFp4

        cls = CurveFp4
    return cls(field, field.element(*a), field.element(*b))


class PointOrderError(ValueError):
    """The witness does not establish what it is supposed to establish."""


def unique_multiple_in_window(order: int, low: int, high: int) -> int:
    """The only multiple of ``order`` inside [low, high].

    This is where the argument actually lands. If more than one multiple
    fits, the witness is too small and the group order is not pinned; the
    refusal is loud because a silent pick of the nearest candidate would
    look identical in the output and mean nothing.
    """
    if order <= 0:
        raise PointOrderError("the order must be positive")
    # A window whose floor is not positive admits zero as a multiple of
    # anything, and zero would then be pinned as a group order. For a real
    # curve the floor is q + 1 - 2*sqrt(q) > 0 whenever p >= 5, so this is
    # unreachable — but an invariant is worth more than an argument that
    # it is unreachable, and the verifier refuses here too, in the same
    # words.
    if low <= 0:
        raise PointOrderError(
            "the Hasse window must be positive; a non-positive floor admits "
            "zero as a multiple"
        )
    first = -(-low // order)  # ceiling division, exact on integers
    last = high // order
    if first > last:
        raise PointOrderError(
            "no multiple of the witness order lies in the Hasse window"
        )
    if first != last:
        raise PointOrderError(
            f"{last - first + 1} multiples of the witness order fit the Hasse "
            "window, so the group order is not pinned down; a larger witness "
            "is needed"
        )
    return first * order


def find_witness(
    curve,
    group_order: int,
    factors: list[tuple[int, int]],
    limit: int = 200,
) -> tuple[tuple[tuple[int, ...], tuple[int, ...]], int]:
    """A point whose exact order pins the group order, and that order.

    Not every point will do, and that is the whole difficulty. A point of
    small order proves only that its order divides the group order, which
    the Hasse window cannot narrow to one candidate. So abscissas are
    tried in a fixed order until one yields a point large enough, and the
    fixed order is what keeps two runs producing identical bytes.

    Most curves give a usable point immediately: a random point of a group
    with a large cyclic factor almost always has close to full order. The
    search exists for the cases that do not, and for the guarantee that
    when it succeeds it succeeds the same way twice.
    """
    field = curve.field
    low, high = field.hasse_window()

    for c1 in range(limit if field.degree == 2 else 1):
        for c0 in range(limit):
            if c0 == 0 and c1 == 0:
                continue
            x = field.element(c0, c1) if field.degree == 2 else field.element(c0)
            y = curve.ordinate(x)
            if y is None:
                continue
            point = (x, y)
            try:
                order = point_order(curve, point, group_order, factors)
            except (OrderError, ValueError) as exc:
                raise PointOrderError(str(exc)) from exc
            try:
                unique_multiple_in_window(order, low, high)
            except PointOrderError:
                continue  # too small to pin anything; try the next abscissa
            return point, order

    raise PointOrderError(
        "no point of sufficient order was found in the searched range; the "
        "group may have no cyclic factor larger than the Hasse window"
    )


def build_point_order_evidence(
    p: int,
    degree: int,
    a: tuple[int, ...],
    b: tuple[int, ...],
    point: tuple[tuple[int, ...], tuple[int, ...]],
    order: int,
    factors: list[tuple[int, int]],
    beta: int | None = None,
    chains: dict[int, list[dict[str, int]]] | None = None,
) -> tuple[dict[str, Any], int]:
    """Assemble the evidence and the group order it establishes.

    Returns the payload and the pinned group order. Raises if the witness
    does not do the job, which is the only useful behaviour: an evidence
    payload that does not prove its claim is worse than none, because it
    looks like proof.

    ``chains`` carries an Atkin-Morain certificate for each factor the
    verifier cannot settle by itself. Factors below the verifier's own
    bound need none and carry none.

    The degree is still a parameter and the arithmetic still works over an
    extension, because that arithmetic is worth testing. What changed is
    where the result may be *used*: `proof.point-order` supports only
    `curve.cardinality`, over the base field, on the subject's own curve.
    A payload built here at degree 2 has no claim it can be attached to,
    and `Bundle.validate` refuses the attempt.
    """
    field = make_field(p, degree, beta)   # refuses a reducible modulus
    curve = make_curve(field, a, b)

    if len(point) != 2 or any(len(c) != degree for c in point):
        raise PointOrderError(
            f"a point over a degree {degree} field needs {degree} "
            "coefficient(s) per coordinate"
        )
    witness = (field.element(*point[0]), field.element(*point[1]))
    if tuple(tuple(c) for c in witness) != tuple(tuple(c) for c in point):
        raise PointOrderError("the point coordinates are not reduced mod p")
    curve.require_on_curve(witness)

    # The order is recomputed from the point and the factorisation rather
    # than taken on the caller's word. point_order also checks that the
    # factors multiply back, so a doctored list cannot slip through.
    try:
        recomputed = point_order(curve, witness, order, factors)
    except (OrderError, ValueError) as exc:
        raise PointOrderError(str(exc)) from exc
    if recomputed != order:
        raise PointOrderError(
            f"the point has order {recomputed}, not the {order} claimed"
        )

    low, high = field.hasse_window()
    group_order = unique_multiple_in_window(order, low, high)

    field_block: dict[str, Any] = {
        "p": canonical.as_str(p),
        "degree": canonical.as_str(degree),
    }
    if degree == 2:
        field_block["beta"] = canonical.as_str(beta % p)

    payload: dict[str, Any] = {
        "field": field_block,
        "curve": {
            "a": [canonical.as_str(c % p) for c in a],
            "b": [canonical.as_str(c % p) for c in b],
        },
        "point": {
            "x": [canonical.as_str(c) for c in witness[0]],
            "y": [canonical.as_str(c) for c in witness[1]],
        },
        "order": canonical.as_str(order),
        "factors": _factor_entries(factors, chains or {}),
    }
    return payload, group_order


def _factor_entries(
    factors: list[tuple[int, int]], chains: dict[int, list[dict[str, int]]]
) -> list[dict[str, Any]]:
    """Factors in canonical form, each with a chain when one was supplied.

    Sorted by the prime, so two runs that found the factors in a different
    order still produce identical bytes.
    """
    entries: list[dict[str, Any]] = []
    for prime, exponent in sorted(factors):
        entry: dict[str, Any] = {
            "prime": canonical.as_str(prime),
            "exponent": canonical.as_str(exponent),
        }
        chain = chains.get(prime)
        if chain is not None:
            entry["steps"] = [
                {key: canonical.as_str(value) for key, value in step.items()}
                for step in chain
            ]
        entries.append(entry)
    return entries
