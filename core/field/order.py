"""The exact order of a point, from a factorisation of the group order.

Kept apart from any one field because the argument does not depend on the
field: it needs a group law and an identity, nothing else. The same
function therefore serves a curve over F_p and one over F_p^2, which is
the point of generalising the evidence to both.
"""

from __future__ import annotations

__all__ = ["point_order", "OrderError"]


class OrderError(ValueError):
    """The factorisation or the point does not support the claimed order."""


def point_order(
    curve, point, group_order: int, factors: list[tuple[int, int]]
) -> int:
    """The exact order of a point, given a factorisation of the group order.

    Start from the group order and strip each prime as far as the point
    allows. This is the same argument the bundle carries: the caller can
    hand the result, the factorisation and the point to a verifier, which
    re-establishes the order without ever trusting how it was found.

    The factorisation is checked against ``group_order`` before use. A
    factor list that does not multiply back would silently produce a
    divisor of the true order, which is exactly the kind of quiet wrongness
    this project exists to refuse.
    """
    product = 1
    limit = group_order.bit_length() + 1
    for prime, exponent in factors:
        if prime < 2 or exponent < 1:
            raise OrderError("a factor entry is not a prime power")
        # Refuse before computing the power. bits(p^e) >= e*(bits(p)-1)+1,
        # so once this product passes the target's size the power cannot
        # divide it, and an honest factorisation is never refused. Without
        # the check, `prime=2, exponent=4e9` allocates half a gigabyte on
        # the way to discovering the entry was nonsense.
        # e*(bits(p) - 1) + 1 is the true lower bound on bits(p^e). The
        # obvious bits(p)*e overestimates, and for p = 2 it overestimates
        # by enough to refuse an honest cofactor of 8 — which is every
        # Edwards curve. A guard that rejects ordinary input is worse than
        # none.
        if exponent * (prime.bit_length() - 1) + 1 > limit:
            raise OrderError(
                "a factor entry exceeds the number it claims to divide"
            )
        product *= prime**exponent
        if product.bit_length() > limit:
            raise OrderError(
                "the factors already exceed the number they claim to "
                "multiply to"
            )
    if product != group_order:
        raise OrderError("the factors do not multiply back to the group order")

    if curve.multiply(point, group_order) is not None:
        raise OrderError(
            "the group order does not annihilate the point, so it is not the "
            "order of a group containing it"
        )

    order = group_order
    for prime, _exponent in factors:
        while order % prime == 0 and curve.multiply(point, order // prime) is None:
            order //= prime
    return order
