"""The orders a sextic twist can have, from the trace alone.

The gap this closes. A pairing bundle proves an order for a curve over
`F_p^n` and calls the claim `g2.cardinality`, but nothing in the document
tied that curve to the subject. A reader had to take the twist relation
from a standard — which is exactly the kind of thing this project exists
not to do.

The route out does not require computing an isogeny. For a curve with
`j = 0`, which every family here has, the orders of the six sextic twists
over `F_q` are determined by two integers: the trace `t2` and the `v`
from the decomposition `4q = t2^2 + 3v^2`. Enumerate the six, and if the
proved `#E'` is among them, then `#E'` is the order of *a* twist of the
subject. The relation stops being an appeal to a standard and becomes
arithmetic anyone can redo.

**Two preconditions, and both are refusals rather than assumptions.**

`a = 0`. Sextic twists exist only for `j = 0`, and a curve with `a != 0`
must be refused rather than skipped: silently producing nothing for the
one case the argument does not cover is how a gap turns into a false
impression of coverage. This module is handed numbers rather than curve
equations, so the check belongs to its callers; every caller makes it.

`q = 1 mod 3`. Six twist classes exist only then. Where `q = 2 mod 3` a
curve with `j = 0` is supersingular and has two classes rather than six,
so an enumeration of six would be an enumeration of the wrong set — and
an enumeration that need not contain the true order is what turns an
elimination argument from sound into worthless. Checked here, once, for
everyone downstream.

What this does **not** establish on its own, stated plainly because the
distinction is easy to lose. Matching an order proves the number is the
order of some sextic twist. It does not by itself prove the particular
curve written in the evidence is that twist — two curves can share an
order. `derive.order-elimination` closes that separately, by running the
elimination on the curve in question and by pinning which of the six the
survivor is; see `core/claims/elimination.py`.
"""

from __future__ import annotations

from math import isqrt

__all__ = ["TwistError", "trace_over_extension", "twist_candidates", "classify"]


class TwistError(ValueError):
    """The numbers do not admit the sextic-twist decomposition."""


def trace_over_extension(trace: int, p: int, degree: int) -> int:
    """The trace of Frobenius over `F_p^degree`, from the trace over `F_p`.

    Weil's recurrence: `t_0 = 2`, `t_1 = t`, and
    `t_n = t*t_(n-1) - p*t_(n-2)` thereafter. Exact integer arithmetic
    over a number the bundle already proves, so it costs nothing and
    generalises to any degree — which is the point, since degree 4 is
    where the witness argument runs out.

    One implementation, here. There used to be a second copy inside
    `twist_candidates`; a recurrence written twice is a second place for
    an off-by-one to hide, and this project has already spent a review
    cycle on a value read correctly in one branch and not in its twin.
    """
    if degree < 1:
        raise TwistError("the extension degree must be positive")
    previous, current = 2, trace          # t_0 = 2 by convention
    for _ in range(degree):
        previous, current = current, trace * current - p * previous
    return previous


def _exact_sqrt(value: int) -> int:
    """The square root, or a refusal. Never an approximation.

    `isqrt` floors, so the result is squared and compared. Accepting a
    floored root would let a near-square pass as a square and the whole
    enumeration would be built on a `v` that is not the right one.
    """
    if value < 0:
        raise TwistError("a negative number has no square root here")
    root = isqrt(value)
    if root * root != value:
        raise TwistError("4q - t2^2 over 3 is not a perfect square")
    return root


def twist_candidates(
    p: int, cardinality: int, degree: int = 2
) -> tuple[list[int], int, int]:
    """The six possible orders of a sextic twist over F_p^degree.

    Returns the candidates in a fixed order, with `t2` and `v`. The order
    is what the evidence indexes into, so it is part of the format:

        0: q + 1 - t2       <- the subject's own order over F_q
        1: q + 1 + t2
        2: q + 1 - (t2 + 3v)/2
        3: q + 1 + (t2 + 3v)/2
        4: q + 1 - (t2 - 3v)/2
        5: q + 1 + (t2 - 3v)/2

    Index 0 is not merely first: it is the order of the subject curve
    itself over the extension, which is a sextic twist of itself and is
    never the second group. `r` divides it, because `r` divides `#E(F_p)`
    which divides `#E(F_q)`, so a caller that filtered on divisibility
    alone would walk straight into it. Callers settling a G2 order rule
    it out by name.

    `v` is taken positive. It is determined only up to sign, and the set
    of six does not depend on which sign is chosen — but the *indices* do,
    so the sign is pinned rather than left to whoever implements this.
    """
    if degree < 2:
        raise TwistError("a twist enumeration needs an extension, not the base field")
    trace = p + 1 - cardinality
    t2 = trace_over_extension(trace, p, degree)
    q = p**degree

    # Six classes exist only when q = 1 mod 3. Otherwise a j = 0 curve is
    # supersingular over this field and has two, and an enumeration of six
    # would be an enumeration of a set the true order need not belong to.
    if q % 3 != 1:
        raise TwistError(
            "q is not 1 mod 3, so this field has two twist classes rather "
            "than six and the enumeration need not contain the order"
        )

    remainder_source = 4 * q - t2 * t2
    if remainder_source < 0:
        raise TwistError("t2 lies outside the Hasse bound for F_q")
    v_squared, remainder = divmod(remainder_source, 3)
    if remainder:
        raise TwistError("4q - t2^2 is not divisible by 3, so j is not 0")
    v = _exact_sqrt(v_squared)
    if v == 0:
        raise TwistError("v vanishes; the curve is supersingular or degenerate")

    candidates = [q + 1 - t2, q + 1 + t2]
    for combined in (t2 + 3 * v, t2 - 3 * v):
        # Halving has to be exact. An odd value here would mean the
        # decomposition is not the one these formulas describe.
        if combined % 2:
            raise TwistError("t2 +- 3v is odd, so the twist formulas do not apply")
        candidates += [q + 1 - combined // 2, q + 1 + combined // 2]
    return candidates, t2, v


def classify(
    p: int, cardinality: int, twist_order: int, degree: int = 2
) -> tuple[int, int, int]:
    """Which of the six the twist order is. Returns index, t2 and v.

    The degree is a parameter and the caller has to state it, because the
    six classes over F_p^4 are a different set from the six over F_p^2 and
    an index is meaningless until the set is named. It defaults to 2 only
    so that existing callers reading a degree-2 twist keep working; the
    bundle asserts the degree it used.
    """
    candidates, t2, v = twist_candidates(p, cardinality, degree)
    for index, value in enumerate(candidates):
        if value == twist_order:
            return index, t2, v
    raise TwistError(
        "the order is not that of any sextic twist of this curve"
    )
