"""A group order settled by eliminating candidates rather than proving one.

`proof.point-order` establishes a group order by exhibiting a point whose
*exact* order exceeds the Hasse window, and proving an exact order needs
the group order's factorisation. That is a ceiling, not an inconvenience:
BLS24-315's second group has a 1005-bit cofactor whose unfactored part is
983 bits, and the record for numbers of that shape is 829 bits at
thousands of core-years. The 192-bit level sits entirely behind it.

The way past does not need a bigger computer. Turn the argument around.

A group order annihilates **every** point, so a point cannot prove which
candidate is right but can rule out those that are wrong. The sextic
twist enumeration already gives six candidates from the trace alone, by
exact arithmetic and no factorisation. Multiply a point by each; discard
every candidate that does not send it to the identity. The true order is
never discarded, because it annihilates everything. If exactly one
survives, it is the order — provably, not probably.

**What the argument rests on, and therefore what has to be checked.**

The conclusion is `#E' = the survivor`, and it follows from two premises
and nothing else: Lagrange, which needs no checking, and *the true order
is among the six*, which needs a great deal. The second premise holds
exactly when `E'` really is a sextic twist of the subject over `F_q`. It
is not a property of the argument, it is a property of the curve handed
to it, and a reviewer demonstrated what happens when nobody checks it: a
run on the subject's own curve over `F_p^2`, with two honestly found
points, singles out candidate 0 and would have been certified as the
second group's order.

So the premise is now established rather than assumed:

* the subject has `a = 0`, so it has sextic twists at all;
* `q = 1 mod 3`, so it has six of them (checked in `core.claims.twist`);
* the curve the points come from has `a' = 0` and is non-singular, so
  `b' != 0` — and over such a `q` every `y^2 = x^3 + b'` with `b' != 0`
  **is** one of the six sextic twists of `y^2 = x^3 + b`. That is the
  whole binding: it needs no isogeny and no appeal to a standard.

**Which twist, not merely which order.** Two of the six are divisible by
`r`. One is the subject's own order over the extension — `r` divides
`#E(F_p)` which divides `#E(F_q)` — and it is never the second group. If
exactly two are divisible, and one of them is index 0, then the other is
the only remaining class that can carry an `r`-torsion subgroup, and the
six being pairwise distinct makes the order determine the class. A
survivor equal to that candidate is therefore the order of the twist that
carries G2, and the curve in the evidence is that twist up to
`F_q`-isomorphism. Where the census does not come out at exactly two, the
producer refuses: the argument has not singled anything out.

**Four further conditions, and none of them is decoration.**

*The candidates must be pairwise distinct.* If two coincide, "exactly one
survived" counts a set that was never six, and the conclusion is about
arithmetic that did not happen.

*More than one survivor is not a choice.* It is a refusal, in the same
way `unique_multiple_in_window` refuses rather than picking the nearest
admissible multiple. Output indistinguishable from a proof is worse than
no output.

*Extra points are tried in a fixed order.* Determinism is the whole
format; a search that depended on timing would put different bytes in two
certificates for one curve.

*The producer multiplies the points itself.* The backend is asked for
nothing here, so there is nothing to take on trust.
"""

from __future__ import annotations

from core.claims.twist import trace_over_extension

__all__ = [
    "EliminationError",
    "eliminate",
    "settle_group_order",
    "points_in_order",
    "trace_over_extension",
]

# How many points to try before giving up.
#
# Six candidates and every recorded point must remove at least one, so
# five is the structural ceiling and this constant can only ever stop a
# search that was going nowhere. It is kept because `points_in_order` will
# happily walk its whole abscissa range on a curve where nothing decides,
# and a refusal a reader can act on beats a loop that runs until something
# happens.
MAX_POINTS = 8


class EliminationError(ValueError):
    """The candidates could not be narrowed to one."""


def points_in_order(curve, field, limit: int = 64):
    """Points of the curve, in the one order every producer will find.

    Abscissas are walked from zero as elements of the base field, and the
    ordinate routine picks the smaller of the two roots. Nothing here
    depends on timing, on hashing, or on which points happen to be
    cached, because two producers must write the same bytes and a search
    that wandered would put different points in two certificates for one
    curve.
    """
    for x in range(limit):
        candidate = field.element(x, 0) if hasattr(field, "beta") else field.element(x)
        ordinate = curve.ordinate(candidate)
        if ordinate is not None:
            yield (candidate, ordinate)


def eliminate(curve, candidates: list[int], points) -> tuple[int, list[int]]:
    """The one candidate every point admits, and the points that decided it.

    `curve` supplies `multiply(point, k)` and `is_on_curve(point)`;
    `points` is an iterable producing them in a fixed order. Returns the
    surviving candidate's index and the points actually consumed, so the
    evidence records the shortest argument rather than every point tried.

    **This is a search, and the verifier is a check. The difference is
    why a point that decides nothing is skipped here and refused there.**

    The rule of the format is that every point *in the evidence* must
    eliminate at least one candidate: padding in an argument is where a
    reader stops reading. That rule is about the record, not about the
    search that produced it. A producer walks abscissas in a fixed order
    and cannot know in advance which will decide anything, and refusing at
    the first that decides nothing would abandon arguments that close
    perfectly well one point later.

    That is not hypothetical. Over F_19 the curve `y^2 = x^3 + 17` has six
    distinct candidates, and the scan meets points at abscissas 2 and 3
    that rule nothing out before a later point closes the argument. A
    producer that refused at the first of them would report no certificate
    for a curve that has one — a liveness bug with no soundness gained,
    since the recorded evidence would have been identical either way.

    So the skip stays, and what the format requires is enforced where it
    belongs: `settle_group_order` replays the recorded points exactly as
    the verifier will, and refuses if any of them turns out to be padding.

    This is the elimination and nothing else. It does not know what the
    candidates are for, so it cannot check that the true order is among
    them; that is `settle_group_order`'s job, and calling this directly
    for a G2 order is how the hole this module documents was opened.
    """
    if len(candidates) != len(set(candidates)):
        raise EliminationError(
            "the candidate orders are not pairwise distinct, so surviving "
            "exactly one would count a set that was never that large"
        )
    if not candidates:
        raise EliminationError("there are no candidates to eliminate")

    surviving = set(range(len(candidates)))
    used = []

    for point in points:
        if len(used) >= MAX_POINTS:
            break
        if not curve.is_on_curve(point):
            raise EliminationError("a point offered for elimination is not on the curve")

        # Points of small order eliminate nothing and would pad the
        # evidence with steps that decide nothing, so only points that
        # actually narrow the set are recorded.
        killed = {
            index
            for index in surviving
            if curve.multiply(point, candidates[index]) is not None
        }
        if not killed:
            continue

        surviving -= killed
        used.append(point)

        if len(surviving) == 1:
            return next(iter(surviving)), used
        if not surviving:
            raise EliminationError(
                "every candidate was eliminated, so the enumeration does not "
                "contain the group order"
            )

    raise EliminationError(
        f"{len(surviving)} candidates survive after {len(used)} point(s); "
        "the order is not pinned down and must not be guessed"
    )


def _replay(curve, candidates: list[int], used, index: int) -> None:
    """Read the produced evidence the way the verifier will.

    Not a second opinion on the arithmetic — the same code just ran it.
    It is a check on the *record*: that every point kept eliminates
    something, that exactly one candidate is left standing, and that it is
    the one the producer is about to assert.

    The verifier refuses a point that decides nothing, and the search
    above skips one. Both are right for what they do, and the gap between
    them is exactly where a producer could write a document its own
    verifier rejects. Replaying closes it here rather than leaving it to
    be discovered by whoever runs `ccert-verify` on the result.
    """
    surviving = set(range(len(candidates)))
    for position, point in enumerate(used):
        killed = {
            i for i in surviving
            if curve.multiply(point, candidates[i]) is not None
        }
        if not killed:
            raise EliminationError(
                f"point {position} of the recorded argument eliminates "
                "nothing; the verifier refuses padding and so does this"
            )
        surviving -= killed
    if surviving != {index}:
        raise EliminationError(
            f"replaying the recorded points leaves {sorted(surviving)}, "
            f"not the single candidate {index} about to be asserted"
        )


def settle_group_order(
    curve, candidates: list[int], points, subgroup_order: int
) -> tuple[int, list[int]]:
    """The second group's order, bound to the subject rather than merely found.

    Everything `eliminate` does, plus the two things that make its
    conclusion mean what the claim name says. The mirror of this is
    `verifier/src/elimination.rs`; the two are written from the docstring
    at the top of this module rather than from each other, so a mistake in
    one has somewhere to show.

    The curve must have `a = 0`. With the subject's `a = 0` and
    `q = 1 mod 3` — both checked by the caller and by
    `core.claims.twist` — that is what makes the curve a sextic twist of
    the subject, and therefore what puts its order among the six. Without
    it the elimination is a true statement about a set that need not
    contain the answer.

    Then the census. Exactly two of the six may be divisible by
    `subgroup_order`; index 0 must be one of them, because it is the
    subject's own order over the extension and `r` divides that; and the
    survivor must be the other. Anything else is a refusal, because
    anything else means the argument did not single out the second group.
    """
    field = curve.field
    if not field.is_zero(curve.a):
        raise EliminationError(
            "the curve offered for elimination has a != 0, so it is not a "
            "sextic twist of the subject and its order need not be among "
            "the candidates"
        )
    if subgroup_order < 2:
        raise EliminationError("the subgroup order must exceed one")

    index, used = eliminate(curve, candidates, points)
    _replay(curve, candidates, used, index)

    divisible = [
        position
        for position, value in enumerate(candidates)
        if value % subgroup_order == 0
    ]
    if len(divisible) != 2:
        raise EliminationError(
            f"{len(divisible)} of the candidates are divisible by r, not two; "
            "the second group is not singled out by this enumeration"
        )
    if divisible[0] != 0:
        raise EliminationError(
            "r does not divide the subject's own order over the extension, "
            "which it must, so the candidates do not describe this curve"
        )
    if index != divisible[1]:
        if index == 0:
            raise EliminationError(
                "the elimination settled on the subject's own order over the "
                "extension rather than on the twist; check the twist parameters"
            )
        raise EliminationError(
            "the surviving candidate is not divisible by r, so it is not the "
            "order of a group containing the subgroup"
        )
    return index, used
