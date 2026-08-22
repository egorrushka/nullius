"""Membership in a pairing-friendly family, from a single parameter.

BLS12 and BN curves are not chosen; they are generated. One integer `u`
determines the characteristic, the subgroup order and the trace, through
polynomials fixed by the family. That makes the whole parameter set
checkable from one number, which is worth more here than it sounds.

Three things follow from a family claim that nothing else in the format
supplies for these curves:

**Rigidity.** Prime-field curves in this corpus can say where their
parameters came from — P-256 derives its `b` from a published seed, and
`check.seed-derivation` re-runs it. A pairing curve has no such claim, so
"why these numbers and not others" was answerable only by pointing at a
standard. A family claim answers it arithmetically: these numbers are the
ones the family produces at this `u`, and there was no freedom left to
abuse.

**The embedding degree.** k = 12 is a property of both families rather
than a fact about a particular curve, so a family claim and the
independently computed `curve.embedding` check each other.

**A footing for the twist relation.** Inside a family the twist is fixed
by construction, which is the route out of the gap the format currently
admits.

The polynomials are stated once, here, and used by both the producer and
the tests. The verifier holds its own copy in Rust, which is the point of
having two implementations.
"""

from __future__ import annotations

__all__ = ["FAMILIES", "FamilyError", "derive", "check_against"]


class FamilyError(ValueError):
    """The parameter does not generate the curve it is claimed to."""


def _bls12(u: int) -> tuple[int, int, int]:
    """p, r, t for BLS12 at parameter u.

    r = u^4 - u^2 + 1
    t = u + 1
    p = (u - 1)^2 * r / 3 + u

    The division by three has to be exact. Python's floor division would
    quietly produce a number for a `u` that generates nothing, and the
    result would look like a characteristic. Not every integer is a valid
    BLS12 parameter, and this is where most invalid ones are caught.
    """
    r = u**4 - u**2 + 1
    numerator = (u - 1) ** 2 * r
    quotient, remainder = divmod(numerator, 3)
    if remainder:
        raise FamilyError(
            "(u - 1)^2 * r is not divisible by 3, so u generates no BLS12 curve"
        )
    return quotient + u, r, u + 1


def _bls24(u: int) -> tuple[int, int, int]:
    """p, r, t for BLS24 at parameter u.

    r = u^8 - u^4 + 1
    t = u + 1
    p = (u - 1)^2 * r / 3 + u

    The same shape as BLS12 with the cyclotomic polynomial one step
    further along, and the same exact division by three: a floor division
    would hand back a number for a u that generates nothing, and that
    number would look exactly like a characteristic.
    """
    r = u**8 - u**4 + 1
    numerator = (u - 1) ** 2 * r
    quotient, remainder = divmod(numerator, 3)
    if remainder:
        raise FamilyError(
            "(u - 1)^2 * r is not divisible by 3, so u generates no BLS24 curve"
        )
    return quotient + u, r, u + 1


def _bn(u: int) -> tuple[int, int, int]:
    """p, r, t for BN at parameter u.

    p = 36u^4 + 36u^3 + 24u^2 + 6u + 1
    r = 36u^4 + 36u^3 + 18u^2 + 6u + 1
    t = 6u^2 + 1

    No divisions, so any integer produces a candidate triple; whether it
    is a curve is decided by p and r being prime, which other claims
    establish.
    """
    return (
        36 * u**4 + 36 * u**3 + 24 * u**2 + 6 * u + 1,
        36 * u**4 + 36 * u**3 + 18 * u**2 + 6 * u + 1,
        6 * u**2 + 1,
    )


# Closed on purpose. An unknown name is a refusal rather than a claim
# nobody can check: a verifier that skipped families it did not recognise
# would let a bundle assert membership in anything.
FAMILIES = {
    "bls12": (_bls12, 12),
    "bls24": (_bls24, 24),
    "bn": (_bn, 12),
}


def derive(family: str, u: int) -> tuple[int, int, int]:
    """The characteristic, subgroup order and trace at this parameter."""
    if family not in FAMILIES:
        raise FamilyError(f"unknown family: {family!r}")
    polynomials, _degree = FAMILIES[family]
    p, r, t = polynomials(u)
    if p <= 0 or r <= 0:
        raise FamilyError("u generates a non-positive characteristic or order")
    return p, r, t


def check_against(
    family: str, u: int, p: int, r: int, cardinality: int
) -> tuple[int, int, int]:
    """Derive and compare against numbers other claims already establish.

    The trace is compared as `p + 1 - #E`, in signed arithmetic. Writing
    it as a subtraction of unsigned values would be a trap the day a
    family with a negative trace appears.
    """
    derived_p, derived_r, derived_t = derive(family, u)
    if derived_p != p:
        raise FamilyError("the family polynomial does not give this characteristic")
    if derived_r != r:
        raise FamilyError("the family polynomial does not give this subgroup order")
    if derived_t != p + 1 - cardinality:
        raise FamilyError("the family polynomial does not give this trace")
    return derived_p, derived_r, derived_t
