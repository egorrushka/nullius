"""Curves written in a model other than short Weierstrass.

Curve25519 is a Montgomery curve and Ed25519 a twisted Edwards one, and
between them they carry a large share of the world's signatures and key
agreement. Neither is in short Weierstrass form, which is the only shape
the rest of this project speaks.

The obvious response — quietly convert and certify the Weierstrass
version — would produce a certificate whose subject is a curve nobody
uses, under a name everybody recognises. That is the failure this project
exists to avoid, so the conversion becomes a claim of its own.

**What is proved.** The Weierstrass coefficients stated in the subject
are the ones the model's parameters give, by exact arithmetic in the
field. That is all: the map is a standard birational equivalence, and the
verifier recomputes both coefficients rather than trusting either.

**What is not.** The equivalence itself is not proved here, only applied.
That the map takes points of one curve to points of the other is a
theorem about the shapes, not a fact about these numbers, and this format
does not carry proofs of theorems. A reader takes it from the literature
in the same way they take the Hasse bound. The distinction is worth
keeping because the two models' groups are isomorphic *up to* a handful
of exceptional points, and cofactors are exactly where that matters.

The maps, for the record:

    Montgomery      B y^2 = x^3 + A x^2 + x
                    a = (3 - A^2) / (3 B^2)
                    b = (2 A^3 - 9 A) / (27 B^3)

    twisted Edwards a_e x^2 + y^2 = 1 + d x^2 y^2
                    A = 2 (a_e + d) / (a_e - d)
                    B = 4 / (a_e - d)
                    then as above

Every division is modular inverse in F_p and every denominator is checked
non-zero, because a zero there means the parameters describe no curve at
all rather than a curve with an awkward coefficient.
"""

from __future__ import annotations

__all__ = ["ModelError", "MODELS", "to_weierstrass", "montgomery_from_edwards"]


class ModelError(ValueError):
    """The parameters do not describe a curve in this model."""


MODELS = ("short-weierstrass", "montgomery", "twisted-edwards")


def _inverse(value: int, p: int, what: str) -> int:
    """A modular inverse, or a refusal naming what vanished.

    A zero denominator is not an edge case to route around: it means the
    parameters are degenerate, and saying which one went to zero is worth
    more than a generic failure.
    """
    if value % p == 0:
        raise ModelError(f"{what} is zero, so these parameters describe no curve")
    return pow(value % p, -1, p)


def montgomery_from_edwards(a_e: int, d: int, p: int) -> tuple[int, int]:
    """The Montgomery parameters A and B of a twisted Edwards curve."""
    a_e, d = a_e % p, d % p
    if a_e == d:
        raise ModelError("a and d coincide, so the Edwards curve is singular")
    if d == 0:
        raise ModelError("d is zero, so the curve is not an Edwards curve")
    difference = _inverse(a_e - d, p, "a - d")
    A = 2 * (a_e + d) % p * difference % p
    B = 4 * difference % p
    return A, B


def to_weierstrass(model: str, params: dict[str, int], p: int) -> tuple[int, int]:
    """The short Weierstrass coefficients this model's parameters give.

    Returns (a, b) reduced mod p. Raises if the parameters are degenerate
    in a way that means there is no curve to convert.
    """
    if model == "short-weierstrass":
        return params["a"] % p, params["b"] % p

    if model == "twisted-edwards":
        A, B = montgomery_from_edwards(params["a"], params["d"], p)
    elif model == "montgomery":
        A, B = params["A"] % p, params.get("B", 1) % p
        if B == 0:
            raise ModelError("B is zero, so the curve equation is degenerate")
        # A^2 = 4 would make x^3 + A x^2 + x factor with a repeated root.
        if (A * A - 4) % p == 0:
            raise ModelError("A^2 = 4, so the Montgomery curve is singular")
    else:
        raise ModelError(f"unknown curve model: {model!r}")

    b_squared = B * B % p
    a = (3 - A * A) % p * _inverse(3 * b_squared, p, "3B^2") % p
    b = (2 * pow(A, 3, p) - 9 * A) % p * _inverse(27 * pow(B, 3, p), p, "27B^3") % p
    return a, b
