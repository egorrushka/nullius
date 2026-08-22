"""PARI/GP calls that work over F_p^2.

A companion to :mod:`core.backends.gp` rather than more methods inside it.
That file is already near the size where it stops being readable in one
sitting, and a reader who wants to know what this project trusts a
subprocess with should be able to finish the file.

What this module does *not* do is as important as what it does. It does
not look for points, and it does not decide anything about the order of
one. Both are done in :mod:`core.field.fp2`, in Python we can read, for
one reason: asking gp for a witness and then asking gp whether the witness
is good would be circular. gp is allowed to propose a cardinality, and
nothing else.

The cardinality it proposes is a candidate, tier X, and stays one. The
bundle proves the order from a point instead, and if this number were
wrong the proof would fail rather than the error becoming a fact. The
Hasse check below is not evidence either; it is a tripwire that catches a
broken pipeline before it wastes an hour.
"""

from __future__ import annotations

from core.backends.gp import GpBackend, GpProtocolError, _check_int

__all__ = [
    "hasse_interval_fp2",
    "is_non_residue",
    "curve_cardinality_fp2",
]


def hasse_interval_fp2(p: int) -> tuple[int, int]:
    """Bounds on the number of points of a curve over F_p^2, inclusive.

    Exact, with no widening: the field has q = p^2 elements and its square
    root is p on the nose, so the bound is q + 1 -+ 2p with nothing
    rounded. Over a prime field the same expression needs a slack term
    because the square root is not an integer; here it does not.
    """
    q = p * p
    return q + 1 - 2 * p, q + 1 + 2 * p


def is_non_residue(beta: int, p: int) -> bool:
    """Whether u^2 - beta is irreducible over F_p, by Euler's criterion.

    Checked here as well as in the field class. Handing a reducible
    modulus to gp produces an error deep inside ffgen, and a clear refusal
    beforehand is worth the duplicated line.
    """
    beta %= p
    if beta == 0:
        return False
    return pow(beta, (p - 1) // 2, p) == p - 1


def curve_cardinality_fp2(
    backend: GpBackend,
    a: tuple[int, int],
    b: tuple[int, int],
    p: int,
    beta: int,
    timeout: float | None = None,
) -> int:
    """Candidate order of y^2 = x^3 + ax + b over F_p[u]/(u^2 - beta).

    ``a`` and ``b`` are pairs ``(c0, c1)`` meaning ``c0 + c1*u``, the same
    representation :mod:`core.field.fp2` uses.

    The returned number is a candidate. It is what a program said when
    asked, which is the whole of its standing.
    """
    p = _check_int("p", p)
    beta = _check_int("beta", beta)
    if p < 5:
        raise ValueError("this backend expects a prime p > 3")
    if not is_non_residue(beta, p):
        raise ValueError(
            "beta is a quadratic residue mod p, so u^2 - beta factors and the "
            "quotient is not a field"
        )

    a0, a1 = (_check_int("a0", a[0]) % p, _check_int("a1", a[1]) % p)
    b0, b1 = (_check_int("b0", b[0]) % p, _check_int("b1", b[1]) % p)
    beta %= p

    # zg generates F_p^2 as a root of zu^2 - beta. Multiplying an integer
    # by zg^0 lifts it into the field, so ellinit sees field elements
    # rather than a mix of integers and field elements.
    setup = [
        f"zt = Mod(1, {p}) * (zu^2 - {beta})",
        "zg = ffgen(zt, 'zu)",
        f"zE = ellinit([{a0}*zg^0 + {a1}*zg, {b0}*zg^0 + {b1}*zg])",
    ]
    (card,) = backend.eval_ints(["ellcard(zE)"], setup=setup, timeout=timeout)

    low, high = hasse_interval_fp2(p)
    if not low <= card <= high:
        raise GpProtocolError(
            "cardinality outside the Hasse interval for F_p^2; the backend is "
            "lying or misconfigured"
        )
    return card
