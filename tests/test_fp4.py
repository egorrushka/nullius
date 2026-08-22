"""Tests for degree-4 extensions, and for the curve that needed them.

Run it directly:

    python tests\\test_fp4.py

BLS24-315 was recorded as unreachable and the reason was arithmetic
rather than effort: its second group has a 1005-bit cofactor whose
composite part is 983 bits, and `proof.point-order` needs exactly that
factorisation. The elimination argument needs none, so the curve became
reachable the moment `F_p^4` existed.

The field tests run over a small prime, where an exhaustive-ish sample
says something. The curve tests run over the real one, where the only
thing worth asserting is that two independent routes agree: the order
settled by elimination against the order implied by Weil's recurrence,
and the family polynomials against the published parameters.

One trap is tested by name because it cost an hour and would cost anyone
else the same: **every element of `F_p` is a square in `F_p^4`**, so a
non-residue cannot be found among the integers. A search that scans
constants does not fail — it runs out, silently, and returns nothing.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.claims.elimination import (
    eliminate,
    points_in_order,
    trace_over_extension,
)
from core.claims.family import derive
from core.claims.twist import twist_candidates
from core.field.fp4 import CurveFp4, Fp4, Fp4Error

ROOT = Path(__file__).resolve().parent.parent
SKIPPED = []

# A small field for the laws, and the real one for the curve.
SMALL_P = 1009
SMALL_BETA = 11
SMALL_XI = (0, 1)

U = -0xBFCFFFFF
R = U**8 - U**4 + 1
P = ((U - 1) ** 2 * R) // 3 + U


def _small():
    return Fp4(SMALL_P, SMALL_BETA, SMALL_XI)


def _raises(exception, call, *args, **kwargs):
    try:
        call(*args, **kwargs)
    except exception:
        return True
    return False


def _sample(field, count):
    """Deterministic pseudo-random elements. Seeded rather than random so
    a failure can be reproduced from the message alone."""
    import random

    generator = random.Random(20260814)
    for _ in range(count):
        yield field.element(*(generator.randrange(field.p) for _ in range(4)))


# -- the field is a field ---------------------------------------------


def test_the_ring_laws_hold():
    field = _small()
    values = list(_sample(field, 40))
    for a in values[:12]:
        for b in values[:12]:
            assert field.mul(a, b) == field.mul(b, a)
            for c in values[:4]:
                assert field.mul(a, field.mul(b, c)) == field.mul(field.mul(a, b), c)
                assert field.mul(a, field.add(b, c)) == field.add(
                    field.mul(a, b), field.mul(a, c)
                )


def test_every_non_zero_element_inverts():
    field = _small()
    for a in _sample(field, 60):
        if field.is_zero(a):
            continue
        assert field.mul(a, field.inv(a)) == field.one


def test_fermat_holds_at_the_right_order():
    """`a^(q-1) = 1` with `q = p^4`, which is the check that would fail if
    the multiplication were reducing modulo the wrong polynomial."""
    field = _small()
    assert field.q == SMALL_P**4
    for a in _sample(field, 20):
        if field.is_zero(a):
            continue
        assert field.pow(a, field.q - 1) == field.one


def test_a_square_xi_is_refused():
    """A residue makes the quotient a ring with zero divisors, and every
    order computed in it means nothing. The criterion is Euler's *in
    F_p^2*, which is stricter than being a non-residue in F_p."""
    field = _small()
    square = field.base.square(field.base.element(3, 5))
    assert _raises(Fp4Error, Fp4, SMALL_P, SMALL_BETA, (square[0], square[1]))
    assert _raises(Fp4Error, Fp4, SMALL_P, SMALL_BETA, (0, 0))


# -- square roots ------------------------------------------------------


def test_squares_have_roots_and_roots_square_back():
    field = _small()
    checked = 0
    for a in _sample(field, 60):
        root = field.sqrt(field.square(a))
        assert root is not None
        assert field.square(root) == field.square(a)
        checked += 1
    assert checked >= 50


def test_non_residues_have_none():
    field = _small()
    found = 0
    for a in _sample(field, 60):
        if field.is_square(a):
            continue
        assert field.sqrt(a) is None
        found += 1
    assert found > 0, "the sample contained no non-residues, so nothing was tested"


def test_prime_field_constants_are_all_squares():
    """The trap, tested by name.

    For `a` in `F_p*`, `a^((p^4-1)/2) = (a^(p-1))^((p^3+p^2+p+1)/2)`. Four
    odd terms sum to an even one, so the exponent is a whole number, and
    `a^(p-1)` is one. Every constant is therefore a square, and a
    non-residue search over the integers never succeeds — it does not
    fail, it runs out.
    """
    field = _small()
    for constant in range(1, 40):
        assert field.is_square(field.element(constant)), constant


def test_the_non_residue_search_looks_in_the_field():
    """Which is the only reason sqrt works at all here."""
    source = (ROOT / "core" / "field" / "fp4.py").read_text(encoding="utf-8")
    assert "self.element(c0, c1, 1)" in source


# -- the Hasse window --------------------------------------------------


def test_the_window_is_exact_at_degree_four():
    """`sqrt(p^4)` is `p^2` on the nose, so nothing is widened. The same
    piece of luck as degree 2, and the reason degree 3 would need care."""
    field = _small()
    low, high = field.hasse_window()
    assert high - low == 4 * SMALL_P**2
    assert low == field.q + 1 - 2 * SMALL_P**2


def test_the_window_is_far_wider_than_the_subgroup():
    """The fact that killed the witness argument.

    Over F_p^4 the window is about 2^631 wide while the subgroup order is
    253 bits, so a point of order r pins nothing: some 2^378 multiples of
    it fit. A witness large enough would need the group order's
    factorisation, and that is the 983-bit composite nobody is factoring.
    """
    field = Fp4(P, 13, (0, 1))
    low, high = field.hasse_window()
    width = (high - low).bit_length()
    assert width > 600
    assert width > 2 * R.bit_length()
    # And the subgroup is nowhere near closing it.
    assert R.bit_length() * 2 < width


# -- BLS24-315 ---------------------------------------------------------


def test_the_family_polynomials_give_the_published_parameters():
    p, r, t = derive("bls24", U)
    assert p == P
    assert r == R
    assert t == U + 1


def test_the_elimination_settles_the_second_group():
    """The whole point. One point, six candidates, five eliminated, and
    not a single factorisation of a 983-bit composite."""
    field = Fp4(P, 13, (0, 1))
    curve = CurveFp4(field, field.zero, field.element(0, 1, 2, 0))
    cardinality = P + 1 - (U + 1)
    candidates, _t, _v = twist_candidates(P, cardinality, 4)
    index, used = eliminate(curve, candidates, points_in_order(curve, field))
    order = candidates[index]
    assert order % R == 0
    assert len(used) == 1
    assert (order // R).bit_length() == 1005


def test_two_candidates_divide_r_and_only_one_is_the_second_group():
    """The trap a producer must not fall into.

    `r` divides `#E(F_p)`, which divides `#E(F_p^4)`, so the base curve
    extended to the larger field is itself a candidate divisible by `r`.
    It is not G2 — the pairing needs the eigenvalue-p subgroup, which
    lives on the twist. Filtering candidates on divisibility alone would
    certify the wrong group with every step of the argument intact.
    """
    cardinality = P + 1 - (U + 1)
    candidates, _t, _v = twist_candidates(P, cardinality, 4)
    divisible = [i for i, c in enumerate(candidates) if c % R == 0]
    assert len(divisible) == 2

    field = Fp4(P, 13, (0, 1))
    base = CurveFp4(field, field.zero, field.element(1))
    twist = CurveFp4(field, field.zero, field.element(0, 1, 2, 0))
    base_index, _ = eliminate(base, candidates, points_in_order(base, field))
    twist_index, _ = eliminate(twist, candidates, points_in_order(twist, field))
    assert base_index in divisible
    assert twist_index in divisible
    assert base_index != twist_index


def test_the_weil_recurrence_agrees_with_the_direct_formula():
    """At degree 2 the recurrence must collapse to `t^2 - 2p`, or the
    generalisation changed the curves that already worked."""
    trace = U + 1
    assert trace_over_extension(trace, P, 2) == trace * trace - 2 * P
    for degree in (2, 3, 4):
        _c, stated, _v = twist_candidates(P, P + 1 - trace, degree)
        assert stated == trace_over_extension(trace, P, degree)


def test_the_candidates_stay_inside_the_window():
    """A candidate outside the Hasse bound could not be a group order, so
    its presence would mean the enumeration is wrong."""
    field = Fp4(P, 13, (0, 1))
    low, high = field.hasse_window()
    candidates, _t, _v = twist_candidates(P, P + 1 - (U + 1), 4)
    assert len(set(candidates)) == 6
    for candidate in candidates:
        assert low <= candidate <= high


# -- standalone runner ------------------------------------------------


def main():
    tests = [
        (name, fn)
        for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn)
    ]
    passed, failed = 0, []
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # report every failure, do not stop at the first
            failed.append((name, f"{type(exc).__name__}: {exc}"))
            print(f"FAIL  {name}")
        else:
            if name in SKIPPED:
                print(f"skip  {name}")
            else:
                passed += 1
                print(f"ok    {name}")

    print()
    print(f"{passed} passed, {len(failed)} failed, {len(SKIPPED)} skipped")
    for name, reason in failed:
        print(f"  {name}: {reason}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
