"""Tests for arithmetic in F_p^2 and on curves over it.

Run it directly:

    python tests\\test_fp2.py

It also collects under pytest, so the suite picks it up unchanged. There
are no fixtures for exactly that reason: the objects below are built once
at import, so the same functions work either way.

Two kinds of test live here, and the second matters more. The first checks
the field and group laws hold. The second checks that a wrong input is
*refused* rather than quietly producing a plausible number: a bad
factorisation, a point off the curve, a modulus that does not give a
field. Each of those would otherwise yield a witness the verifier could
not reject, because the certificate would be internally consistent and
simply wrong.

The small curve is enumerated in full, so an exact point order is compared
against a counted answer rather than another implementation of the same
idea.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.field.fp2 import CurveFp2, Fp2, Fp2Error
from core.field.order import OrderError, point_order

# -- BLS12-381, the curve this work exists for ----------------------

BLS_P = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
BLS_R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
BLS_H2 = 0x5D543A95414E7F1091D50792876A202CD91DE4547085ABAA68A205B2E5A7DDFA628F1CB4D9E82EF21537E293A6691AE1616EC6E786F0C70CF1C38E31C7238E5

BLS_G2 = (
    (
        0x024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8,
        0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E,
    ),
    (
        0x0CE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801,
        0x0606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE,
    ),
)

BLS_FIELD = Fp2(BLS_P, -1)                       # F_p[u] / (u^2 + 1)
BLS_CURVE = CurveFp2(BLS_FIELD, BLS_FIELD.zero, BLS_FIELD.element(4, 4))

# -- a field small enough to enumerate ------------------------------
# 103 = 3 mod 4, so -1 is a non-residue and u^2 + 1 stays irreducible.

SMALL_P = 103
SMALL_FIELD = Fp2(SMALL_P, -1)
SMALL_CURVE = CurveFp2(SMALL_FIELD, SMALL_FIELD.element(1), SMALL_FIELD.element(1))


def _enumerate_points():
    """Every affine point, found by trying every abscissa."""
    found = []
    for c1 in range(SMALL_P):
        for c0 in range(SMALL_P):
            x = (c0, c1)
            y = SMALL_CURVE.ordinate(x)
            if y is None:
                continue
            found.append((x, y))
            if not SMALL_FIELD.is_zero(y):
                found.append((x, SMALL_FIELD.neg(y)))
    return found


SMALL_POINTS = _enumerate_points()
SMALL_ORDER = len(SMALL_POINTS) + 1  # the affine points, plus infinity


def _factor(n):
    factors, d = [], 2
    while d * d <= n:
        if n % d == 0:
            e = 0
            while n % d == 0:
                n //= d
                e += 1
            factors.append((d, e))
        d += 1
    if n > 1:
        factors.append((n, 1))
    return factors


SMALL_FACTORS = _factor(SMALL_ORDER)


def _raises(exception, call, *args):
    """True if the call raised what it was supposed to raise."""
    try:
        call(*args)
    except exception:
        return True
    return False


# -- the field is a field -------------------------------------------


def test_residue_beta_is_refused():
    """u^2 - beta must be irreducible, or the quotient is not a field."""
    assert _raises(Fp2Error, Fp2, 103, 4)      # 4 = 2^2 is a square
    assert _raises(Fp2Error, Fp2, 101, -1)     # 101 = 1 mod 4, so -1 is a residue


def test_degenerate_moduli_are_refused():
    for p, beta in [(2, -1), (3, -1), (9, -1)]:
        assert _raises(Fp2Error, Fp2, p, beta)
    assert _raises(Fp2Error, Fp2, 103, 0)


def test_ring_laws():
    f = SMALL_FIELD
    a, b, c = f.element(7, 11), f.element(29, 2), f.element(0, 5)
    assert f.add(a, b) == f.add(b, a)
    assert f.mul(a, b) == f.mul(b, a)
    assert f.mul(a, f.mul(b, c)) == f.mul(f.mul(a, b), c)
    assert f.mul(a, f.add(b, c)) == f.add(f.mul(a, b), f.mul(a, c))
    assert f.sub(a, a) == f.zero
    assert f.mul(a, f.one) == a


def test_square_agrees_with_multiplication():
    f = SMALL_FIELD
    for c0 in range(0, SMALL_P, 7):
        for c1 in range(0, SMALL_P, 11):
            a = f.element(c0, c1)
            assert f.square(a) == f.mul(a, a)


def test_inverse_round_trips():
    f = SMALL_FIELD
    for c0 in range(0, SMALL_P, 5):
        for c1 in range(0, SMALL_P, 5):
            a = f.element(c0, c1)
            if f.is_zero(a):
                continue
            assert f.mul(a, f.inv(a)) == f.one


def test_zero_has_no_inverse():
    assert _raises(Fp2Error, SMALL_FIELD.inv, SMALL_FIELD.zero)


def test_frobenius_is_the_conjugate():
    """Raising to the p is the non-trivial automorphism, on a real modulus."""
    a = BLS_FIELD.element(0xDEADBEEF, 0xC0FFEE)
    assert BLS_FIELD.pow(a, BLS_P) == BLS_FIELD.conjugate(a)


def test_norm_is_multiplicative():
    f = SMALL_FIELD
    a, b = f.element(13, 40), f.element(77, 5)
    assert f.norm(f.mul(a, b)) == (f.norm(a) * f.norm(b)) % SMALL_P


def test_negative_exponent_inverts():
    f = SMALL_FIELD
    a = f.element(9, 4)
    assert f.pow(a, -3) == f.inv(f.pow(a, 3))


# -- square roots ----------------------------------------------------


def test_sqrt_round_trips_everywhere():
    """Every square must have a root, and the root must square back."""
    f = SMALL_FIELD
    for c0 in range(SMALL_P):
        for c1 in range(0, SMALL_P, 3):
            value = f.square(f.element(c0, c1))
            root = SMALL_CURVE._sqrt(value)
            assert root is not None
            assert f.square(root) == value


def test_sqrt_refuses_non_squares():
    f = SMALL_FIELD
    squares = {
        f.square(f.element(c0, c1))
        for c0 in range(SMALL_P)
        for c1 in range(SMALL_P)
    }
    tested = 0
    for c0 in range(0, SMALL_P, 9):
        for c1 in range(0, SMALL_P, 9):
            value = f.element(c0, c1)
            if value in squares:
                continue
            tested += 1
            assert SMALL_CURVE._sqrt(value) is None
    # Without this the test could pass having checked nothing at all.
    assert tested > 0, "the sample contained no non-squares"


# -- the group law ---------------------------------------------------


def test_singular_curve_is_refused():
    f = SMALL_FIELD
    assert _raises(Fp2Error, CurveFp2, f, f.zero, f.zero)  # 4a^3 + 27b^2 = 0


def test_group_axioms_on_every_point():
    for point in SMALL_POINTS:
        assert SMALL_CURVE.is_on_curve(point)
        assert SMALL_CURVE.add(point, None) == point
        assert SMALL_CURVE.add(point, SMALL_CURVE.negate(point)) is None
        assert SMALL_CURVE.add(point, point) == SMALL_CURVE.double(point)


def test_addition_is_commutative_and_associative():
    sample = SMALL_POINTS[:12]
    for a in sample:
        for b in sample:
            assert SMALL_CURVE.add(a, b) == SMALL_CURVE.add(b, a)
            for c in sample[:4]:
                left = SMALL_CURVE.add(SMALL_CURVE.add(a, b), c)
                right = SMALL_CURVE.add(a, SMALL_CURVE.add(b, c))
                assert left == right


def test_scalar_multiplication_matches_repeated_addition():
    point = SMALL_POINTS[0]
    running = None
    for k in range(40):
        assert SMALL_CURVE.multiply(point, k) == running
        running = SMALL_CURVE.add(running, point)


def test_negative_scalars():
    point = SMALL_POINTS[3]
    assert SMALL_CURVE.multiply(point, -5) == SMALL_CURVE.negate(
        SMALL_CURVE.multiply(point, 5)
    )


def test_group_order_annihilates_every_point():
    for point in SMALL_POINTS:
        assert SMALL_CURVE.multiply(point, SMALL_ORDER) is None


def test_counted_order_sits_in_the_hasse_window():
    """Sanity on the enumeration itself, over F_p^2 where q = p^2."""
    q = SMALL_P**2
    root = 2 * SMALL_P  # 2*sqrt(q), exact because q is a perfect square
    assert q + 1 - root <= SMALL_ORDER <= q + 1 + root


def test_point_search_is_deterministic():
    first = SMALL_CURVE.first_point()
    assert first == SMALL_CURVE.first_point()
    assert SMALL_CURVE.is_on_curve(first)


def test_ordinate_picks_the_same_root_twice():
    x = SMALL_FIELD.element(2, 3)
    y = SMALL_CURVE.ordinate(x)
    if y is not None:
        assert y == SMALL_CURVE.ordinate(x)


def test_off_curve_point_is_refused():
    x, y = SMALL_POINTS[0]
    bogus = (x, SMALL_FIELD.add(y, SMALL_FIELD.one))
    assert not SMALL_CURVE.is_on_curve(bogus)
    assert _raises(Fp2Error, SMALL_CURVE.require_on_curve, bogus)


# -- exact order of a point ------------------------------------------


def test_point_order_matches_a_counted_order():
    """The answer is checked against enumeration, not another formula."""
    for point in SMALL_POINTS[:20]:
        found = point_order(SMALL_CURVE, point, SMALL_ORDER, SMALL_FACTORS)
        assert SMALL_ORDER % found == 0
        assert SMALL_CURVE.multiply(point, found) is None
        # Nothing smaller works: stripping any prime breaks it.
        for prime, _ in SMALL_FACTORS:
            if found % prime == 0:
                assert SMALL_CURVE.multiply(point, found // prime) is not None


def test_point_order_refuses_a_wrong_factorisation():
    broken = [(SMALL_FACTORS[0][0], SMALL_FACTORS[0][1] + 1)] + list(SMALL_FACTORS[1:])
    assert _raises(
        OrderError, point_order, SMALL_CURVE, SMALL_POINTS[0], SMALL_ORDER, broken
    )


def test_point_order_refuses_a_wrong_group_order():
    """An order that does not annihilate the point is not the order."""
    wrong = SMALL_ORDER + 1
    assert _raises(
        OrderError, point_order, SMALL_CURVE, SMALL_POINTS[0], wrong, _factor(wrong)
    )


def test_point_order_refuses_junk_factors():
    junk = [(1, 1), (SMALL_ORDER, 1)]
    assert _raises(
        OrderError, point_order, SMALL_CURVE, SMALL_POINTS[0], SMALL_ORDER, junk
    )


# -- the real thing --------------------------------------------------


def test_bls12_381_generator_is_on_the_curve():
    assert BLS_CURVE.is_on_curve(BLS_G2)


def test_bls12_381_generator_has_order_r():
    assert BLS_CURVE.multiply(BLS_G2, BLS_R) is None
    assert BLS_CURVE.multiply(BLS_G2, 1) is not None


def test_bls12_381_group_order_annihilates_the_generator():
    assert BLS_CURVE.multiply(BLS_G2, BLS_H2 * BLS_R) is None


def test_bls12_381_cofactor_clearing_lands_in_the_subgroup():
    """h2 * P lands in the r-torsion for an arbitrary point, which is what
    cofactor clearing relies on in practice."""
    point = BLS_CURVE.first_point()
    cleared = BLS_CURVE.multiply(point, BLS_H2)
    assert BLS_CURVE.multiply(cleared, BLS_R) is None


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
            passed += 1
            print(f"ok    {name}")

    print()
    print(f"{passed} passed, {len(failed)} failed")
    for name, reason in failed:
        print(f"  {name}: {reason}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
