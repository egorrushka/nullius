"""Tests for F_p arithmetic and for point-order evidence at degree 1.

Run it directly:

    python tests\\test_fp.py

The prime-field classes exist so one evidence kind covers both degrees.
That only pays off if the two fields really do present the same
interface, so the first group of tests checks exactly that, method by
method. The rest exercise the argument on curves whose cofactor is larger
than one, which is where the older order evidence could not reach.

secp256k1 has cofactor 1 and is here as a control: the generalised
evidence must handle the easy case too, and must agree with the order the
standard publishes.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.claims.point_order import (
    PointOrderError,
    build_point_order_evidence,
    find_witness,
    make_curve,
    make_field,
)
from core.field.fp import CurveFp, Fp, FpError
from core.field.fp2 import Fp2
from core.field.order import point_order

SECP_P = 2**256 - 2**32 - 977
SECP_N = 115792089237316195423570985008687907852837564279074904382605163141518161494337

# BLS12-381 over the prime field: #E = h1 * r, and h1 is not one.
BLS_P = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
BLS_R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
BLS_H1 = 76329603384216526031706109802092473003
BLS_G1_FACTORS = [
    (3, 1), (11, 2), (10177, 2), (859267, 2), (52437899, 2), (BLS_R, 1),
]

SMALL_P = 1009


def _raises(exception, call, *args, **kwargs):
    try:
        call(*args, **kwargs)
    except exception:
        return True
    return False


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


SMALL_FIELD = Fp(SMALL_P)
SMALL_CURVE = CurveFp(SMALL_FIELD, SMALL_FIELD.element(2), SMALL_FIELD.element(3))


def _count_small():
    total = 1
    for c0 in range(SMALL_P):
        y = SMALL_CURVE.ordinate((c0,))
        if y is None:
            continue
        total += 1 if SMALL_FIELD.is_zero(y) else 2
    return total


SMALL_ORDER = _count_small()


# -- the two fields present one interface ---------------------------


def test_both_fields_expose_the_same_names():
    """A missing method here means the generalisation is a lie."""
    shared = [
        "degree", "q", "hasse_window", "coefficients", "zero", "one",
        "element", "is_zero", "add", "sub", "neg", "mul", "scale",
        "square", "inv", "div", "pow",
    ]
    for name in shared:
        assert hasattr(Fp(103), name), name
        assert hasattr(Fp2(103, -1), name), name


def test_degrees_are_reported():
    assert Fp(103).degree == 1
    assert Fp2(103, -1).degree == 2


def test_field_sizes():
    assert Fp(103).q == 103
    assert Fp2(103, -1).q == 103**2


def test_prime_field_window_is_widened():
    """The root of p is not an integer, so the window must be widened."""
    low, high = Fp(103).hasse_window()
    assert low <= 103 + 1 - 20 and high >= 103 + 1 + 20


def test_extension_window_is_not_widened():
    low, high = Fp2(103, -1).hasse_window()
    assert high - low == 4 * 103


def test_prime_field_refuses_a_second_coefficient():
    assert _raises(FpError, Fp(103).element, 1, 5)
    assert Fp(103).element(1, 0) == (1,)


# -- ring laws -------------------------------------------------------


def test_ring_laws():
    f = SMALL_FIELD
    a, b, c = f.element(7), f.element(29), f.element(500)
    assert f.add(a, b) == f.add(b, a)
    assert f.mul(a, f.mul(b, c)) == f.mul(f.mul(a, b), c)
    assert f.mul(a, f.add(b, c)) == f.add(f.mul(a, b), f.mul(a, c))
    assert f.sub(a, a) == f.zero
    assert f.mul(a, f.one) == a


def test_inverse_round_trips():
    f = SMALL_FIELD
    for c0 in range(1, SMALL_P, 7):
        a = f.element(c0)
        assert f.mul(a, f.inv(a)) == f.one


def test_zero_has_no_inverse():
    assert _raises(FpError, SMALL_FIELD.inv, SMALL_FIELD.zero)


def test_singular_curve_is_refused():
    f = SMALL_FIELD
    assert _raises(FpError, CurveFp, f, f.zero, f.zero)


# -- the group law ---------------------------------------------------


def test_group_law_on_a_counted_curve():
    running = None
    point = SMALL_CURVE.first_point()
    for k in range(30):
        assert SMALL_CURVE.multiply(point, k) == running
        running = SMALL_CURVE.add(running, point)


def test_group_order_annihilates_a_point():
    point = SMALL_CURVE.first_point()
    assert SMALL_CURVE.multiply(point, SMALL_ORDER) is None


def test_counted_order_sits_in_the_window():
    low, high = SMALL_FIELD.hasse_window()
    assert low <= SMALL_ORDER <= high


def test_point_search_is_deterministic():
    assert SMALL_CURVE.first_point() == SMALL_CURVE.first_point()


# -- the field and curve factories ------------------------------------


def test_factory_refuses_beta_on_a_prime_field():
    assert _raises(PointOrderError, make_field, 103, 1, -1)


def test_factory_requires_beta_at_degree_two():
    assert _raises(PointOrderError, make_field, 103, 2, None)


def test_factory_refuses_an_unsupported_degree():
    assert _raises(PointOrderError, make_field, 103, 3, None)


def test_factory_refuses_a_wrong_coefficient_count():
    field = make_field(103, 1)
    assert _raises(PointOrderError, make_curve, field, (1, 0), (1,))


# -- degree 1 evidence, on a counted curve ---------------------------


def test_small_curve_order_is_pinned():
    factors = _factor(SMALL_ORDER)
    point, order = find_witness(SMALL_CURVE, SMALL_ORDER, factors)
    _, pinned = build_point_order_evidence(
        SMALL_P, 1, (2,), (3,), point, order, _factor(order)
    )
    assert pinned == SMALL_ORDER


def test_degree_one_payload_has_one_coefficient_per_value():
    factors = _factor(SMALL_ORDER)
    point, order = find_witness(SMALL_CURVE, SMALL_ORDER, factors)
    payload, _ = build_point_order_evidence(
        SMALL_P, 1, (2,), (3,), point, order, _factor(order)
    )
    assert payload["field"]["degree"] == "1"
    assert "beta" not in payload["field"]
    for section in ("curve", "point"):
        for coefficients in payload[section].values():
            assert len(coefficients) == 1


def test_degree_one_bytes_are_reproducible():
    factors = _factor(SMALL_ORDER)
    point, order = find_witness(SMALL_CURVE, SMALL_ORDER, factors)
    first, _ = build_point_order_evidence(
        SMALL_P, 1, (2,), (3,), point, order, _factor(order)
    )
    again, _ = build_point_order_evidence(
        SMALL_P, 1, (2,), (3,), point, order, _factor(order)
    )
    assert first == again


# -- real curves ------------------------------------------------------


def test_secp256k1_is_pinned_with_cofactor_one():
    """The control: the easy case must still work."""
    field = Fp(SECP_P)
    curve = CurveFp(field, field.zero, field.element(7))
    point, order = find_witness(curve, SECP_N, [(SECP_N, 1)])
    _, pinned = build_point_order_evidence(
        SECP_P, 1, (0,), (7,), point, order, [(order, 1)]
    )
    assert pinned == SECP_N


def test_bls12_381_g1_is_pinned_despite_a_cofactor():
    """The case the older evidence refused: the cofactor is not one."""
    group_order = BLS_H1 * BLS_R
    field = Fp(BLS_P)
    curve = CurveFp(field, field.zero, field.element(4))
    point, order = find_witness(curve, group_order, BLS_G1_FACTORS)
    factors = [(q, _exponent(order, q)) for q, _ in BLS_G1_FACTORS
               if order % q == 0]
    _, pinned = build_point_order_evidence(
        BLS_P, 1, (0,), (4,), point, order, factors
    )
    assert pinned == group_order
    assert group_order % BLS_R == 0
    assert group_order // BLS_R == BLS_H1


def _exponent(n, prime):
    e = 0
    while n % prime == 0:
        n //= prime
        e += 1
    return e


def test_bls12_381_g1_witness_beats_the_window():
    group_order = BLS_H1 * BLS_R
    field = Fp(BLS_P)
    curve = CurveFp(field, field.zero, field.element(4))
    _, order = find_witness(curve, group_order, BLS_G1_FACTORS)
    low, high = field.hasse_window()
    assert order > high - low


def test_a_small_order_witness_is_refused():
    """A point whose order does not beat the window pins nothing.

    Done on the counted curve, where a small-order point is easy to build
    and the whole group is known. Accepting such a witness would mean
    picking one of several admissible group orders silently, which is the
    failure this evidence exists to prevent.
    """
    factors = _factor(SMALL_ORDER)
    point, order = find_witness(SMALL_CURVE, SMALL_ORDER, factors)
    prime = factors[0][0]
    small = SMALL_CURVE.multiply(point, order // prime)
    assert point_order(SMALL_CURVE, small, SMALL_ORDER, factors) == prime

    low, high = SMALL_FIELD.hasse_window()
    assert prime < high - low          # the reason it cannot pin
    assert _raises(
        PointOrderError,
        build_point_order_evidence,
        SMALL_P, 1, (2,), (3,), small, prime, [(prime, 1)],
    )


def test_order_r_alone_still_pins_over_the_prime_field():
    """Worth stating: over F_p the subgroup order is already enough.

    r is about 2^255 against a window of about 2^193, so a point of order
    r pins the group order even though the cofactor is not one. That is
    why the prime-field side needs no larger witness than G1 already has.
    """
    group_order = BLS_H1 * BLS_R
    field = Fp(BLS_P)
    curve = CurveFp(field, field.zero, field.element(4))
    point, order = find_witness(curve, group_order, BLS_G1_FACTORS)
    in_subgroup = curve.multiply(point, order // BLS_R)
    assert point_order(curve, in_subgroup, group_order, BLS_G1_FACTORS) == BLS_R
    _, pinned = build_point_order_evidence(
        BLS_P, 1, (0,), (4,), in_subgroup, BLS_R, [(BLS_R, 1)]
    )
    assert pinned == group_order


def _factor_from(factors, n):
    return [(q, _exponent(n, q)) for q, _ in factors if n % q == 0]


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
