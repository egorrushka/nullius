"""Field and curve laws over F_p, F_p^2 and F_p^4, checked with Hypothesis.

The Rust side has `proptest_laws.rs`; this is its mirror on the producer.
The two implementations are written from one specification and meant to
agree, so the laws a field must satisfy are asserted on both, and a
formula that drifts on one side is caught where it drifts.

Field laws run over a small prime, because a formula is right or wrong
independently of the size of p and a small modulus buys far more cases.
Curve laws run the group law on real points, generated as multiples of a
deterministic base point so each one genuinely lies on the curve.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from core.field.fp import Fp, CurveFp
from core.field.fp2 import Fp2, CurveFp2
from core.field.fp4 import Fp4, CurveFp4

# A small prime, a non-residue in F_p for the quadratic step, and a
# non-residue in F_p^2 for the quartic step. The field constructors verify
# both by Euler's criterion, so a wrong choice here fails loudly at import.
P = 2_147_483_647  # 2^31 - 1
BETA = 3
XI = (2, 2)

FP = Fp(P)
FP2 = Fp2(P, BETA)
FP4 = Fp4(P, BETA, XI)

coeff = st.integers(min_value=0, max_value=P - 1)
fp_elem = coeff.map(lambda c0: FP.element(c0))
fp2_elem = st.tuples(coeff, coeff).map(lambda cs: FP2.element(*cs))
fp4_elem = st.tuples(coeff, coeff, coeff, coeff).map(lambda cs: FP4.element(*cs))

CASES = 1500


def _field_laws(field, a, b, c):
    one = field.one
    assert field.add(a, b) == field.add(b, a)
    assert field.mul(a, b) == field.mul(b, a)
    assert field.add(field.add(a, b), c) == field.add(a, field.add(b, c))
    assert field.mul(a, field.add(b, c)) == field.add(field.mul(a, b), field.mul(a, c))
    assert field.is_zero(field.sub(a, a))
    assert field.mul(a, one) == a
    assert field.square(a) == field.mul(a, a)
    if not field.is_zero(a):
        assert field.mul(a, field.inv(a)) == one
    if not field.is_zero(b):
        assert field.mul(field.div(a, b), b) == a


@settings(max_examples=CASES)
@given(fp_elem, fp_elem, fp_elem)
def test_prime_field_is_a_field(a, b, c):
    _field_laws(FP, a, b, c)


@settings(max_examples=CASES)
@given(fp2_elem, fp2_elem, fp2_elem)
def test_quadratic_extension_is_a_field(a, b, c):
    _field_laws(FP2, a, b, c)


@settings(max_examples=CASES)
@given(fp4_elem, fp4_elem, fp4_elem)
def test_quartic_extension_is_a_field(a, b, c):
    _field_laws(FP4, a, b, c)


# -- curves: the group law over each field ---------------------------

# secp256k1 for the prime-field curve, mirroring the Rust side; small
# curves over the extensions, where a scanned base point needs no constant.
SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
CURVE_FP = CurveFp(Fp(SECP_P), (0,), (7,))
CURVE_FP2 = CurveFp2(FP2, FP2.element(0, 0), FP2.element(1, 0))
CURVE_FP4 = CurveFp4(FP4, FP4.element(0), FP4.element(1))

scalar = st.integers(min_value=1, max_value=2**64)


def _curve_laws(curve, base, j, k, m):
    P = curve.multiply(base, j)
    Q = curve.multiply(base, k)
    R = curve.multiply(base, m)
    assert curve.is_on_curve(P)
    assert curve.add(P, None) == P
    assert curve.add(None, P) == P
    assert curve.add(P, curve.negate(P)) is None
    assert curve.add(P, Q) == curve.add(Q, P)
    assert curve.add(curve.add(P, Q), R) == curve.add(P, curve.add(Q, R))


@settings(max_examples=120, deadline=None)
@given(scalar, scalar, scalar)
def test_prime_curve_group_law(j, k, m):
    _curve_laws(CURVE_FP, CURVE_FP.first_point(), j, k, m)


@settings(max_examples=120, deadline=None)
@given(scalar, scalar, scalar)
def test_quadratic_curve_group_law(j, k, m):
    _curve_laws(CURVE_FP2, CURVE_FP2.first_point(), j, k, m)


@settings(max_examples=60, deadline=None)
@given(scalar, scalar, scalar)
def test_quartic_curve_group_law(j, k, m):
    _curve_laws(CURVE_FP4, CURVE_FP4.first_point(), j, k, m)
