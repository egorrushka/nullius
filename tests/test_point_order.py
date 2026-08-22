"""Tests for the point-order evidence.

Run it directly:

    python tests\\test_point_order.py

The evidence exists because ``check.order-unique`` cannot reach a group
whose cofactor is larger than the Hasse window, which is every G2 of a
pairing-friendly curve. What is tested here is mostly the refusals: a
witness that does not pin the order must be rejected loudly rather than
quietly producing the nearest plausible number.

The small curve is enumerated in full, so the pinned group order is
compared against a counted one.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.bundle.model import Bundle, BundleError, EVIDENCE_TIERS, CLAIM_TYPES
from core.claims.point_order import (
    CLAIM_TYPE,
    EVIDENCE_TYPE,
    PointOrderError,
    build_point_order_evidence,
    find_witness,
    unique_multiple_in_window,
)
from core.field.fp import CurveFp, Fp
from core.field.fp2 import CurveFp2, Fp2

BLS_P = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
BLS_R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
BLS_H2 = 0x5D543A95414E7F1091D50792876A202CD91DE4547085ABAA68A205B2E5A7DDFA628F1CB4D9E82EF21537E293A6691AE1616EC6E786F0C70CF1C38E31C7238E5

# h2 = 13^2 * 23^2 * 2713 * 11953 * 262069 * (a 448-bit prime), and r is
# prime, so the whole group order factors.
BLS_Q448 = 402096035359507321594726366720466575392706800671181159425656785868777272553337714697862511267018014931937703598282857976535744623203249
BLS_FACTORS = [
    (13, 2),
    (23, 2),
    (2713, 1),
    (11953, 1),
    (262069, 1),
    (BLS_Q448, 1),
    (BLS_R, 1),
]

BLS_FIELD = Fp2(BLS_P, -1)
BLS_CURVE = CurveFp2(BLS_FIELD, BLS_FIELD.zero, BLS_FIELD.element(4, 4))

SMALL_P = 103
SMALL_FIELD = Fp2(SMALL_P, -1)
SMALL_CURVE = CurveFp2(SMALL_FIELD, SMALL_FIELD.element(1), SMALL_FIELD.element(1))

# The same curve over the base field, for the bundle tests below.
#
# The arithmetic tests in this file work over F_p^2 and stay there: an
# extension exercises the two-coefficient paths, and that is worth
# testing whatever claim the result may be attached to. The *bundle*
# tests are different — they build a document, and the document has to be
# one the format admits. `proof.point-order` supports `curve.cardinality`
# only, over the base field, so a toy bundle carrying degree-2 evidence
# under that claim would be a fixture no verifier would accept.
BASE_FIELD = Fp(SMALL_P)
BASE_CURVE = CurveFp(BASE_FIELD, BASE_FIELD.element(1), BASE_FIELD.element(1))
BASE_ORDER = 87                       # counted below, and checked there


def _enumerate():
    total = 1
    for c1 in range(SMALL_P):
        for c0 in range(SMALL_P):
            y = SMALL_CURVE.ordinate((c0, c1))
            if y is None:
                continue
            total += 1 if SMALL_FIELD.is_zero(y) else 2
    return total


SMALL_ORDER = _enumerate()


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


def _raises(exception, call, *args, **kwargs):
    try:
        call(*args, **kwargs)
    except exception:
        return True
    return False


def _toy_bundle(pinned, payload):
    """A minimal bundle carrying the evidence under test.

    It has to include `field.characteristic`, because the point-order
    evidence is now required to declare that it rests on a proved
    characteristic: the field, the Euler criterion and the Hasse window
    all assume p is prime, and nothing in the evidence itself can say so.
    """
    bundle = Bundle(subject={"kind": "elliptic-curve", "label": "toy"})
    bundle.add_claim(
        "field.characteristic",
        {"p": str(SMALL_P), "prime": "proved"},
        "proof.ecpp",
        {"subject": str(SMALL_P), "steps": []},
    )
    bundle.add_claim(
        CLAIM_TYPE,
        {"n": str(pinned)},
        EVIDENCE_TYPE,
        payload,
        depends_on=("field.characteristic",),
    )
    return bundle


# -- the window argument ---------------------------------------------


def test_unique_multiple_is_found():
    assert unique_multiple_in_window(10, 95, 105) == 100


def test_several_multiples_are_refused():
    """A witness too small to pin the order must be rejected, not guessed."""
    assert _raises(PointOrderError, unique_multiple_in_window, 10, 95, 125)


def test_no_multiple_is_refused():
    assert _raises(PointOrderError, unique_multiple_in_window, 100, 101, 199)


def test_window_edges_count():
    """The window is inclusive at both ends."""
    assert unique_multiple_in_window(10, 100, 109) == 100
    assert unique_multiple_in_window(10, 91, 100) == 100


# -- the small curve, checked against enumeration --------------------


def test_small_curve_order_is_pinned_correctly():
    point, order = SMALL_WITNESS, SMALL_WITNESS_ORDER
    _, pinned = build_point_order_evidence(
        SMALL_P, 2, (1, 0), (1, 0), point, order, _factor(order), -1
    )
    assert pinned == SMALL_ORDER


SMALL_WITNESS, SMALL_WITNESS_ORDER = find_witness(
    SMALL_CURVE, SMALL_ORDER, _factor(SMALL_ORDER)
)


def test_payload_holds_only_decimal_strings():
    point, order = SMALL_WITNESS, SMALL_WITNESS_ORDER
    payload, _ = build_point_order_evidence(
        SMALL_P, 2, (1, 0), (1, 0), point, order, _factor(order), -1
    )
    for value in payload["field"].values():
        assert isinstance(value, str) and value.lstrip("-").isdigit()
    for section in ("curve", "point"):
        for coefficients in payload[section].values():
            assert isinstance(coefficients, list)
            assert len(coefficients) == 2      # degree of the field
            for value in coefficients:
                assert isinstance(value, str) and value.lstrip("-").isdigit()
    assert isinstance(payload["order"], str)
    assert payload["field"]["degree"] == "2"


def test_factors_are_sorted_for_reproducible_bytes():
    point, order = SMALL_WITNESS, SMALL_WITNESS_ORDER
    factors = _factor(order)
    forward, _ = build_point_order_evidence(
        SMALL_P, 2, (1, 0), (1, 0), point, order, factors, -1
    )
    backward, _ = build_point_order_evidence(
        SMALL_P, 2, (1, 0), (1, 0), point, order, list(reversed(factors)), -1
    )
    assert forward == backward


# -- the witness search ----------------------------------------------


def test_find_witness_is_deterministic():
    """Two runs must pick the same point, or the bundle hash moves."""
    again = find_witness(SMALL_CURVE, SMALL_ORDER, _factor(SMALL_ORDER))
    assert again == (SMALL_WITNESS, SMALL_WITNESS_ORDER)


def test_find_witness_skips_points_that_do_not_pin():
    """The first point on the curve is not good enough here, and that is
    exactly why the search exists."""
    from core.field.order import point_order

    first = SMALL_CURVE.first_point()
    weak = point_order(SMALL_CURVE, first, SMALL_ORDER, _factor(SMALL_ORDER))
    assert weak < SMALL_WITNESS_ORDER
    assert _raises(
        PointOrderError,
        build_point_order_evidence,
        SMALL_P, 2, (1, 0), (1, 0), first, weak, _factor(weak), -1,
    )


def test_found_witness_beats_the_window():
    assert SMALL_WITNESS_ORDER > 4 * SMALL_P


# -- refusals ---------------------------------------------------------


def test_point_off_the_curve_is_refused():
    point, order = SMALL_WITNESS, SMALL_WITNESS_ORDER
    bogus = (point[0], SMALL_FIELD.add(point[1], SMALL_FIELD.one))
    assert _raises(
        Exception,
        build_point_order_evidence,
        SMALL_P, 2, (1, 0), (1, 0), bogus, order, _factor(order), -1, -1,
    )


def test_overstated_order_is_refused():
    point, order = SMALL_WITNESS, SMALL_WITNESS_ORDER
    assert _raises(
        PointOrderError,
        build_point_order_evidence,
        SMALL_P, 2, (1, 0), (1, 0), point, order * 2, _factor(order * 2), -1,
    )


def test_reducible_modulus_is_refused():
    assert _raises(
        Exception,
        build_point_order_evidence,
        101, 2, (1, 0), (1, 0), ((0, 0), (0, 0)), 1, [(1, 1)], -1,
    )


def test_unreduced_coordinates_are_refused():
    point, order = SMALL_WITNESS, SMALL_WITNESS_ORDER
    raw = ((point[0][0] + SMALL_P, point[0][1]), point[1])
    assert _raises(
        PointOrderError,
        build_point_order_evidence,
        SMALL_P, 2, (1, 0), (1, 0), raw, order, _factor(order), -1, -1,
    )


def test_a_witness_of_order_r_alone_is_refused():
    """The whole reason this evidence exists: r does not pin G2.

    r is about 2^255 and the window over F_p^2 is about 2^383 wide, so
    many multiples of r fit. The generator is a perfectly good point and
    still must not be accepted as a witness.
    """
    generator = (
        (
            0x024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8,
            0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E,
        ),
        (
            0x0CE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801,
            0x0606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE,
        ),
    )
    assert _raises(
        PointOrderError,
        build_point_order_evidence,
        BLS_P, 2, (0, 0), (4, 4), generator, BLS_R, [(BLS_R, 1)], -1,
    )


# -- BLS12-381 G2, the real target -----------------------------------


def test_bls12_381_g2_is_pinned():
    """A point of full order pins h2 * r and nothing else."""
    from core.field.order import point_order

    group_order = BLS_H2 * BLS_R
    point = BLS_CURVE.first_point()
    order = point_order(BLS_CURVE, point, group_order, BLS_FACTORS)
    factors = [(q, e) for q, e in BLS_FACTORS if order % q == 0]
    payload, pinned = build_point_order_evidence(
        BLS_P, 2, (0, 0), (4, 4), point, order, _trim(factors, order), -1
    )
    assert pinned == group_order
    assert payload["order"] == str(order)


def _trim(factors, order):
    """The factorisation of ``order``, taken from that of the group."""
    trimmed = []
    for prime, _ in factors:
        e = 0
        rest = order
        while rest % prime == 0:
            rest //= prime
            e += 1
        if e:
            trimmed.append((prime, e))
    return trimmed


def test_bls12_381_witness_beats_the_window():
    """The witness order must exceed the window, or nothing is pinned."""
    from core.field.order import point_order

    point = BLS_CURVE.first_point()
    order = point_order(BLS_CURVE, point, BLS_H2 * BLS_R, BLS_FACTORS)
    assert order > 4 * BLS_P


# -- the model accepts the new kind ----------------------------------


def test_evidence_type_is_registered_as_proved():
    assert EVIDENCE_TIERS[EVIDENCE_TYPE] == "A"


def test_claim_type_is_registered():
    assert CLAIM_TYPE in CLAIM_TYPES


def test_the_base_field_fixture_is_what_it_says():
    """Counted rather than asserted, so the constant cannot rot."""
    total = 1
    for x in range(SMALL_P):
        y = BASE_CURVE.ordinate(BASE_FIELD.element(x))
        if y is None:
            continue
        total += 1 if BASE_FIELD.is_zero(y) else 2
    assert total == BASE_ORDER


def test_a_bundle_carrying_it_validates():
    point, order = find_witness(BASE_CURVE, BASE_ORDER, _factor(BASE_ORDER))
    payload, pinned = build_point_order_evidence(
        SMALL_P, 1, (1,), (1,), point, order, _factor(order)
    )
    bundle = _toy_bundle(pinned, payload)
    bundle.validate()
    assert bundle.by_name(CLAIM_TYPE).tier == "A"
    assert len(bundle.digest()) == len("sha256:") + 64


def test_bundle_bytes_are_reproducible():
    point, order = find_witness(BASE_CURVE, BASE_ORDER, _factor(BASE_ORDER))

    def make():
        payload, pinned = build_point_order_evidence(
            SMALL_P, 1, (1,), (1,), point, order, _factor(order)
        )
        return _toy_bundle(pinned, payload).encode()

    assert make() == make()


def test_tampered_evidence_breaks_the_pool():
    point, order = find_witness(BASE_CURVE, BASE_ORDER, _factor(BASE_ORDER))
    payload, pinned = build_point_order_evidence(
        SMALL_P, 1, (1,), (1,), point, order, _factor(order)
    )
    bundle = _toy_bundle(pinned, payload)
    ref = bundle.by_name(CLAIM_TYPE).evidence_ref
    bundle.evidence[ref]["order"] = str(order + 1)
    assert _raises(BundleError, bundle.validate)


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
