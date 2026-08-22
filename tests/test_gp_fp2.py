"""Tests for the F_p^2 calls into PARI/GP.

Run it directly:

    python tests\\test_gp_fp2.py

Split the same way the existing backend tests are: the arithmetic and the
refusals are checked without gp installed, because those are the parts
that decide whether a wrong number gets through. The calls that need gp
skip themselves when it is absent, and say so.

The last test is the one that matters. It asks gp for the order of the
BLS12-381 G2 curve and compares it against h2 * r assembled from the
published parameters. Those two numbers come from completely different
places: one from a point-counting algorithm, one from the standard. They
agreeing is a real check on both.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.backends import gp as G
from core.backends.gp_fp2 import (
    curve_cardinality_fp2,
    hasse_interval_fp2,
    is_non_residue,
)

BLS_P = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
BLS_R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
BLS_H2 = 0x5D543A95414E7F1091D50792876A202CD91DE4547085ABAA68A205B2E5A7DDFA628F1CB4D9E82EF21537E293A6691AE1616EC6E786F0C70CF1C38E31C7238E5

SKIPPED = []


def _backend():
    """A backend, or None when gp is not installed."""
    try:
        return G.GpBackend()
    except G.GpNotFound:
        return None


def _raises(exception, call, *args, **kwargs):
    try:
        call(*args, **kwargs)
    except exception:
        return True
    return False


# -- arithmetic, no gp needed ---------------------------------------


def test_hasse_window_is_exact():
    """Over F_p^2 the square root of q is p exactly, so nothing is widened."""
    low, high = hasse_interval_fp2(103)
    q = 103**2
    assert low == q + 1 - 2 * 103
    assert high == q + 1 + 2 * 103


def test_hasse_window_holds_for_bls12_381():
    low, high = hasse_interval_fp2(BLS_P)
    assert low <= BLS_H2 * BLS_R <= high


def test_hasse_window_is_tighter_than_the_prime_field_one():
    """The prime-field helper widens by one; this one must not."""
    p = 103
    low, high = hasse_interval_fp2(p)
    assert high - low == 4 * p


def test_non_residue_detection():
    assert is_non_residue(-1, 103)      # 103 = 3 mod 4
    assert not is_non_residue(-1, 101)  # 101 = 1 mod 4
    assert not is_non_residue(4, 103)   # a square
    assert not is_non_residue(0, 103)


def test_non_residue_matches_brute_force():
    p = 103
    squares = {(k * k) % p for k in range(p)}
    for beta in range(1, p):
        assert is_non_residue(beta, p) == (beta not in squares)


# -- refusals, no gp needed -----------------------------------------


def test_residue_beta_is_refused_before_the_subprocess():
    """A reducible modulus must never reach ffgen."""
    assert _raises(
        ValueError, curve_cardinality_fp2, None, (0, 0), (4, 4), 101, -1
    )


def test_tiny_characteristic_is_refused():
    assert _raises(ValueError, curve_cardinality_fp2, None, (0, 0), (1, 0), 3, -1)


def test_absurd_inputs_are_refused():
    huge = 2 ** 9000
    assert _raises(ValueError, curve_cardinality_fp2, None, (0, 0), (4, 4), huge, -1)


# -- calls that need gp ---------------------------------------------


def test_small_curve_order_matches_enumeration():
    """gp's answer against a group counted by hand, on a field small
    enough that counting is possible."""
    backend = _backend()
    if backend is None:
        SKIPPED.append("test_small_curve_order_matches_enumeration")
        return

    from core.field.fp2 import CurveFp2, Fp2

    p, beta = 103, -1
    field = Fp2(p, beta)
    curve = CurveFp2(field, field.element(1), field.element(1))

    counted = 1  # the point at infinity
    for c1 in range(p):
        for c0 in range(p):
            y = curve.ordinate((c0, c1))
            if y is None:
                continue
            counted += 1 if field.is_zero(y) else 2

    reported = curve_cardinality_fp2(backend, (1, 0), (1, 0), p, beta)
    assert reported == counted


def test_bls12_381_g2_order_matches_the_published_parameters():
    """Point counting against h2 * r. Two independent origins."""
    backend = _backend()
    if backend is None:
        SKIPPED.append("test_bls12_381_g2_order_matches_the_published_parameters")
        return

    reported = curve_cardinality_fp2(backend, (0, 0), (4, 4), BLS_P, -1)
    assert reported == BLS_H2 * BLS_R


def test_cardinality_lands_in_the_hasse_window():
    backend = _backend()
    if backend is None:
        SKIPPED.append("test_cardinality_lands_in_the_hasse_window")
        return

    reported = curve_cardinality_fp2(backend, (0, 0), (4, 4), BLS_P, -1)
    low, high = hasse_interval_fp2(BLS_P)
    assert low <= reported <= high


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
                print(f"skip  {name}  (gp not found)")
            else:
                passed += 1
                print(f"ok    {name}")

    print()
    print(f"{passed} passed, {len(failed)} failed, {len(SKIPPED)} skipped")
    for name, reason in failed:
        print(f"  {name}: {reason}")
    if SKIPPED:
        print("  install PARI/GP or set CCERT_GP to run the skipped calls")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
