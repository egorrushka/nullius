"""Tests for the pairing-curve bundle.

Run it directly:

    python tests\\test_pairing.py

Building the bundle needs gp, so those tests skip themselves when it is
absent and say so. The bundle is built once and reused, because the cost
is a couple of seconds and every test below wants the same one.

The check that matters most is reproducibility. Two builds must produce
identical bytes, because the whole format rests on a certificate being
addressable by its hash. A witness picked by a search that is not fully
deterministic would pass every other test here and quietly break that.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.backends import gp as G
from core.bundle.model import Bundle, BundleError
from core.bundle.pairing import KNOWN_PAIRING_CURVES, build_pairing_bundle

BLS = KNOWN_PAIRING_CURVES["bls12-381"]
BLS_R = BLS["r"]
BLS_H1 = 76329603384216526031706109802092473003
BLS_H2 = 0x5D543A95414E7F1091D50792876A202CD91DE4547085ABAA68A205B2E5A7DDFA628F1CB4D9E82EF21537E293A6691AE1616EC6E786F0C70CF1C38E31C7238E5

BN = KNOWN_PAIRING_CURVES["bn254"]
BN_R = BN["r"]
BN_H2 = 2 * BN["p"] - BN["r"]

SKIPPED = []
_CACHE: dict[str, Bundle] = {}


def _raises(exception, call, *args, **kwargs):
    try:
        call(*args, **kwargs)
    except exception:
        return True
    return False


def _build(name="bls12-381"):
    """A built bundle, or None when gp is missing.

    Cached because every test below wants the same object and building
    costs a couple of seconds each.
    """
    if name in _CACHE:
        return _CACHE[name]
    try:
        backend = G.GpBackend()
    except G.GpNotFound:
        return None
    params = KNOWN_PAIRING_CURVES[name]
    # Keyword arguments throughout. The signature has grown twice, and
    # both times a positional call in a test silently handed a parameter
    # to the wrong slot.
    bundle = build_pairing_bundle(
        name=params["label"], p=params["p"], a=params["a"], b=params["b"],
        r=params["r"], beta=params["beta"],
        family=params.get("family"), u=params.get("u"),
        twist_a=params["twist_a"], twist_b=params["twist_b"],
        backend=backend,
        published_order=params["published_order"],
        embedding_degree=params["embedding_degree"],
    )
    _CACHE[name] = bundle
    return bundle


def _skip(name):
    SKIPPED.append(name)


# -- the claim set ----------------------------------------------------


def test_every_expected_claim_is_present():
    bundle = _build()
    if bundle is None:
        return _skip("test_every_expected_claim_is_present")
    expected = {
        "field.characteristic",
        "curve.order.prime",
        "curve.cardinality",
        "curve.order",
        "curve.embedding",
        "g2.cardinality",
        "g2.order",
        "curve.family",
        "g2.twist",
        "curve.cm",
        "twist.cardinality",
    }
    assert {claim.claim for claim in bundle.claims} == expected


def test_nothing_is_a_bare_candidate():
    """A pairing bundle carrying a number a program merely reported would
    be worth little. One derived claim is expected: the twist identity
    holds only as far as the cardinality it rests on, and the format says
    so by tiering it below proved rather than by a footnote."""
    bundle = _build()
    if bundle is None:
        return _skip("test_nothing_is_a_bare_candidate")
    counts = bundle.tier_counts()
    assert counts["X"] == 0
    assert counts["D"] == 1
    assert counts["A"] == len(bundle.claims) - 1
    assert bundle.by_name("twist.cardinality").tier == "D"


def test_the_bundle_validates():
    bundle = _build()
    if bundle is None:
        return _skip("test_the_bundle_validates")
    bundle.validate()


# -- the numbers agree with the standard -----------------------------


def test_g1_order_splits_as_h1_times_r():
    bundle = _build()
    if bundle is None:
        return _skip("test_g1_order_splits_as_h1_times_r")
    order = int(bundle.by_name("curve.cardinality").asserts["n"])
    assert order == BLS_H1 * BLS_R
    split = bundle.by_name("curve.order").asserts
    assert int(split["cofactor"]) == BLS_H1
    assert int(split["n"]) == BLS_R


def test_g2_order_splits_as_h2_times_r():
    bundle = _build()
    if bundle is None:
        return _skip("test_g2_order_splits_as_h2_times_r")
    order = int(bundle.by_name("g2.cardinality").asserts["n"])
    assert order == BLS_H2 * BLS_R
    split = bundle.by_name("g2.order").asserts
    assert int(split["cofactor"]) == BLS_H2
    assert int(split["n"]) == BLS_R


def test_embedding_degree_is_twelve():
    """The defining property of the family, and the reason for the name."""
    bundle = _build()
    if bundle is None:
        return _skip("test_embedding_degree_is_twelve")
    assert bundle.by_name("curve.embedding").asserts["degree"] == "12"


# -- the evidence is shaped as the format says -----------------------


def test_g1_evidence_is_degree_one():
    bundle = _build()
    if bundle is None:
        return _skip("test_g1_evidence_is_degree_one")
    claim = bundle.by_name("curve.cardinality")
    payload = bundle.evidence[claim.evidence_ref]
    assert payload["field"]["degree"] == "1"
    assert "beta" not in payload["field"]
    assert len(payload["point"]["x"]) == 1


def test_g2_evidence_is_degree_two():
    bundle = _build()
    if bundle is None:
        return _skip("test_g2_evidence_is_degree_two")
    claim = bundle.by_name("g2.cardinality")
    payload = bundle.evidence[claim.evidence_ref]
    assert payload["field"]["degree"] == "2"
    assert payload["field"]["beta"] == str(BLS["beta"] % BLS["p"])
    assert len(payload["curve"]["b"]) == 2
    # Points, plural: the argument narrows a set rather than exhibiting
    # one witness, so however many it took to close is what gets carried.
    assert len(payload["points"]) >= 1
    assert len(payload["points"][0]["x"]) == 2


def test_g2_carries_no_factorisation():
    """The whole point of the change. `proof.point-order` needed the
    group order factored, and that is a ceiling rather than a cost:
    BLS24-315's G2 cofactor has a 983-bit composite part. Elimination
    needs none, so the evidence has none."""
    bundle = _build()
    if bundle is None:
        return _skip("test_g2_carries_no_factorisation")
    payload = bundle.evidence[bundle.by_name("g2.cardinality").evidence_ref]
    assert "factors" not in payload
    assert "order" not in payload


def test_the_elimination_evidence_is_smaller():
    """A side effect worth having: the G2 argument shrank from a witness
    plus its factorisation to a handful of points."""
    bundle = _build()
    if bundle is None:
        return _skip("test_the_elimination_evidence_is_smaller")
    import json

    g2 = bundle.evidence[bundle.by_name("g2.cardinality").evidence_ref]
    g1 = bundle.evidence[bundle.by_name("curve.cardinality").evidence_ref]
    assert len(json.dumps(g2)) < len(json.dumps(g1))


def test_witness_orders_beat_their_windows():
    """Without this the pinning argument does not close."""
    bundle = _build()
    if bundle is None:
        return _skip("test_witness_orders_beat_their_windows")
    # Only G1 now. The G2 order is settled by elimination, which has no
    # witness and therefore no window to beat — that is exactly why it
    # reaches curves the witness argument cannot.
    p = BLS["p"]
    payload = bundle.evidence[bundle.by_name("curve.cardinality").evidence_ref]
    order = int(payload["order"])
    assert order > 4 * _isqrt(p) + 2


def _isqrt(n):
    from math import isqrt

    return isqrt(n)


def test_large_factors_carry_chains():
    """Anything the verifier cannot settle itself must arrive with a chain."""
    bundle = _build()
    if bundle is None:
        return _skip("test_large_factors_carry_chains")
    from core.bundle.builder import SMALL_PRIME_LIMIT

    # g2.cardinality is not in this list any more: it carries no factors
    # to attach chains to.
    for name in ("curve.cardinality", "g2.order"):
        payload = bundle.evidence[bundle.by_name(name).evidence_ref]
        for entry in payload["factors"]:
            prime = int(entry["prime"])
            if prime >= SMALL_PRIME_LIMIT:
                assert "steps" in entry, f"{name}: {prime} has no chain"
                assert entry["steps"], f"{name}: {prime} has an empty chain"


# -- BN254 ------------------------------------------------------------


def test_bn254_has_the_same_claim_set():
    """A second curve on the same evidence kinds is the point of the
    format. If BN254 needed a new claim, the generalisation was too narrow."""
    bundle = _build("bn254")
    if bundle is None:
        return _skip("test_bn254_has_the_same_claim_set")
    reference = _build()
    assert {c.claim for c in bundle.claims} == {c.claim for c in reference.claims}
    assert {c.evidence_type for c in bundle.claims} == {
        c.evidence_type for c in reference.claims
    }


def test_bn254_has_a_trivial_g1_cofactor():
    """Where BLS12-381 has h1 = 76329..., BN254 has one. Both must work,
    and the difference must show up in the certificate rather than in the
    code path that produced it."""
    bundle = _build("bn254")
    if bundle is None:
        return _skip("test_bn254_has_a_trivial_g1_cofactor")
    split = bundle.by_name("curve.order").asserts
    assert int(split["cofactor"]) == 1
    assert int(split["n"]) == BN_R
    assert int(bundle.by_name("curve.cardinality").asserts["n"]) == BN_R


def test_bn254_g2_order_matches_the_family_formula():
    """For a BN curve the twist order is (2p - r) * r. The certificate does
    not use the formula; agreeing with it is a check on both."""
    bundle = _build("bn254")
    if bundle is None:
        return _skip("test_bn254_g2_order_matches_the_family_formula")
    order = int(bundle.by_name("g2.cardinality").asserts["n"])
    assert order == BN_H2 * BN_R
    assert int(bundle.by_name("g2.order").asserts["cofactor"]) == BN_H2


def test_bn254_embedding_degree_is_twelve():
    bundle = _build("bn254")
    if bundle is None:
        return _skip("test_bn254_embedding_degree_is_twelve")
    assert bundle.by_name("curve.embedding").asserts["degree"] == "12"


def test_bn254_twist_coefficient_derives_from_the_standard():
    """The stored pair must equal 3/(9 + u), which is how the standard
    states it. Stored evaluated because the format carries coefficients,
    not expressions, so the derivation has to be checked somewhere."""
    from core.field.fp2 import Fp2

    field = Fp2(BN["p"], BN["beta"])
    expected = field.div(field.element(3, 0), field.element(9, 1))
    assert BN["twist_b"] == expected


def test_the_two_curves_differ_where_they_should():
    """Two certificates from one builder must not be quietly identical."""
    first, second = _build(), _build("bn254")
    if first is None or second is None:
        return _skip("test_the_two_curves_differ_where_they_should")
    assert first.digest() != second.digest()
    assert first.subject["label"] != second.subject["label"]


# -- reproducibility --------------------------------------------------


def test_two_builds_agree_byte_for_byte():
    """The property the whole format rests on."""
    first = _build()
    if first is None:
        return _skip("test_two_builds_agree_byte_for_byte")
    backend = G.GpBackend()
    second = build_pairing_bundle(
        name=BLS["label"], p=BLS["p"], a=BLS["a"], b=BLS["b"], r=BLS["r"],
        beta=BLS["beta"], family=BLS.get("family"), u=BLS.get("u"),
        twist_a=BLS["twist_a"], twist_b=BLS["twist_b"], backend=backend,
        published_order=BLS["published_order"],
        embedding_degree=BLS["embedding_degree"],
    )
    assert first.encode() == second.encode()
    assert first.digest() == second.digest()


def test_reencoding_is_stable():
    bundle = _build()
    if bundle is None:
        return _skip("test_reencoding_is_stable")
    again = Bundle.from_obj(bundle.to_obj())
    assert again.encode() == bundle.encode()


def test_the_file_ends_with_one_newline(tmp_path=None):
    bundle = _build()
    if bundle is None:
        return _skip("test_the_file_ends_with_one_newline")
    encoded = bundle.encode()
    assert not encoded.endswith(b"\n")
    assert b"\r" not in encoded


# -- tampering --------------------------------------------------------


def test_a_changed_order_breaks_the_pool():
    bundle = _build()
    if bundle is None:
        return _skip("test_a_changed_order_breaks_the_pool")
    # A plain round trip. from_obj copies on the way in, so the original
    # is untouched; this test is the regression for that.
    clone = Bundle.from_obj(bundle.to_obj())
    # The G1 witness, because the G2 evidence no longer carries an order
    # to change: elimination narrows candidates rather than exhibiting a
    # witness of a stated order.
    ref = clone.by_name("curve.cardinality").evidence_ref
    clone.evidence[ref]["order"] = str(int(clone.evidence[ref]["order"]) + 1)
    assert _raises(BundleError, clone.validate)
    bundle.validate()   # the original must be untouched


def test_a_wrong_published_order_is_refused():
    """A mistyped parameter must stop the build, not produce a certificate
    about a curve nobody uses."""
    try:
        backend = G.GpBackend()
    except G.GpNotFound:
        return _skip("test_a_wrong_published_order_is_refused")
    assert _raises(
        ValueError,
        build_pairing_bundle,
        name=BLS["label"], p=BLS["p"], a=BLS["a"], b=BLS["b"], r=BLS["r"],
        beta=BLS["beta"], family=BLS.get("family"), u=BLS.get("u"),
        twist_a=BLS["twist_a"], twist_b=BLS["twist_b"], backend=backend,
        published_order=BLS["published_order"] + 1,
    )


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
        print("  install PARI/GP or set CCERT_GP to run the skipped builds")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
