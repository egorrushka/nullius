"""Tests for canonical form and the bundle model.

Most of these check that bad input is refused. A format whose encoder is
permissive has no hash worth computing.
"""

import pytest

from core.bundle import canonical
from core.bundle.model import Bundle, BundleError, Claim, EVIDENCE_TIERS

SECP_P = 2**256 - 2**32 - 977
SECP_N = (
    115792089237316195423570985008687907852837564279074904382605163141518161494337
)


# -- canonical form -------------------------------------------------


def test_key_order_does_not_affect_bytes():
    left = {"b": "2", "a": "1", "c": {"z": "3", "y": "4"}}
    right = {"c": {"y": "4", "z": "3"}, "a": "1", "b": "2"}
    assert canonical.encode(left) == canonical.encode(right)


def test_golden_digest_is_stable():
    """Pins the encoding. If this changes, every published hash changed."""
    assert canonical.digest({"a": "1", "b": ["2", "3"]}) == (
        "sha256:f36dce65bd4739180e46ea9a21e355869834bb6ea5b4a553ae333d27ca7f46d5"
    )


def test_numbers_are_refused():
    with pytest.raises(canonical.CanonicalError):
        canonical.encode({"n": 7})
    with pytest.raises(canonical.CanonicalError):
        canonical.encode({"n": 1.5})


def test_odd_types_are_refused():
    with pytest.raises(canonical.CanonicalError):
        canonical.encode({"n": {1, 2}})
    with pytest.raises(canonical.CanonicalError):
        canonical.encode({"n": b"raw"})


def test_bad_keys_are_refused():
    with pytest.raises(canonical.CanonicalError):
        canonical.encode({"has space": "1"})
    with pytest.raises(canonical.CanonicalError):
        canonical.encode({"": "1"})


def test_decimal_strings_have_one_spelling():
    assert canonical.as_int("0") == 0
    assert canonical.as_int("-7") == -7
    for bad in ["007", "+7", "7 ", "1_000", "0x10", "1e3", "", "-0"]:
        with pytest.raises(canonical.CanonicalError):
            canonical.as_int(bad)


def test_large_integers_survive_the_round_trip():
    assert canonical.as_int(canonical.as_str(SECP_N)) == SECP_N


def test_bool_is_not_an_integer():
    with pytest.raises(canonical.CanonicalError):
        canonical.as_str(True)


# -- bundle model ---------------------------------------------------


def sample() -> Bundle:
    """A bundle shaped like the real thing, with token evidence.

    The mathematics is the verifier's business; this fixture only needs the
    structure to be right.
    """
    bundle = Bundle(
        subject={
            "kind": "elliptic-curve",
            "model": "short-weierstrass",
            "field": {"kind": "prime", "p": canonical.as_str(SECP_P)},
            "a": "0",
            "b": "7",
        }
    )
    bundle.add_claim(
        "curve.order.prime",
        {"n": canonical.as_str(SECP_N), "prime": "proved"},
        "proof.ecpp",
        {"subject": canonical.as_str(SECP_N), "steps": []},
    )
    bundle.add_claim(
        "curve.order",
        {"n": canonical.as_str(SECP_N), "cofactor": "1"},
        "check.order-unique",
        {"point": {"x": "1", "y": "2"}},
        depends_on=("curve.order.prime",),
    )
    bundle.add_claim(
        "twist.cardinality",
        {
            "n_twist": canonical.as_str(2 * SECP_P + 2 - SECP_N),
            "identity": "n + n_twist = 2p + 2",
        },
        "derive.twist-sum",
        depends_on=("curve.order",),
    )
    return bundle


def test_sample_validates_and_round_trips():
    bundle = sample()
    bundle.validate()
    again = Bundle.from_obj(bundle.to_obj())
    assert again.digest() == bundle.digest()


def test_tier_comes_from_evidence_not_from_the_producer():
    bundle = sample()
    assert bundle.by_name("curve.order.prime").tier == "A"
    assert bundle.by_name("twist.cardinality").tier == "D"
    assert bundle.tier_counts() == {"A": 2, "D": 1, "X": 0}


def test_proof_may_not_rest_on_a_candidate():
    """The rule that keeps tier A meaning something."""
    bundle = sample()
    bundle.add_claim(
        "curve.cardinality",
        {"n": canonical.as_str(SECP_N)},
        "candidate.sea",
        {"tool": "pari/gp"},
    )
    bundle.claims[1] = Claim(
        "curve.order",
        bundle.claims[1].asserts,
        "check.order-unique",
        bundle.claims[1].evidence_ref,
        depends_on=("curve.cardinality",),
    )
    with pytest.raises(BundleError):
        bundle.validate()


def test_tier_table_covers_every_evidence_type_in_use():
    bundle = sample()
    for record in bundle.claims:
        assert record.evidence_type in EVIDENCE_TIERS


def test_unknown_claim_type_is_refused():
    bundle = sample()
    bundle.claims.append(Claim("curve.magic", {"x": "1"}, "check.hasse"))
    with pytest.raises(BundleError):
        bundle.validate()


def test_unknown_evidence_type_is_refused():
    bundle = sample()
    with pytest.raises(BundleError):
        bundle.add_claim("curve.hasse", {"low": "1"}, "check.vibes")


def test_tampered_evidence_is_caught():
    bundle = sample()
    ref = next(iter(bundle.evidence))
    bundle.evidence[ref] = dict(bundle.evidence[ref], version="9.9.9")
    with pytest.raises(BundleError):
        bundle.validate()


def test_dangling_evidence_reference_is_caught():
    bundle = sample()
    bundle.evidence.clear()
    with pytest.raises(BundleError):
        bundle.validate()


def test_orphan_evidence_is_caught():
    bundle = sample()
    bundle.add_evidence({"type": "candidate.sea", "tool": "nobody-points-here"})
    with pytest.raises(BundleError):
        bundle.validate()


def test_dangling_dependency_is_caught():
    bundle = sample()
    bundle.claims.append(
        Claim(
            "curve.hasse",
            {"low": "1", "high": "2", "contains": "1"},
            "check.hasse",
            depends_on=("curve.absent",),
        )
    )
    with pytest.raises(BundleError):
        bundle.validate()


def test_duplicate_claims_are_refused():
    bundle = sample()
    bundle.claims.append(bundle.claims[0])
    with pytest.raises(BundleError):
        bundle.validate()


def test_foreign_format_is_refused():
    with pytest.raises(BundleError):
        Bundle.from_obj({"format": "something-else", "version": "0"})


def test_future_version_is_refused():
    obj = sample().to_obj()
    obj["version"] = "1"
    with pytest.raises(BundleError):
        Bundle.from_obj(obj)


def test_unknown_field_is_refused():
    """Silently ignoring a field is how a verifier misses what matters."""
    obj = sample().to_obj()
    obj["extra"] = "surprise"
    with pytest.raises(BundleError):
        Bundle.from_obj(obj)
