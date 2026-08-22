"""Tests for the pairing policies, and for criteria that name a model.

Run it directly:

    python tests\\test_pairing_policy.py

The case these policies exist to make is this one. BN254 has not changed
since it was standardised: its order is the same number, and every claim
in its certificate holds today exactly as it did in 2015. What changed is
an estimate of what an attacker can afford. Under the pre-2016 analysis
the curve meets a 128-bit target; under the tower number field sieve it
does not.

So the tests below check two things beyond the arithmetic. That the same
certificate really does receive different verdicts from the two policies,
and that a criterion whose verdict rests on something outside the bundle
is required to name it. A threshold with no model behind it dates
silently, and silence is what this project is against.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.bundle.model import Bundle
from core.policy.engine import (
    PolicyError,
    available_policies,
    evaluate,
    load_policy,
)

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"

SKIPPED = []

TNFS = "pairing-security-tnfs-2016"
PRE_TNFS = "pairing-security-pre-tnfs"
SUITABILITY = "pairing-suitability"


def _bundle(name):
    path = CORPUS / f"{name}.ccert"
    if not path.is_file():
        return None
    return Bundle.from_obj(__import__("json").loads(path.read_text(encoding="utf-8")))


def _ready(test_name, *curves):
    for curve in curves:
        if not (CORPUS / f"{curve}.ccert").is_file():
            SKIPPED.append(test_name)
            return False
    return True


def _verdict(curve, policy_name):
    return evaluate(_bundle(curve), load_policy(policy_name))


def _outcome(verdict, criterion_id):
    for outcome in verdict.outcomes:
        if outcome.criterion.id == criterion_id:
            return outcome
    raise AssertionError(f"no criterion `{criterion_id}` in this policy")


def _raises(exception, call, *args, **kwargs):
    try:
        call(*args, **kwargs)
    except exception:
        return True
    return False


# -- the policies load ------------------------------------------------


def test_all_three_policies_load():
    for name in (SUITABILITY, TNFS, PRE_TNFS):
        policy = load_policy(name)
        assert policy.criteria


def test_every_policy_in_the_directory_parses():
    """A malformed policy must stop the engine, not be skipped."""
    names = available_policies()
    assert len(names) >= 5
    for name in names:
        assert load_policy(name).criteria


# -- the model block --------------------------------------------------


def test_the_model_dependent_criterion_names_its_model():
    policy = load_policy(TNFS)
    criterion = next(c for c in policy.criteria if c.id == "embedding-field-size")
    assert criterion.model is not None
    assert criterion.model["name"] == "tnfs-kim-barbulescu-2016"
    assert "Kim" in criterion.model["source"]
    assert criterion.model.get("note")


def test_criteria_that_are_theorems_carry_no_model():
    """Pollard rho is a bound, not an estimate, and must not be dressed as
    one. A model on every criterion would make the label meaningless."""
    for name in (TNFS, PRE_TNFS):
        policy = load_policy(name)
        rho = next(c for c in policy.criteria if c.id == "subgroup-order-large")
        assert rho.model is None


def test_the_structural_policy_names_no_model_at_all():
    """Its verdicts do not date, and that is the point of separating it."""
    policy = load_policy(SUITABILITY)
    assert all(c.model is None for c in policy.criteria)


def test_a_model_without_a_source_is_refused():
    """Half a citation is worse than none: it looks like provenance."""
    import tempfile

    import yaml

    document = {
        "name": "broken",
        "title": "broken",
        "source": "test",
        "criteria": [
            {
                "id": "x",
                "description": "x",
                "claim": "curve.order",
                "field": "n",
                "op": "ge",
                "value": "1",
                "model": {"name": "unnamed"},
            }
        ],
    }
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".yaml", delete=False, encoding="utf-8"
    )
    yaml.safe_dump(document, handle)
    handle.close()
    assert _raises(PolicyError, load_policy, Path(handle.name))


# -- the demonstration ------------------------------------------------


def test_bn254_passes_the_old_model_and_fails_the_new_one():
    """The whole argument, in one certificate and two policies."""
    if not _ready("test_bn254_passes_the_old_model_and_fails_the_new_one", "bn254"):
        return
    old = _verdict("bn254", PRE_TNFS)
    new = _verdict("bn254", TNFS)
    assert old.count("fail") == 0
    assert new.count("fail") > 0


def test_the_difference_is_exactly_the_field_size_criterion():
    """Nothing else may move, or the demonstration proves something else."""
    if not _ready("test_the_difference_is_exactly_the_field_size_criterion", "bn254"):
        return
    old = _verdict("bn254", PRE_TNFS)
    new = _verdict("bn254", TNFS)
    flipped = {
        outcome.criterion.id
        for outcome in new.outcomes
        if outcome.status != _outcome(old, outcome.criterion.id).status
    }
    assert flipped == {"embedding-field-size"}


def test_the_facts_behind_the_flip_are_identical():
    """The certificate does not change. Only the threshold does."""
    if not _ready("test_the_facts_behind_the_flip_are_identical", "bn254"):
        return
    old = _outcome(_verdict("bn254", PRE_TNFS), "embedding-field-size")
    new = _outcome(_verdict("bn254", TNFS), "embedding-field-size")
    # 254 bits of p, embedding degree 12.
    assert old.detail.startswith("3044")
    assert new.detail.startswith("3044")
    assert old.status == "pass" and new.status == "fail"


def test_bls12_381_also_fails_the_strict_target():
    """It fails too, and the policy says so rather than flattering it.

    An earlier version of this policy used a threshold of 4400, which had
    no derivation, and under it BLS12-381 passed. The source gives 5004
    for the 128-bit level, and at 4569 bits the curve is under that. The
    literature says the same in words: slightly below 128.

    The curve is not thereby broken, and remains the recommended choice
    for efficient pairings at this level. What fails is the strict reading
    of the target, which is what the policy is named for."""
    if not _ready("test_bls12_381_also_fails_the_strict_target", "bls12-381"):
        return
    verdict = _verdict("bls12-381", TNFS)
    assert _outcome(verdict, "embedding-field-size").status == "fail"
    assert _verdict("bls12-381", PRE_TNFS).count("fail") == 0


def test_the_threshold_matches_its_source():
    """The number in the policy has to be the number in the citation."""
    policy = load_policy(TNFS)
    criterion = next(c for c in policy.criteria if c.id == "embedding-field-size")
    assert criterion.value == "5004"
    assert "5004" in criterion.model["note"]
    assert "Barbulescu" in criterion.citation


def test_every_model_note_shows_where_its_number_came_from():
    """A threshold with a model but no derivation is the defect this
    whole wave was about."""
    for name in (TNFS, PRE_TNFS):
        policy = load_policy(name)
        for criterion in policy.criteria:
            if criterion.model is None:
                continue
            note = criterion.model.get("note", "")
            assert note, f"{name}/{criterion.id}: model with no note"
            assert any(ch.isdigit() for ch in note), (
                f"{name}/{criterion.id}: the note cites no number"
            )
            assert criterion.value is None or criterion.value in note, (
                f"{name}/{criterion.id}: the threshold does not appear in its note"
            )


def test_the_exact_field_size_is_used_not_an_upper_bound():
    """bits(p) * k overstates bits(p^k), and overstates it in the
    direction that flatters the curve under `at least`."""
    if not _ready("test_the_exact_field_size_is_used_not_an_upper_bound",
                  "bls12-381"):
        return
    bundle = _bundle("bls12-381")
    p = int(bundle.by_name("field.characteristic").asserts["p"])
    degree = int(bundle.by_name("curve.embedding").asserts["degree"])
    exact = (p**degree).bit_length()
    approximate = p.bit_length() * degree
    assert exact < approximate          # 4569 against 4572
    outcome = _outcome(_verdict("bls12-381", TNFS), "embedding-field-size")
    assert outcome.detail.startswith(str(exact))


def test_a_prime_field_curve_cannot_be_raised_to_its_degree():
    """Its embedding degree is a 254-bit number, so the criterion is
    undecided rather than failed — and undecided still blocks a pass."""
    if not _ready("test_a_prime_field_curve_cannot_be_raised_to_its_degree",
                  "secp256k1"):
        return
    verdict = _verdict("secp256k1", TNFS)
    outcome = _outcome(verdict, "embedding-field-size")
    assert outcome.status == "undecided"
    assert verdict.result != "passes"


# -- the structural policy --------------------------------------------


def test_both_pairing_curves_are_structurally_suitable():
    if not _ready("test_both_pairing_curves_are_structurally_suitable",
                  "bls12-381", "bn254"):
        return
    for curve in ("bls12-381", "bn254"):
        verdict = _verdict(curve, SUITABILITY)
        assert verdict.count("fail") == 0, curve
        assert verdict.count("undecided") == 0, curve


def test_a_prime_field_curve_is_not_pairing_suitable():
    """secp256k1 has a huge embedding degree, which is a virtue there and
    disqualifying here. The same fact, opposite verdicts."""
    if not _ready("test_a_prime_field_curve_is_not_pairing_suitable", "secp256k1"):
        return
    verdict = _verdict("secp256k1", SUITABILITY)
    assert _outcome(verdict, "pairing-exists").status == "fail"


def test_safecurves_and_suitability_disagree_about_the_same_curve():
    """The clearest statement of the design: one bundle, two policies
    written for different purposes, both correct."""
    if not _ready("test_safecurves_and_suitability_disagree_about_the_same_curve",
                  "bls12-381"):
        return
    suitable = _verdict("bls12-381", SUITABILITY)
    safe = _verdict("bls12-381", "safecurves-2024")
    assert suitable.count("fail") == 0
    assert safe.count("fail") > 0
    # And the criterion they disagree on is the embedding degree.
    assert _outcome(suitable, "pairing-exists").status == "pass"
    assert _outcome(safe, "transfers").status == "fail"


# -- the multiplied fact ----------------------------------------------


def test_the_field_size_comes_from_two_proved_claims():
    """The engine raises one fact to another and measures the result. It
    computes; it does not model."""
    if not _ready("test_the_field_size_comes_from_two_proved_claims",
                  "bls12-381"):
        return
    bundle = _bundle("bls12-381")
    p = int(bundle.by_name("field.characteristic").asserts["p"])
    degree = int(bundle.by_name("curve.embedding").asserts["degree"])
    outcome = _outcome(_verdict("bls12-381", TNFS), "embedding-field-size")
    assert outcome.detail.startswith(str((p**degree).bit_length()))


def test_an_undecidable_criterion_blocks_rather_than_passes():
    """A curve with no embedding claim must not slip through the product."""
    if not _ready("test_an_undecidable_criterion_blocks_rather_than_passes",
                  "secp256k1"):
        return
    verdict = _verdict("secp256k1", TNFS)
    outcome = _outcome(verdict, "g2-subgroup-security")
    assert outcome.status == "undecided"
    assert "g2.order" in outcome.detail


# -- the order of operations ------------------------------------------


def test_observe_transforms_after_the_power_not_before():
    """The regression for a bug that passed every test it had.

    Applying `bits` before the exponentiation computes bits(p) ** k. For
    BN254 that is 254 ** 12, whose bit length is 96 — against a threshold
    of 5004, so the criterion still failed and the verdict still matched.
    The expectations below are worked out by hand rather than read off
    the implementation, which is the only way this kind of mistake shows.
    """
    from core.policy.engine import _observe, Criterion

    if not _ready("test_observe_transforms_after_the_power_not_before", "bn254"):
        return
    bundle = _bundle("bn254")
    p = int(bundle.by_name("field.characteristic").asserts["p"])

    criterion = Criterion(
        id="x", description="", claim="field.characteristic", field="p",
        transform="bits", op="ge", value="1",
        pow={"claim": "curve.embedding", "field": "degree"},
    )
    observed = _observe(bundle, load_policy(TNFS), criterion)

    assert observed == (p**12).bit_length()
    assert observed == 3044
    assert observed != (p.bit_length() ** 12).bit_length()   # 96, the old bug
    assert observed != p.bit_length() * 12                   # 3048, the bound


def test_observe_without_arithmetic_is_the_plain_reading():
    from core.policy.engine import _observe, Criterion

    if not _ready("test_observe_without_arithmetic_is_the_plain_reading", "bn254"):
        return
    bundle = _bundle("bn254")
    n = int(bundle.by_name("curve.order").asserts["n"])
    criterion = Criterion(
        id="x", description="", claim="curve.order", field="n",
        transform="bits", op="ge", value="1",
    )
    assert _observe(bundle, load_policy(TNFS), criterion) == n.bit_length()
    assert _observe(bundle, load_policy(TNFS), criterion) == 254


def test_observe_multiplies_before_transforming():
    """`times` is the older operation and keeps its meaning: the product
    is formed first, the transform describes the result."""
    from core.policy.engine import _observe, Criterion

    if not _ready("test_observe_multiplies_before_transforming", "bn254"):
        return
    bundle = _bundle("bn254")
    p = int(bundle.by_name("field.characteristic").asserts["p"])
    criterion = Criterion(
        id="x", description="", claim="field.characteristic", field="p",
        transform="bits", op="ge", value="1",
        times={"claim": "curve.embedding", "field": "degree"},
    )
    assert _observe(bundle, load_policy(TNFS), criterion) == (p * 12).bit_length()


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
                print(f"skip  {name}  (build the corpus first)")
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
