"""Tests for the policy layer.

The engine's job is to read proved facts and compare them. Most of what can
go wrong is a policy that quietly approves something, so that is what most
of these check.
"""

import json
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml", reason="pip install pyyaml")

from core.bundle.model import Bundle
from core.policy import engine

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "spec" / "vectors" / "valid"
GOLDEN = VECTORS / "secp256k1.ccert"
P256 = VECTORS / "p-256.ccert"

needs_golden = pytest.mark.skipif(not GOLDEN.is_file(), reason="golden vector missing")


def bundle(path: Path = GOLDEN) -> Bundle:
    return Bundle.from_obj(json.loads(path.read_text(encoding="utf-8")))


def write_policy(tmp_path: Path, body: dict) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(body), encoding="utf-8")
    return path


def minimal(**overrides) -> dict:
    criterion = {
        "id": "cofactor",
        "description": "the group must have prime order",
        "claim": "curve.order",
        "field": "cofactor",
        "op": "eq",
        "value": "1",
    }
    criterion.update(overrides.pop("criterion", {}))
    document = {
        "name": "test",
        "title": "Test policy",
        "source": "invented for the test suite",
        "criteria": [criterion],
    }
    document.update(overrides)
    return document


# -- the point of the whole design ----------------------------------


@needs_golden
def test_the_same_facts_yield_opposite_verdicts():
    """One proved discriminant, two policies, two answers."""
    facts = bundle()
    strict = engine.evaluate(facts, engine.load_policy("safecurves-2024"))
    glv = engine.evaluate(facts, engine.load_policy("glv-endomorphism"))

    cm_strict = next(o for o in strict.outcomes if o.criterion.id == "complex-multiplication")
    cm_glv = next(o for o in glv.outcomes if o.criterion.id == "small-discriminant")
    assert cm_strict.status == "fail"
    assert cm_glv.status == "pass"


@pytest.mark.skipif(not P256.is_file(), reason="P-256 vector missing")
def test_two_curves_split_on_the_same_criterion():
    """The discriminant criterion separates the curves, not the policies."""
    policy = engine.load_policy("safecurves-2024")
    verdicts = {
        name: engine.evaluate(bundle(path), policy)
        for name, path in (("secp256k1", GOLDEN), ("p-256", P256))
    }
    statuses = {
        name: next(
            o.status for o in verdict.outcomes if o.criterion.id == "complex-multiplication"
        )
        for name, verdict in verdicts.items()
    }
    assert statuses == {"secp256k1": "fail", "p-256": "pass"}


@needs_golden
def test_missing_evidence_is_undecided_not_approval():
    verdict = engine.evaluate(bundle(), engine.load_policy("safecurves-2024"))
    undecided = [o for o in verdict.outcomes if o.status == "undecided"]
    assert undecided, "the shipped policy should show its gaps"
    assert verdict.result != "passes"


@needs_golden
def test_an_undecided_criterion_blocks_a_pass(tmp_path):
    document = minimal(
        criterion={
            "id": "absent",
            "claim": "twist.security",
            "field": "largest_prime_factor",
        }
    )
    verdict = engine.evaluate(bundle(), engine.load_policy(write_policy(tmp_path, document)))
    assert verdict.outcomes[0].status == "undecided"
    assert verdict.result == "cannot be decided"


@needs_golden
def test_a_candidate_does_not_count_as_a_fact(tmp_path):
    """A policy that accepts only proof must ignore what a program reported."""
    facts = bundle()
    facts.add_claim(
        "curve.cardinality",
        {"n": "12345"},
        "candidate.sea",
        {"tool": "pari/gp"},
    )
    document = minimal(
        accept_tiers=["A"],
        criterion={
            "id": "cardinality",
            "claim": "curve.cardinality",
            "field": "n",
            "op": "eq",
            "value": "12345",
        },
    )
    verdict = engine.evaluate(facts, engine.load_policy(write_policy(tmp_path, document)))
    assert verdict.outcomes[0].status == "undecided"


# -- comparisons ----------------------------------------------------


@needs_golden
def test_threshold_from_another_claim(tmp_path):
    """SafeCurves states the transfer bound relative to n, not absolutely."""
    document = minimal(
        criterion={
            "id": "transfers",
            "claim": "curve.embedding",
            "field": "degree",
            "op": "ge",
            "value": None,
            "value_from": {"claim": "curve.order", "field": "n", "minus": 1, "over": 100},
        }
    )
    document["criteria"][0].pop("value")
    verdict = engine.evaluate(bundle(), engine.load_policy(write_policy(tmp_path, document)))
    assert verdict.outcomes[0].status == "pass"


@needs_golden
def test_absolute_value_transform(tmp_path):
    """The discriminant is negative; a policy speaks about its magnitude."""
    document = minimal(
        criterion={
            "id": "cm",
            "claim": "curve.cm",
            "field": "fundamental",
            "transform": "abs",
            "op": "eq",
            "value": "3",
        }
    )
    verdict = engine.evaluate(bundle(), engine.load_policy(write_policy(tmp_path, document)))
    assert verdict.outcomes[0].status == "pass"


def test_power_notation():
    assert engine._literal("2^100") == 2**100
    assert engine._literal("1267650600228229401496703205376") == 2**100


# -- malformed policies are refused ---------------------------------


def test_unknown_operator(tmp_path):
    document = minimal(criterion={"op": "approximately"})
    with pytest.raises(engine.PolicyError):
        engine.load_policy(write_policy(tmp_path, document))


def test_unknown_transform(tmp_path):
    document = minimal(criterion={"transform": "square"})
    with pytest.raises(engine.PolicyError):
        engine.load_policy(write_policy(tmp_path, document))


def test_unknown_key_is_refused(tmp_path):
    document = minimal()
    document["criteria"][0]["unless"] = "monday"
    with pytest.raises(engine.PolicyError):
        engine.load_policy(write_policy(tmp_path, document))


def test_a_criterion_needs_exactly_one_threshold(tmp_path):
    document = minimal()
    document["criteria"][0]["value_from"] = {"claim": "curve.order", "field": "n"}
    with pytest.raises(engine.PolicyError):
        engine.load_policy(write_policy(tmp_path, document))

    document = minimal()
    document["criteria"][0].pop("value")
    with pytest.raises(engine.PolicyError):
        engine.load_policy(write_policy(tmp_path, document))


def test_duplicate_criterion_ids(tmp_path):
    document = minimal()
    document["criteria"].append(dict(document["criteria"][0]))
    with pytest.raises(engine.PolicyError):
        engine.load_policy(write_policy(tmp_path, document))


def test_empty_policy(tmp_path):
    document = minimal()
    document["criteria"] = []
    with pytest.raises(engine.PolicyError):
        engine.load_policy(write_policy(tmp_path, document))


def test_missing_policy_name():
    with pytest.raises(engine.PolicyError):
        engine.load_policy("no-such-policy")


# -- the shipped policies must themselves be well formed ------------


@pytest.mark.parametrize("name", engine.available_policies())
def test_shipped_policy_loads(name):
    policy = engine.load_policy(name)
    assert policy.criteria
    assert policy.source.strip(), f"{name} must cite where its criteria come from"
    for criterion in policy.criteria:
        assert criterion.description.strip()


@pytest.mark.skipif(not P256.is_file(), reason="P-256 vector missing")
def test_rigidity_separates_the_two_curves():
    """P-256 publishes a seed and can prove it. secp256k1 has none, and the
    absence of a seed is not something a certificate can prove."""
    policy = engine.load_policy("safecurves-2024")
    for path, expected in ((P256, "pass"), (GOLDEN, "undecided")):
        verdict = engine.evaluate(bundle(path), policy)
        status = next(
            o.status for o in verdict.outcomes if o.criterion.id == "rigidity"
        )
        assert status == expected, f"{path.stem}: expected {expected}"
