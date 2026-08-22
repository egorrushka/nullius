"""Tests for the CM discriminant, the two-adicity, and the SNARK policy.

Run it directly:

    python tests\\test_snark.py

Two facts that were being computed and thrown away. The CM discriminant
was emitted for prime-field curves from the start but not for pairing
ones, so a policy about endomorphisms could not be decided for the curves
that most obviously have them. The two-adicity of r - 1 was sitting inside
the embedding evidence, verified as part of the order argument, and
invisible to a policy because policies read assertions.

Neither is asserted on trust: both are recomputed by the verifier from
material it already re-establishes, so stating them adds nothing a reader
has to believe.

The third thing tested here is a mistake this work uncovered. Several
handlers read `curve.order` when they meant the number of points on the
curve. On a curve with cofactor one those coincide, which is why the code
was right for years and wrong the moment a pairing curve arrived.
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.bundle.model import Bundle
from core.policy.engine import evaluate, load_policy

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "spec" / "vectors" / "valid"

SKIPPED = []

# The exponent of two in r - 1, for each curve.
EXPECTED_ADICITY = {"bls12-381": 32, "bn254": 28}


def _binary():
    for name in ("ccert-verify.exe", "ccert-verify"):
        candidate = ROOT / "verifier" / "target" / "release" / name
        if candidate.is_file():
            return candidate
    return None


def _ready(name, *curves):
    if _binary() is None:
        SKIPPED.append(name)
        return False
    for curve in curves:
        if not (VECTORS / f"{curve}.ccert").is_file():
            SKIPPED.append(name)
            return False
    return True


def _run(path):
    result = subprocess.run(
        [str(_binary()), str(path)], capture_output=True, text=True
    )
    return result.returncode, result.stdout + result.stderr


def _bundle(curve):
    return Bundle.from_obj(
        json.loads((VECTORS / f"{curve}.ccert").read_text(encoding="utf-8"))
    )


# -- the CM discriminant ----------------------------------------------


def test_both_pairing_curves_state_their_discriminant():
    if not _ready("test_both_pairing_curves_state_their_discriminant",
                  "bls12-381", "bn254"):
        return
    for curve in ("bls12-381", "bn254"):
        claim = _bundle(curve).by_name("curve.cm")
        assert claim is not None, curve
        # Both families have j = 0, so D = -3.
        assert int(claim.asserts["fundamental"]) == -3, curve


def test_the_discriminant_is_what_makes_the_twists_exist():
    """D = -3 is the same fact the sextic twist enumeration rests on, and
    the two are computed independently. Agreeing is worth something."""
    if not _ready("test_the_discriminant_is_what_makes_the_twists_exist",
                  "bls12-381"):
        return
    bundle = _bundle("bls12-381")
    assert int(bundle.by_name("curve.cm").asserts["fundamental"]) == -3
    assert bundle.by_name("g2.twist") is not None


def test_the_trace_is_taken_from_the_cardinality():
    """Not from the subgroup order. On BLS12-381 the cofactor is 126 bits
    wide, so a trace computed the other way is a trace for no curve."""
    if not _ready("test_the_trace_is_taken_from_the_cardinality", "bls12-381"):
        return
    bundle = _bundle("bls12-381")
    p = int(bundle.by_name("field.characteristic").asserts["p"])
    cardinality = int(bundle.by_name("curve.cardinality").asserts["n"])
    subgroup = int(bundle.by_name("curve.order").asserts["n"])
    assert cardinality != subgroup           # the case that exposed it
    assert int(bundle.by_name("curve.cm").asserts["trace"]) == p + 1 - cardinality


def test_prime_field_curves_are_unaffected():
    """Their cofactor is one, so both readings agree, and their bytes did
    not move when the handlers were corrected."""
    if not _ready("test_prime_field_curves_are_unaffected", "secp256k1"):
        return
    code, output = _run(VECTORS / "secp256k1.ccert")
    assert code == 0
    assert "6 proved" in output


# -- the two-adicity ---------------------------------------------------


def test_the_adicity_matches_the_curve():
    if not _ready("test_the_adicity_matches_the_curve", "bls12-381", "bn254"):
        return
    for curve, expected in EXPECTED_ADICITY.items():
        stated = int(_bundle(curve).by_name("curve.embedding").asserts["two_adicity"])
        assert stated == expected, curve


def test_the_adicity_is_the_exponent_of_two_in_r_minus_one():
    """Checked here against the number itself, not against the payload,
    so this test would catch producer and verifier being wrong together."""
    if not _ready("test_the_adicity_is_the_exponent_of_two_in_r_minus_one",
                  "bls12-381", "bn254"):
        return
    for curve in ("bls12-381", "bn254"):
        bundle = _bundle(curve)
        r = int(bundle.by_name("curve.order.prime").asserts["n"])
        counted, rest = 0, r - 1
        while rest % 2 == 0:
            rest //= 2
            counted += 1
        stated = int(bundle.by_name("curve.embedding").asserts["two_adicity"])
        assert stated == counted, curve


def test_the_verifier_reports_it():
    if not _ready("test_the_verifier_reports_it", "bls12-381"):
        return
    _, output = _run(VECTORS / "bls12-381.ccert")
    assert "2-adicity 32" in output


def test_the_assertion_remains_optional():
    """Every curve in the corpus carries it now, but the verifier must
    still accept a bundle without it: the format only adds, and a
    certificate published before the assertion existed does not become
    invalid because a later one carries more."""
    if not _ready("test_the_assertion_remains_optional", "p-256"):
        return
    import hashlib
    import tempfile

    document = json.loads((VECTORS / "p-256.ccert").read_text(encoding="utf-8"))
    for claim in document["claims"]:
        if claim["claim"] == "curve.embedding":
            claim["asserts"].pop("two_adicity", None)
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".ccert", delete=False, encoding="utf-8", newline="\n"
    )
    handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    handle.close()
    code, output = _run(Path(handle.name))
    assert code == 0, output


# -- the policy --------------------------------------------------------


def test_both_pairing_curves_are_snark_suitable():
    if not _ready("test_both_pairing_curves_are_snark_suitable",
                  "bls12-381", "bn254"):
        return
    for curve in ("bls12-381", "bn254"):
        verdict = evaluate(_bundle(curve), load_policy("snark-suitability"))
        assert verdict.result == "passes", curve


def test_a_prime_field_curve_is_not():
    """secp256k1 has an embedding degree in the hundreds of bits and no
    two-adic structure to speak of."""
    if not _ready("test_a_prime_field_curve_is_not", "secp256k1"):
        return
    verdict = evaluate(_bundle("secp256k1"), load_policy("snark-suitability"))
    assert verdict.result != "passes"


def test_the_policy_names_no_model():
    """None of its thresholds is an estimate of what an attacker can
    afford, so none carries a model — and the ones that are engineering
    floors still say where the number came from."""
    policy = load_policy("snark-suitability")
    for criterion in policy.criteria:
        assert criterion.model is None, criterion.id
        assert criterion.citation, criterion.id


def test_the_snark_policy_still_asks_about_security():
    """A curve that satisfies every engineering requirement and no
    security one must not read as suitable."""
    policy = load_policy("snark-suitability")
    assert any(c.id == "subgroup-order-large" for c in policy.criteria)
    assert any(c.id == "twist-relation-established" for c in policy.criteria)


# -- twist security ----------------------------------------------------


def test_every_curve_states_its_twist_security():
    """Decidable for the whole corpus, not half of it. The criterion that
    reads this named a claim type the format never had, so it returned
    unknown for every curve and nobody noticed."""
    if not _ready("test_every_curve_states_its_twist_security",
                  "bls12-381", "bn254", "secp256k1", "p-256"):
        return
    for curve in ("bls12-381", "bn254", "secp256k1", "p-256"):
        claim = _bundle(curve).by_name("twist.cardinality")
        assert claim is not None, curve
        assert "largest_prime_factor" in claim.asserts, curve


def test_the_twist_identity_still_holds():
    if not _ready("test_the_twist_identity_still_holds", "bls12-381"):
        return
    bundle = _bundle("bls12-381")
    p = int(bundle.by_name("field.characteristic").asserts["p"])
    n = int(bundle.by_name("curve.cardinality").asserts["n"])
    twist = int(bundle.by_name("twist.cardinality").asserts["n_twist"])
    assert n + twist == 2 * p + 2


def test_the_largest_factor_is_really_the_largest():
    """Checked against the payload rather than taken from the assert, so
    this catches producer and verifier agreeing on the wrong number."""
    if not _ready("test_the_largest_factor_is_really_the_largest", "bn254"):
        return
    bundle = _bundle("bn254")
    claim = bundle.by_name("twist.cardinality")
    payload = bundle.evidence[claim.evidence_ref]
    largest = max(int(entry["prime"]) for entry in payload["factors"])
    assert int(claim.asserts["largest_prime_factor"]) == largest
    product = 1
    for entry in payload["factors"]:
        product *= int(entry["prime"]) ** int(entry["exponent"])
    assert product == int(claim.asserts["n_twist"])


def test_the_pairing_curves_have_weaker_twists():
    """A real finding rather than a formality: BN254's twist has a
    94-bit largest factor against secp256k1's 220."""
    if not _ready("test_the_pairing_curves_have_weaker_twists",
                  "bn254", "secp256k1"):
        return
    bn = int(_bundle("bn254").by_name("twist.cardinality")
             .asserts["largest_prime_factor"]).bit_length()
    secp = int(_bundle("secp256k1").by_name("twist.cardinality")
               .asserts["largest_prime_factor"]).bit_length()
    assert bn < secp


def test_the_safecurves_policy_admits_it_is_a_subset():
    """P-256 passes this policy and fails the real SafeCurves. The policy
    has to say so, or a pass here reads as a pass there."""
    policy = load_policy("safecurves-2024")
    assert "subset" in policy.title.lower() or "partial" in policy.source.lower()
    assert "manipulable" in policy.source or "seed itself" in policy.source
    rigidity = next(c for c in policy.criteria if c.id == "rigidity")
    assert "weaker half" in rigidity.description


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
