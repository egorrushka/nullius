"""Tests for curves published in a model other than short Weierstrass.

Run it directly:

    python tests\\test_models.py

Curve25519 is a Montgomery curve and Ed25519 a twisted Edwards one, and
between them they carry a large share of the world's signatures and key
agreement. Until now neither could be certified, because the rest of the
project speaks short Weierstrass and nothing else.

The tempting shortcut is to convert quietly and certify the Weierstrass
version. That produces a document whose subject is a curve nobody uses
under a name everybody recognises, so the conversion is a claim instead:
the subject carries both the model's parameters and the Weierstrass
coefficients, and a verifier recomputes the second from the first.

What the tests keep separating is proved from applied. That the
coefficients follow from the parameters is arithmetic, and it is checked.
That the birational map relates the two curves' groups is a theorem about
the shapes, and it is not — a reader takes it from the literature the way
they take the Hasse bound.
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.bundle.builder import KNOWN_CURVES
from core.bundle.model import Bundle
from core.claims.models import ModelError, montgomery_from_edwards, to_weierstrass

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "spec" / "vectors" / "valid"

SKIPPED = []

P25519 = 2**255 - 19
R25519 = 2**252 + 27742317777372353535851937790883648493


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


def _raises(exception, call, *args, **kwargs):
    try:
        call(*args, **kwargs)
    except exception:
        return True
    return False


# -- the conversion ----------------------------------------------------


def test_curve25519_converts_to_its_published_coefficients():
    a, b = to_weierstrass("montgomery", {"A": 486662, "B": 1}, P25519)
    assert a == KNOWN_CURVES["curve25519"]["a"]
    assert b == KNOWN_CURVES["curve25519"]["b"]


def test_ed25519_gives_the_same_montgomery_parameter():
    """Its A is 486662, the same curve; only B differs, because the
    birational map from Edwards gives B = 4/(a - d) rather than 1."""
    d = (-121665 * pow(121666, -1, P25519)) % P25519
    A, B = montgomery_from_edwards(-1, d, P25519)
    assert A == 486662
    assert B != 1


def test_the_two_forms_are_isomorphic_not_identical():
    """Different B gives different Weierstrass coefficients for the same
    curve up to isomorphism. Both are certified separately rather than
    one standing in for the other; the ratio being a square is why their
    orders agree."""
    d = (-121665 * pow(121666, -1, P25519)) % P25519
    _, B = montgomery_from_edwards(-1, d, P25519)
    assert pow(B, (P25519 - 1) // 2, P25519) == 1        # B is a square
    montgomery = to_weierstrass("montgomery", {"A": 486662, "B": 1}, P25519)
    edwards = to_weierstrass("twisted-edwards", {"a": -1, "d": d}, P25519)
    assert montgomery != edwards
    assert edwards == (KNOWN_CURVES["ed25519"]["a"], KNOWN_CURVES["ed25519"]["b"])


def test_short_weierstrass_converts_to_itself():
    assert to_weierstrass("short-weierstrass", {"a": 7, "b": 11}, 103) == (7, 11)


# -- degenerate parameters ---------------------------------------------


def test_a_singular_montgomery_curve_is_refused():
    """A^2 = 4 gives x^3 + A x^2 + x a repeated root, so there is no
    curve to convert."""
    for A in (2, 103 - 2):
        assert _raises(ModelError, to_weierstrass, "montgomery", {"A": A, "B": 1}, 103)


def test_a_zero_b_is_refused():
    assert _raises(ModelError, to_weierstrass, "montgomery", {"A": 5, "B": 0}, 103)


def test_edwards_with_a_equal_to_d_is_refused():
    assert _raises(ModelError, montgomery_from_edwards, 5, 5, 103)


def test_edwards_with_zero_d_is_refused():
    assert _raises(ModelError, montgomery_from_edwards, 5, 0, 103)


def test_an_unknown_model_is_refused():
    """The list is closed. A model nobody can convert is not a claim."""
    assert _raises(ModelError, to_weierstrass, "hessian", {"a": 1}, 103)


# -- the claim in a bundle ---------------------------------------------


def test_both_curves_carry_a_model_claim():
    if not _ready("test_both_curves_carry_a_model_claim", "curve25519", "ed25519"):
        return
    for curve, model in (("curve25519", "montgomery"), ("ed25519", "twisted-edwards")):
        claim = _bundle(curve).by_name("curve.model")
        assert claim is not None, curve
        assert claim.asserts["model"] == model


def test_the_verifier_says_what_it_did_not_prove():
    """The claim name would let a reader conclude the equivalence was
    established. It was applied, not proved."""
    if not _ready("test_the_verifier_says_what_it_did_not_prove", "curve25519"):
        return
    _, output = _run(VECTORS / "curve25519.ccert")
    assert "not proved here" in output


def test_weierstrass_curves_carry_no_model_claim():
    """They are already in the shape everything else speaks, and saying
    so would be noise."""
    if not _ready("test_weierstrass_curves_carry_no_model_claim", "secp256k1"):
        return
    assert _bundle("secp256k1").by_name("curve.model") is None


# -- the cofactor path -------------------------------------------------


def test_a_cofactor_of_eight_is_certified():
    """The prime-field builder assumed cofactor one and proved the *group*
    order prime. Curve25519 has order 8r, so it failed outright — the
    refusal was right and the remedy was the argument the pairing curves
    already use."""
    if not _ready("test_a_cofactor_of_eight_is_certified", "curve25519"):
        return
    bundle = _bundle("curve25519")
    split = bundle.by_name("curve.order").asserts
    assert int(split["cofactor"]) == 8
    assert int(split["n"]) == R25519
    assert int(bundle.by_name("curve.cardinality").asserts["n"]) == 8 * R25519


def test_the_power_of_two_cofactor_is_not_refused_as_hostile():
    """The guard against an absurd exponent computed bits(p)*e, which
    overestimates for p = 2 by enough to reject a cofactor of 8 — that is
    to say, every Edwards curve. The exact bound is e*(bits(p)-1)+1."""
    if not _ready("test_the_power_of_two_cofactor_is_not_refused_as_hostile",
                  "curve25519"):
        return
    code, output = _run(VECTORS / "curve25519.ccert")
    assert code == 0, output


def test_the_embedding_degree_is_taken_modulo_the_subgroup():
    """Not the group order. They coincide at cofactor one, which is why
    this was right until a curve with cofactor 8 arrived."""
    if not _ready("test_the_embedding_degree_is_taken_modulo_the_subgroup",
                  "curve25519"):
        return
    bundle = _bundle("curve25519")
    claim = bundle.by_name("curve.embedding")
    payload = bundle.evidence[claim.evidence_ref]
    assert int(payload["modulus"]) == R25519          # not 8r


def test_the_curves_verify_end_to_end():
    if not _ready("test_the_curves_verify_end_to_end", "curve25519", "ed25519"):
        return
    for curve in ("curve25519", "ed25519"):
        code, output = _run(VECTORS / f"{curve}.ccert")
        assert code == 0, f"{curve}: {output}"
        assert "7 proved" in output


# -- the optional CM claim ---------------------------------------------


def test_the_cm_claim_is_absent_rather_than_weakened():
    """Its cost is the one step not bounded by the size of the curve: it
    factors a number as large as the discriminant, and for Curve25519
    that is 257 bits taking minutes. A producer that cannot afford it
    publishes everything else, and a policy asking about complex
    multiplication returns undecided — which blocks a pass."""
    if not _ready("test_the_cm_claim_is_absent_rather_than_weakened", "curve25519"):
        return
    from core.policy.engine import evaluate, load_policy

    bundle = _bundle("curve25519")
    assert bundle.by_name("curve.cm") is None
    verdict = evaluate(bundle, load_policy("safecurves-2024"))
    undecided = [o for o in verdict.outcomes if o.status == "undecided"]
    assert any("curve.cm" in o.detail for o in undecided)
    assert verdict.result != "passes"


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
