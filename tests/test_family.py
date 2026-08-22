"""Tests for the family claim.

Run it directly:

    python tests\\test_family.py

BLS12 and BN curves are generated, not chosen: one integer determines the
characteristic, the subgroup order and the trace. Proving membership does
for a pairing curve what `check.seed-derivation` does for P-256 — it
answers "why these numbers and not others" arithmetically instead of by
pointing at a standard.

The tests are mostly about refusals, and about the two implementations
agreeing. The polynomials are written out twice on purpose, once in
Python and once in Rust, so a transcription error in one has somewhere to
show up; a test that compared them by sharing a constant would defeat
that.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.bundle.pairing import KNOWN_PAIRING_CURVES
from core.claims.family import FAMILIES, FamilyError, check_against, derive

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "spec" / "vectors" / "valid"

SKIPPED = []

BLS = KNOWN_PAIRING_CURVES["bls12-381"]
BN = KNOWN_PAIRING_CURVES["bn254"]
BLS_H1 = 76329603384216526031706109802092473003


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


def _raises(exception, call, *args, **kwargs):
    try:
        call(*args, **kwargs)
    except exception:
        return True
    return False


# -- the polynomials --------------------------------------------------


def test_bls12_381_is_generated_by_its_parameter():
    p, r, t = derive("bls12", BLS["u"])
    assert p == BLS["p"]
    assert r == BLS["r"]
    assert t == p + 1 - BLS_H1 * BLS["r"]


def test_bn254_is_generated_by_its_parameter():
    p, r, t = derive("bn", BN["u"])
    assert p == BN["p"]
    assert r == BN["r"]
    # BN curves have cofactor 1, so #E = r.
    assert t == p + 1 - BN["r"]


def test_the_bls12_parameter_is_negative():
    """Which is the reason everything here is signed arithmetic."""
    assert BLS["u"] < 0
    assert derive("bls12", BLS["u"])[2] < 0    # so is the trace


def test_an_unknown_family_is_refused():
    """A family nobody can check is not a claim."""
    assert _raises(FamilyError, derive, "kss16", 1)
    assert _raises(FamilyError, derive, "", 1)


def test_a_parameter_that_generates_nothing_is_refused():
    """For BLS12 the division by three has to be exact. Most integers are
    not valid parameters, and a floor division would hand back a number
    that looks exactly like a characteristic."""
    refused = 0
    for u in range(2, 60):
        try:
            derive("bls12", u)
        except FamilyError:
            refused += 1
    assert refused > 0, "no parameter in the sample was refused, so nothing was tested"


def test_a_wrong_parameter_does_not_match_the_curve():
    assert _raises(
        FamilyError, check_against, "bls12", BLS["u"] + 1, BLS["p"], BLS["r"],
        BLS_H1 * BLS["r"],
    )


def test_the_sign_of_the_parameter_matters():
    assert _raises(
        FamilyError, check_against, "bls12", -BLS["u"], BLS["p"], BLS["r"],
        BLS_H1 * BLS["r"],
    )


def test_a_family_mismatch_is_refused():
    """BN polynomials at the BLS parameter, and the other way round."""
    assert _raises(
        FamilyError, check_against, "bn", BLS["u"], BLS["p"], BLS["r"],
        BLS_H1 * BLS["r"],
    )
    assert _raises(
        FamilyError, check_against, "bls12", BN["u"], BN["p"], BN["r"], BN["r"],
    )


def test_each_family_states_its_embedding_degree():
    """A property of the family, checked independently by
    `curve.embedding`. The two agreeing is worth something.

    BLS12 and BN are degree 12; BLS24 is 24, which is the whole reason it
    reaches a larger embedding field with a smaller characteristic.
    """
    expected = {"bls12": 12, "bn": 12, "bls24": 24}
    assert set(FAMILIES) == set(expected)
    for name, (_polynomials, degree) in FAMILIES.items():
        assert degree == expected[name], name


# -- the claim in a bundle --------------------------------------------


def test_both_pairing_curves_carry_a_family_claim():
    if not _ready("test_both_pairing_curves_carry_a_family_claim",
                  "bls12-381", "bn254"):
        return
    for curve in ("bls12-381", "bn254"):
        document = json.loads(
            (VECTORS / f"{curve}.ccert").read_text(encoding="utf-8")
        )
        claim = next(
            c for c in document["claims"] if c["claim"] == "curve.family"
        )
        assert claim["evidence"]["type"] == "check.family"
        assert set(claim["depends_on"]) >= {
            "field.characteristic", "curve.order.prime", "curve.cardinality",
        }


def test_the_verifier_re_derives_the_family():
    if not _ready("test_the_verifier_re_derives_the_family", "bn254"):
        return
    _, output = _run(VECTORS / "bn254.ccert")
    assert "curve.family" in output
    assert "bn polynomials" in output


def test_prime_field_curves_carry_no_family_claim():
    """They belong to no family, and saying nothing is the honest option."""
    if not _ready("test_prime_field_curves_carry_no_family_claim", "secp256k1"):
        return
    document = json.loads(
        (VECTORS / "secp256k1.ccert").read_text(encoding="utf-8")
    )
    assert all(c["claim"] != "curve.family" for c in document["claims"])


def test_a_tampered_parameter_is_refused_by_the_verifier():
    """The Rust polynomials are a separate transcription, so this also
    tests that the two agree."""
    if not _ready("test_a_tampered_parameter_is_refused_by_the_verifier", "bn254"):
        return
    import hashlib

    document = json.loads((VECTORS / "bn254.ccert").read_text(encoding="utf-8"))
    claim = next(c for c in document["claims"] if c["claim"] == "curve.family")
    payload = document["evidence"].pop(claim["evidence"]["ref"])
    payload["u"] = str(int(payload["u"]) + 1)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    document["evidence"][digest] = payload
    claim["evidence"]["ref"] = digest
    claim["asserts"]["u"] = payload["u"]

    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".ccert", delete=False, encoding="utf-8", newline="\n"
    )
    handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    handle.close()
    code, output = _run(Path(handle.name))
    assert code != 0
    assert "family polynomial" in output


def test_the_rust_polynomials_are_written_out_separately():
    """Not shared with Python, deliberately: one transcription error
    should have somewhere to show up."""
    source = (ROOT / "verifier" / "src" / "family.rs").read_text(encoding="utf-8")
    assert "36u32" in source          # the BN coefficients
    assert "divisible by 3" in source  # the BLS exactness check
    assert "BigInt" in source          # signed throughout


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
