"""Tests for `--explain`.

Run it directly:

    python tests\\test_explain.py

The ordinary output answers "is this proved". The question a reader
actually has is "proved on top of what", and the verifier already knows:
pass one walks the dependency graph and refuses any edge that is missing
or standing too low. Printing that walk costs nothing.

What the tests are really about is one property. A proved claim may not
rest on anything below proved, and a derived one may not rest on a bare
candidate — so a tier is not a label on a single claim, it is a statement
about everything beneath it. The tree makes that visible, and the check
for a violation is deliberately one that can never fire on a bundle the
verifier accepted.
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "spec" / "vectors" / "valid"

SKIPPED = []


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


def _explain(curve):
    result = subprocess.run(
        [str(_binary()), "--explain", str(VECTORS / f"{curve}.ccert")],
        capture_output=True, text=True,
    )
    return result.returncode, result.stdout + result.stderr


def _claims(curve):
    document = json.loads((VECTORS / f"{curve}.ccert").read_text(encoding="utf-8"))
    return {claim["claim"]: claim for claim in document["claims"]}


# -- the tree ----------------------------------------------------------


def test_every_claim_gets_a_tree():
    if not _ready("test_every_claim_gets_a_tree", "bls12-381"):
        return
    code, output = _explain("bls12-381")
    assert code == 0
    for name in _claims("bls12-381"):
        assert f"{name}  [" in output, name


def test_a_claim_with_no_dependencies_says_so():
    """Rather than showing an empty branch, which reads as truncation."""
    if not _ready("test_a_claim_with_no_dependencies_says_so", "secp256k1"):
        return
    _, output = _explain("secp256k1")
    assert "rests on nothing else in this bundle" in output


def test_the_edges_match_the_document():
    """The tree is built from what the verification carried out, not from
    a second reading of the file. It has to agree with the file
    regardless."""
    if not _ready("test_the_edges_match_the_document", "curve25519"):
        return
    _, output = _explain("curve25519")
    for name, claim in _claims("curve25519").items():
        for dependency in claim.get("depends_on", []):
            # Somewhere under this claim's heading, the dependency appears.
            section = output.split(f"{name}  [")[1].split("\n\n")[0]
            assert dependency in section, f"{name} -> {dependency}"


def test_a_repeated_subtree_is_not_repeated():
    """The graph is acyclic but not a tree, and printing a whole subtree
    twice buries the part that is new."""
    if not _ready("test_a_repeated_subtree_is_not_repeated", "bls12-381"):
        return
    _, output = _explain("bls12-381")
    assert "shown above" in output


def test_deep_chains_are_shown_to_their_leaves():
    """A tree that stopped one level down would answer nothing: the
    question is how far the proof goes before it stops being one."""
    if not _ready("test_deep_chains_are_shown_to_their_leaves", "bls12-381"):
        return
    _, output = _explain("bls12-381")
    # `g2.order` rests on `g2.cardinality`, which rests on
    # `field.characteristic`: three levels, so the deepest indent appears.
    section = output.split("g2.order  [")[1].split("\n\n")[0]
    assert "g2.cardinality" in section
    assert "field.characteristic" in section


# -- the property it exists to show ------------------------------------


def test_the_tier_rule_is_stated():
    if not _ready("test_the_tier_rule_is_stated", "bn254"):
        return
    _, output = _explain("bn254")
    assert "nothing proved rests on anything less" in output


def test_no_claim_overstates_what_is_beneath_it():
    """The check that can never fire, and the reason it cannot.

    Pass one refuses a proved claim resting on anything below proved, and
    a derived one resting on a candidate. So the weakest tier under a
    claim always equals the claim's own, and this line appears only if
    those rules have been broken.
    """
    if not _ready("test_no_claim_overstates_what_is_beneath_it",
                  "secp256k1", "bls12-381", "bls24-509", "curve25519"):
        return
    for curve in ("secp256k1", "bls12-381", "bls24-509", "curve25519"):
        _, output = _explain(curve)
        assert "overstates it" not in output, curve


def test_the_rule_is_checked_and_not_merely_asserted():
    """A comment saying an invariant holds is not a check. The tree
    computes the floor of every claim and compares it."""
    source = (ROOT / "verifier" / "src" / "main.rs").read_text(encoding="utf-8")
    assert "fn floor(" in source
    assert "overstates it" in source


# -- it does not disturb anything --------------------------------------


def test_the_ordinary_report_is_still_printed():
    if not _ready("test_the_ordinary_report_is_still_printed", "bn254"):
        return
    _, output = _explain("bn254")
    assert "proved," in output and "not proved" in output


def test_the_exit_code_is_unchanged():
    if not _ready("test_the_exit_code_is_unchanged", "bls24-315"):
        return
    plain = subprocess.run(
        [str(_binary()), str(VECTORS / "bls24-315.ccert")],
        capture_output=True, text=True,
    )
    explained, _ = _explain("bls24-315")
    assert plain.returncode == explained == 0


def test_it_is_absent_without_the_flag():
    """A reader who did not ask should not have to scroll past it."""
    if not _ready("test_it_is_absent_without_the_flag", "bn254"):
        return
    result = subprocess.run(
        [str(_binary()), str(VECTORS / "bn254.ccert")],
        capture_output=True, text=True,
    )
    assert "What each claim rests on" not in result.stdout


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
