"""Tests for the certificate diff.

Run it directly:

    python tests\\test_ccert_diff.py

A byte diff of a certificate is useless: the payloads are walls of
decimal digits and adding one claim reorders the evidence pool. The
question anyone actually has when a digest moves is what the document
says now that it did not before.

What the tests insist on, in order of how much it matters:

Weakening must be visible. A claim that dropped from proved to derived is
the most consequential thing that can happen to a certificate and the
least visible in a diff, because the words around it barely change.

Silence about what did not move. A change that added one claim should
produce one line; anything else buries the answer.

And the tool must not verify. Both files may be nonsense and it should
still describe the difference, because that is exactly the situation you
reach for it in.
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.bundle.model import EVIDENCE_TIERS
from tools.ccert_diff import diff

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "spec" / "vectors" / "valid"

SKIPPED = []


def _ready(name, *curves):
    for curve in curves:
        if not (VECTORS / f"{curve}.ccert").is_file():
            SKIPPED.append(name)
            return False
    return True


def _load(curve):
    return json.loads((VECTORS / f"{curve}.ccert").read_text(encoding="utf-8"))


def _diff(old, new):
    return diff(old, new, EVIDENCE_TIERS)


def _kinds(changes):
    return {change.kind for change in changes}


def _run(old_path, new_path, *flags):
    result = subprocess.run(
        [sys.executable, "-m", "tools.ccert_diff", str(old_path), str(new_path), *flags],
        capture_output=True, text=True, cwd=ROOT,
    )
    return result.returncode, result.stdout


# -- nothing moved -----------------------------------------------------


def test_a_file_against_itself_reports_nothing():
    if not _ready("test_a_file_against_itself_reports_nothing", "bn254"):
        return
    assert _diff(_load("bn254"), _load("bn254")) == []


def test_identical_files_exit_zero():
    if not _ready("test_identical_files_exit_zero", "bn254"):
        return
    path = VECTORS / "bn254.ccert"
    code, output = _run(path, path)
    assert code == 0
    assert "identical bytes" in output


# -- weakening ---------------------------------------------------------


def test_a_dropped_tier_is_reported_as_alarming():
    """The case the tool exists for. Nothing else in the rendered output
    would change enough to notice."""
    if not _ready("test_a_dropped_tier_is_reported_as_alarming", "bls12-381"):
        return
    old = _load("bls12-381")
    new = json.loads(json.dumps(old))
    for claim in new["claims"]:
        if claim["claim"] == "g2.cardinality":
            claim["evidence"]["type"] = "candidate.sea"
    changes = _diff(old, new)
    weakened = [c for c in changes if c.kind == "tier-weakened"]
    assert len(weakened) == 1
    assert weakened[0].claim == "g2.cardinality"
    assert weakened[0].detail == "A -> X"
    assert weakened[0].severity == "alarming"


def test_a_strengthened_tier_is_reported_but_not_alarming():
    if not _ready("test_a_strengthened_tier_is_reported_but_not_alarming",
                  "bls12-381"):
        return
    old = _load("bls12-381")
    new = json.loads(json.dumps(old))
    for claim in old["claims"]:
        if claim["claim"] == "twist.cardinality":
            claim["evidence"]["type"] = "candidate.sea"
    changes = _diff(old, new)
    strengthened = [c for c in changes if c.kind == "tier-strengthened"]
    assert len(strengthened) == 1
    assert strengthened[0].severity != "alarming"


def test_a_removed_claim_is_alarming():
    if not _ready("test_a_removed_claim_is_alarming", "bls12-381"):
        return
    old = _load("bls12-381")
    new = json.loads(json.dumps(old))
    new["claims"] = [c for c in new["claims"] if c["claim"] != "curve.family"]
    changes = _diff(old, new)
    removed = [c for c in changes if c.kind == "claim-removed"]
    assert len(removed) == 1 and removed[0].severity == "alarming"


def test_a_removed_dependency_is_alarming():
    """An undeclared dependency is how a claim comes to rest on something
    nobody checked, so its disappearance is worth a line of its own."""
    if not _ready("test_a_removed_dependency_is_alarming", "bls12-381"):
        return
    old = _load("bls12-381")
    new = json.loads(json.dumps(old))
    for claim in new["claims"]:
        if claim["claim"] == "curve.order":
            claim["depends_on"] = ["curve.order.prime"]
    changes = _diff(old, new)
    dropped = [c for c in changes if c.kind == "dependency-removed"]
    assert dropped and all(c.severity == "alarming" for c in dropped)


def test_weakening_sets_a_non_zero_exit_code():
    """So a release can be gated on it without anyone reading the
    output."""
    if not _ready("test_weakening_sets_a_non_zero_exit_code", "bls12-381"):
        return
    import tempfile

    new = _load("bls12-381")
    new["claims"] = [c for c in new["claims"] if c["claim"] != "curve.family"]
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".ccert", delete=False, encoding="utf-8", newline="\n"
    )
    handle.write(json.dumps(new, sort_keys=True, separators=(",", ":")) + "\n")
    handle.close()
    code, _ = _run(VECTORS / "bls12-381.ccert", handle.name)
    assert code == 1


# -- growth ------------------------------------------------------------


def test_an_added_claim_produces_one_line():
    """The whole output for a change that added one claim."""
    if not _ready("test_an_added_claim_produces_one_line", "bls12-381"):
        return
    new = _load("bls12-381")
    old = json.loads(json.dumps(new))
    old["claims"] = [c for c in old["claims"] if c["claim"] != "g2.twist"]
    changes = _diff(old, new)
    assert len(changes) == 1
    assert changes[0].kind == "claim-added"
    assert changes[0].claim == "g2.twist"


def test_an_added_assertion_is_not_alarming():
    """Growth is the ordinary case: the format only ever adds."""
    if not _ready("test_an_added_assertion_is_not_alarming", "bls12-381"):
        return
    new = _load("bls12-381")
    old = json.loads(json.dumps(new))
    for claim in old["claims"]:
        if claim["claim"] == "curve.embedding":
            claim["asserts"].pop("two_adicity", None)
    changes = _diff(old, new)
    assert [c.kind for c in changes] == ["assert-added"]
    assert changes[0].severity == "info"


def test_a_changed_assertion_is_alarming():
    """A number that moved is the thing most likely to matter and least
    likely to be noticed."""
    if not _ready("test_a_changed_assertion_is_alarming", "bn254"):
        return
    old = _load("bn254")
    new = json.loads(json.dumps(old))
    for claim in new["claims"]:
        if claim["claim"] == "curve.embedding":
            claim["asserts"]["degree"] = "11"
    changes = _diff(old, new)
    assert changes[0].kind == "assert-changed"
    assert changes[0].severity == "alarming"


# -- the subject -------------------------------------------------------


def test_a_changed_subject_is_reported_first():
    """It makes every other difference meaningless, so it goes on top."""
    if not _ready("test_a_changed_subject_is_reported_first", "bn254", "bls12-381"):
        return
    changes = _diff(_load("bn254"), _load("bls12-381"))
    assert changes[0].kind == "subject"
    assert all(c.severity == "alarming" for c in changes[:3])


# -- it does not verify ------------------------------------------------


def test_nonsense_is_still_described():
    """The situation you reach for this tool in is one where a file
    stopped verifying and you want to know why."""
    old = {"subject": {"label": "toy"}, "claims": [
        {"claim": "field.characteristic", "asserts": {"p": "7"},
         "evidence": {"type": "proof.ecpp", "ref": "x"}}]}
    new = {"subject": {"label": "toy"}, "claims": []}
    changes = _diff(old, new)
    assert len(changes) == 1
    assert changes[0].kind == "claim-removed"


def test_an_unknown_evidence_type_does_not_crash():
    """A tier of `?` rather than an exception: describing a broken file is
    the job."""
    old = {"claims": [{"claim": "x", "asserts": {},
                       "evidence": {"type": "invented.kind"}}]}
    new = {"claims": []}
    changes = _diff(old, new)
    assert changes[0].detail == "?"


# -- machine output ----------------------------------------------------


def test_the_json_form_carries_both_digests():
    if not _ready("test_the_json_form_carries_both_digests", "bn254", "bls12-381"):
        return
    code, output = _run(
        VECTORS / "bn254.ccert", VECTORS / "bls12-381.ccert", "--json"
    )
    parsed = json.loads(output)
    assert parsed["old_digest"].startswith("sha256:")
    assert parsed["new_digest"] != parsed["old_digest"]
    assert parsed["identical"] is False
    assert parsed["changes"]


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
