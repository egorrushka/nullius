"""Tests for the curve dispatcher and the published vectors.

Run it directly:

    python tests\\test_build_curve.py

Two builders exist because their parameters genuinely differ. Which
builder a name belongs to is not a fact worth repeating, and it was
repeated: the corpus script carried one list, the CI rebuild step assumed
every certificate came from the prime-field builder, and the tests named
curves by hand. The CI copy would have failed the moment a pairing curve
was published beside the others.

So the mapping lives in one module now, and these tests check that the
places which consume it stay in step with it. Nothing here needs gp: it is
all about names and files.
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.bundle.builder import KNOWN_CURVES
from core.bundle.pairing import KNOWN_PAIRING_CURVES
from tools.build_curve import ALL_CURVES, build, is_pairing

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "spec" / "vectors" / "valid"

SKIPPED = []


def _raises(exception, call, *args, **kwargs):
    try:
        call(*args, **kwargs)
    except exception:
        return True
    return False


# -- the mapping ------------------------------------------------------


def test_every_curve_belongs_to_exactly_one_builder():
    """A name in both would be resolved by precedence, which is a silent
    way to build the wrong thing."""
    assert not set(KNOWN_CURVES) & set(KNOWN_PAIRING_CURVES)
    assert set(ALL_CURVES) == set(KNOWN_CURVES) | set(KNOWN_PAIRING_CURVES)


def test_the_list_is_sorted_and_free_of_duplicates():
    """CI loops over it, and a shell loop over a shuffled list produces a
    different log every run for no reason."""
    assert list(ALL_CURVES) == sorted(set(ALL_CURVES))


def test_pairing_curves_are_recognised():
    assert is_pairing("bls12-381")
    assert is_pairing("bn254")
    assert not is_pairing("secp256k1")
    assert not is_pairing("p-256")


def test_an_unknown_name_raises():
    # Not a name that might later be added: `curve25519` was the example
    # here until it became a real entry, and the test then passed for the
    # wrong reason before failing for a confusing one.
    assert _raises(KeyError, build, "not-a-curve-at-all", None)


# -- the command line CI depends on -----------------------------------


def test_the_list_command_prints_one_name_per_line():
    """The CI rebuild step reads this. If the format changes, the loop
    silently iterates over something else."""
    result = subprocess.run(
        [sys.executable, "-m", "tools.build_curve", "--list"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr
    printed = result.stdout.split()
    assert printed == list(ALL_CURVES)


def test_an_unknown_curve_exits_with_a_code():
    result = subprocess.run(
        [sys.executable, "-m", "tools.build_curve", "--curve", "nonsense"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode == 2
    assert "unknown curve" in result.stderr


def test_calling_it_with_nothing_is_an_error():
    result = subprocess.run(
        [sys.executable, "-m", "tools.build_curve"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode != 0


# -- the published vectors --------------------------------------------


def test_every_known_curve_has_a_published_vector():
    """CI compares each rebuild against a vector. A curve with no vector
    would go unchecked, which is the failure that hides best: everything
    passes and one curve is simply never tested."""
    if not VECTORS.is_dir():
        SKIPPED.append("test_every_known_curve_has_a_published_vector")
        return
    missing = [
        name for name in ALL_CURVES if not (VECTORS / f"{name}.ccert").is_file()
    ]
    assert not missing, f"no published vector for: {', '.join(missing)}"


def test_no_vector_is_orphaned():
    """The other direction: a vector for a curve nothing can rebuild would
    fail CI with a confusing message rather than a clear one."""
    if not VECTORS.is_dir():
        SKIPPED.append("test_no_vector_is_orphaned")
        return
    extra = [
        path.stem for path in VECTORS.glob("*.ccert") if path.stem not in ALL_CURVES
    ]
    assert not extra, f"vectors nothing can rebuild: {', '.join(extra)}"


def test_the_vectors_are_canonical_bytes():
    """One trailing newline, no carriage returns. Windows adds them, and a
    vector with CRLF fails the byte comparison on every platform."""
    if not VECTORS.is_dir():
        SKIPPED.append("test_the_vectors_are_canonical_bytes")
        return
    for path in sorted(VECTORS.glob("*.ccert")):
        raw = path.read_bytes()
        assert b"\r" not in raw, f"{path.name} has carriage returns"
        assert raw.endswith(b"\n"), f"{path.name} does not end with a newline"
        assert not raw.endswith(b"\n\n"), f"{path.name} ends with a blank line"


def test_the_corpus_matches_the_vectors():
    """If the working corpus and the published vectors disagree, one of
    them is stale and CI will fail on whichever is checked in."""
    corpus = ROOT / "corpus"
    if not (VECTORS.is_dir() and corpus.is_dir()):
        SKIPPED.append("test_the_corpus_matches_the_vectors")
        return
    for path in sorted(VECTORS.glob("*.ccert")):
        local = corpus / path.name
        if not local.is_file():
            continue
        assert local.read_bytes() == path.read_bytes(), (
            f"{path.name} differs between corpus/ and spec/vectors/valid/"
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
