"""Tests that the invalid vectors are refused, and refused correctly.

Run it directly:

    python tests\\test_invalid_vectors.py

These vectors are a product, not a fixture. The claim the project makes
is that you do not have to trust it, and the way someone acts on that is
by writing a second verifier. A second implementation needs to know what
the format rules out, and prose does not say it precisely enough.

Two things are checked, and the second is the one that costs something.
Every vector must be refused; and every vector must be refused **for its
own reason**. A verifier that turns them all away on a malformed-input
check has proved nothing about the arguments underneath, and three of
these mutations behaved exactly that way when they were first written.
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.make_invalid_vectors import MUTATIONS, build_all

ROOT = Path(__file__).resolve().parent.parent
INVALID = ROOT / "spec" / "vectors" / "invalid"
VALID = ROOT / "spec" / "vectors" / "valid"

SKIPPED = []


def _binary():
    for name in ("ccert-verify.exe", "ccert-verify"):
        candidate = ROOT / "verifier" / "target" / "release" / name
        if candidate.is_file():
            return candidate
    return None


def _ready(name):
    if _binary() is None or not INVALID.is_dir():
        SKIPPED.append(name)
        return False
    return True


def _run(path):
    result = subprocess.run(
        [str(_binary()), str(path)], capture_output=True, text=True
    )
    return result.returncode, result.stdout + result.stderr


# -- the set is complete ----------------------------------------------


def test_every_mutation_has_a_vector():
    if not _ready("test_every_mutation_has_a_vector"):
        return
    for name in MUTATIONS:
        assert (INVALID / f"{name}.ccert").is_file(), name
        assert (INVALID / f"{name}.expect").is_file(), name
        assert (INVALID / f"{name}.why").is_file(), name


def test_no_vector_is_orphaned():
    """A file with no mutation behind it would never be regenerated and
    would drift out of step with the format."""
    if not _ready("test_no_vector_is_orphaned"):
        return
    for path in INVALID.glob("*.ccert"):
        assert path.stem in MUTATIONS, path.name


def test_the_catalogue_lists_them_all():
    if not _ready("test_the_catalogue_lists_them_all"):
        return
    catalogue = INVALID / "README.md"
    # A generated file, and a reviewer working in this folder removed it
    # once. Absent, `read_text` raises `FileNotFoundError` with a pathlib
    # traceback that reads like a crash and cost real time to diagnose as
    # "just run the generator". The check exists so the next person is
    # told plainly rather than left to read a stack trace.
    if not catalogue.is_file():
        raise AssertionError(
            "spec/vectors/invalid/README.md is missing; it is generated — run "
            "`python -m tools.make_invalid_vectors` to write it"
        )
    readme = catalogue.read_text(encoding="utf-8")
    for name in MUTATIONS:
        assert f"`{name}`" in readme, name


def test_each_defect_class_is_covered():
    """Named explicitly, so removing one is a deliberate act rather than
    an oversight. Each corresponds to a hole that was once open."""
    for name in (
        "foreign-curve",            # evidence about another curve
        "candidate-source",         # a proved split of an unproved number
        "undeclared-dependency",    # resting on something undeclared
        "unproved-characteristic",  # a field over a composite
        "undersized-witness",       # a witness that pins nothing
        "unreduced-coordinate",     # two spellings of one number
        "giant-exponent",           # a factor entry that costs memory
        "broken-evidence-hash",     # the pool edited without re-addressing
    ):
        assert name in MUTATIONS, name


# -- they are refused -------------------------------------------------


def test_every_vector_is_refused():
    if not _ready("test_every_vector_is_refused"):
        return
    accepted = []
    for name in sorted(MUTATIONS):
        code, _ = _run(INVALID / f"{name}.ccert")
        if code == 0:
            accepted.append(name)
    assert not accepted, f"accepted: {', '.join(accepted)}"


def test_every_vector_is_refused_for_its_own_reason():
    """The check that costs something.

    A refusal that arrives from the wrong place proves nothing about the
    argument the vector was built to attack, and it hides the fact that
    the argument was never reached.
    """
    if not _ready("test_every_vector_is_refused_for_its_own_reason"):
        return
    wrong = []
    for name in sorted(MUTATIONS):
        expected = (INVALID / f"{name}.expect").read_text(encoding="utf-8").strip()
        _, output = _run(INVALID / f"{name}.ccert")
        if expected.lower() not in output.lower():
            wrong.append(f"{name} (wanted `{expected}`)")
    assert not wrong, "; ".join(wrong)


# -- they are regenerated, not maintained -----------------------------


def test_regeneration_is_reproducible():
    """Rebuilding must produce the same bytes, or the vectors drift and
    a diff against them stops meaning anything."""
    if not _ready("test_regeneration_is_reproducible"):
        return
    before = {
        path.name: path.read_bytes() for path in sorted(INVALID.glob("*.ccert"))
    }
    build_all(INVALID)
    after = {
        path.name: path.read_bytes() for path in sorted(INVALID.glob("*.ccert"))
    }
    assert before == after


def test_each_vector_differs_from_its_source():
    """A mutation that changed nothing would produce a valid certificate
    and a test that passes by refusing nothing."""
    if not _ready("test_each_vector_differs_from_its_source"):
        return
    for name, (curve, _mutate, _expected) in sorted(MUTATIONS.items()):
        source = VALID / f"{curve}.ccert"
        if not source.is_file():
            continue
        assert (INVALID / f"{name}.ccert").read_bytes() != source.read_bytes(), name


def test_the_sources_themselves_still_verify():
    """The controls. If a source stopped verifying, every vector built
    from it would be refused for a reason that has nothing to do with its
    mutation."""
    if not _ready("test_the_sources_themselves_still_verify"):
        return
    for curve in sorted({curve for curve, _, _ in MUTATIONS.values()}):
        path = VALID / f"{curve}.ccert"
        if not path.is_file():
            continue
        code, output = _run(path)
        assert code == 0, f"{curve}: {output}"


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
