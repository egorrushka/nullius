"""Tests that the Rust verifier accepts the pairing bundle and refuses
tampered copies of it.

Run it directly:

    python tests\\test_verifier_pairing.py

This is the test that matters most in the whole set. Everything else
checks that the producer is consistent with itself; this one checks that a
program written in another language, which shares no code with the
producer, reaches the same conclusion from the file alone.

Each tamper case below is a way a certificate could be wrong while still
looking well formed. A verifier that accepts any of them is worse than no
verifier, because it turns an error into a fact.

The certificate and the binary are located rather than built: run
``python -m core.bundle.pairing --out corpus`` and
``tools\\build_verifier.bat`` first, and the tests skip themselves with a
note if either is missing.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent
BUNDLE = ROOT / "corpus" / "bls12-381.ccert"
BINARY_CANDIDATES = [
    ROOT / "verifier" / "target" / "release" / "ccert-verify.exe",
    ROOT / "verifier" / "target" / "release" / "ccert-verify",
]

SKIPPED = []


def _binary():
    for candidate in BINARY_CANDIDATES:
        if candidate.is_file():
            return candidate
    return None


def _ready(name):
    """True when both the bundle and the binary are present."""
    if _binary() is None or not BUNDLE.is_file():
        SKIPPED.append(name)
        return False
    return True


def _run(path):
    """Exit code and combined output of the verifier on a file."""
    result = subprocess.run(
        [str(_binary()), str(path)],
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout + result.stderr


def _tampered(mutate):
    """A temporary copy of the bundle, altered by ``mutate``.

    The canonical encoding is rebuilt with sorted keys and no spaces, so
    the file stays well formed and only the value under test differs. A
    verifier that rejected it merely for being malformed would prove
    nothing.
    """
    document = json.loads(BUNDLE.read_text(encoding="utf-8"))
    mutate(document)
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"))
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".ccert", delete=False, encoding="utf-8", newline="\n"
    )
    handle.write(encoded + "\n")
    handle.close()
    return Path(handle.name)


def _claim(document, name):
    for claim in document["claims"]:
        if claim["claim"] == name:
            return claim
    raise AssertionError(f"no claim named {name}")


def _payload(document, name):
    return document["evidence"][_claim(document, name)["evidence"]["ref"]]


def _rehash(document, name):
    """Re-key an evidence entry after changing it.

    Without this the pool check fires first and the tamper never reaches
    the handler under test, which would make the test look like it passed
    for the wrong reason.
    """
    import hashlib

    claim = _claim(document, name)
    old = claim["evidence"]["ref"]
    payload = document["evidence"].pop(old)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    document["evidence"][digest] = payload
    claim["evidence"]["ref"] = digest


# -- the honest certificate ------------------------------------------


def test_the_certificate_is_accepted():
    if not _ready("test_the_certificate_is_accepted"):
        return
    code, output = _run(BUNDLE)
    assert code == 0, output
    assert "10 proved" in output
    assert "not proved" in output and "0 not proved" in output


def test_both_groups_are_accounted_for():
    """G1 by a witness, G2 by elimination. Two arguments, because the two
    problems differ: over the base field a witness's order can be proved,
    over the extension the factorisation that would take is out of reach
    on the curves this argument is meant to grow into.

    Each argument is now confined to its own side. `proof.point-order`
    takes `curve.cardinality` and the subject's own curve; it no longer
    accepts a G2 order, where it could tie the curve in its evidence to
    nothing."""
    if not _ready("test_both_groups_are_accounted_for"):
        return
    _, output = _run(BUNDLE)
    assert "over the base field" in output
    assert "eliminating" in output and "no factorisation needed" in output


def test_bn254_is_accepted():
    """A second pairing curve through the same verifier, unchanged."""
    if not _ready("test_bn254_is_accepted"):
        return
    path = ROOT / "corpus" / "bn254.ccert"
    if not path.is_file():
        SKIPPED.append("test_bn254_is_accepted")
        return
    code, output = _run(path)
    assert code == 0, output
    assert "10 proved" in output and "0 not proved" in output


def test_a_trivial_cofactor_is_reported_plainly():
    """BN254 has cofactor one; saying so in bits would read as noise."""
    if not _ready("test_a_trivial_cofactor_is_reported_plainly"):
        return
    path = ROOT / "corpus" / "bn254.ccert"
    if not path.is_file():
        SKIPPED.append("test_a_trivial_cofactor_is_reported_plainly")
        return
    _, output = _run(path)
    assert "the subgroup is the whole group" in output


def test_the_old_corpus_still_verifies():
    """Nothing added for pairing curves may disturb what came before."""
    if not _ready("test_the_old_corpus_still_verifies"):
        return
    for name in ("secp256k1", "p-256"):
        path = ROOT / "corpus" / f"{name}.ccert"
        if not path.is_file():
            continue
        code, output = _run(path)
        assert code == 0, f"{name}: {output}"


# -- tampering with the witness --------------------------------------


def test_a_moved_witness_point_is_refused():
    if not _ready("test_a_moved_witness_point_is_refused"):
        return

    def mutate(document):
        payload = _payload(document, "curve.cardinality")
        payload["point"]["y"][0] = str(int(payload["point"]["y"][0]) + 1)
        _rehash(document, "curve.cardinality")

    code, output = _run(_tampered(mutate))
    assert code != 0
    assert "not on the curve" in output


def test_an_inflated_witness_order_is_refused():
    if not _ready("test_an_inflated_witness_order_is_refused"):
        return

    def mutate(document):
        payload = _payload(document, "curve.cardinality")
        payload["order"] = str(int(payload["order"]) * 2)
        _rehash(document, "curve.cardinality")

    code, output = _run(_tampered(mutate))
    assert code != 0


def test_a_dropped_factor_is_refused():
    """Removing a factor makes the product disagree with the order."""
    if not _ready("test_a_dropped_factor_is_refused"):
        return

    def mutate(document):
        payload = _payload(document, "g2.order")
        payload["factors"] = payload["factors"][:-1]
        _rehash(document, "g2.order")

    code, output = _run(_tampered(mutate))
    assert code != 0
    assert "multiply" in output or "factors" in output


def test_a_chainless_large_factor_is_refused():
    """A big prime with its chain stripped cannot be settled, and the
    verifier must say so rather than take it on faith."""
    if not _ready("test_a_chainless_large_factor_is_refused"):
        return

    def mutate(document):
        payload = _payload(document, "g2.order")
        for entry in payload["factors"]:
            entry.pop("steps", None)
        _rehash(document, "g2.order")

    code, output = _run(_tampered(mutate))
    assert code != 0
    assert "chain" in output


def test_a_wrong_asserted_order_is_refused():
    if not _ready("test_a_wrong_asserted_order_is_refused"):
        return

    def mutate(document):
        claim = _claim(document, "g2.cardinality")
        claim["asserts"]["n"] = str(int(claim["asserts"]["n"]) + 1)

    code, output = _run(_tampered(mutate))
    assert code != 0


# -- tampering with the field ----------------------------------------


def test_a_square_beta_is_refused():
    """A reducible modulus makes the quotient a ring with zero divisors,
    and every conclusion drawn from it void."""
    if not _ready("test_a_square_beta_is_refused"):
        return

    def mutate(document):
        payload = _payload(document, "g2.cardinality")
        payload["field"]["beta"] = "4"
        _rehash(document, "g2.cardinality")

    code, output = _run(_tampered(mutate))
    assert code != 0
    assert "square" in output or "field" in output


def test_a_foreign_characteristic_is_refused():
    """The evidence must be about the curve the subject names."""
    if not _ready("test_a_foreign_characteristic_is_refused"):
        return

    def mutate(document):
        payload = _payload(document, "curve.cardinality")
        payload["field"]["p"] = str(int(payload["field"]["p"]) - 2)
        _rehash(document, "curve.cardinality")

    code, output = _run(_tampered(mutate))
    assert code != 0
    assert "characteristic" in output


def test_a_wrong_coefficient_count_is_refused():
    if not _ready("test_a_wrong_coefficient_count_is_refused"):
        return

    def mutate(document):
        payload = _payload(document, "curve.cardinality")
        payload["point"]["x"] = payload["point"]["x"] + ["0"]
        _rehash(document, "curve.cardinality")

    code, output = _run(_tampered(mutate))
    assert code != 0
    assert "coefficient" in output


# -- tampering with the cofactor -------------------------------------


def test_a_cofactor_that_does_not_multiply_back_is_refused():
    if not _ready("test_a_cofactor_that_does_not_multiply_back_is_refused"):
        return

    def mutate(document):
        claim = _claim(document, "g2.order")
        claim["asserts"]["cofactor"] = str(int(claim["asserts"]["cofactor"]) + 1)

    code, output = _run(_tampered(mutate))
    assert code != 0
    assert "multiply" in output


def test_a_broken_cofactor_factorisation_is_refused():
    """The cofactor factorisation is evidence, not decoration.

    A subgroup-security policy reads the largest prime factor from it, so
    a split nobody checked would be an assertion dressed as proof.
    """
    if not _ready("test_a_broken_cofactor_factorisation_is_refused"):
        return

    def mutate(document):
        payload = _payload(document, "g2.order")
        payload["factors"] = payload["factors"][:-1]
        _rehash(document, "g2.order")

    code, output = _run(_tampered(mutate))
    assert code != 0
    assert "multiply" in output


def test_the_largest_cofactor_factor_is_reported():
    """Policies need the number, so the verifier states it."""
    if not _ready("test_the_largest_cofactor_factor_is_reported"):
        return
    _, output = _run(BUNDLE)
    assert "largest prime factor 448 bits" in output


def test_a_subgroup_order_not_proved_prime_is_refused():
    """The cofactor split must be against the prime the bundle proved,
    not against some other divisor."""
    if not _ready("test_a_subgroup_order_not_proved_prime_is_refused"):
        return

    def mutate(document):
        claim = _claim(document, "curve.order")
        n = int(claim["asserts"]["n"])
        cofactor = int(claim["asserts"]["cofactor"])
        # Move a factor of 3 across: the product still matches.
        claim["asserts"]["n"] = str(n * 3)
        claim["asserts"]["cofactor"] = str(cofactor // 3)

    code, output = _run(_tampered(mutate))
    assert code != 0


# -- the pool itself --------------------------------------------------


def test_evidence_edited_without_rehashing_is_refused():
    if not _ready("test_evidence_edited_without_rehashing_is_refused"):
        return

    def mutate(document):
        _payload(document, "curve.cardinality")["order"] = "7"

    code, output = _run(_tampered(mutate))
    assert code != 0


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
    if SKIPPED:
        print("  build the bundle and the verifier first, then rerun")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
