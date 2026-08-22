"""Tests for machine-readable output and the 192-bit policy.

Run it directly:

    python tests\\test_json_output.py

Embedding this in someone else's pipeline — "do not deploy until the
curve passes policy X" — required parsing human prose until now, which
makes the wording of a note load-bearing and turns every improvement to
it into a breaking change.

Both writers emit sorted keys and no floating point, so the output is
reproducible the way a certificate is: two runs give identical bytes, and
a consumer can pin a hash of the verdict if it wants to.

The verdict always carries the bundle digest. A verdict without it is an
opinion about a curve rather than a statement about a document, and the
difference is what the format exists for.
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.bundle.model import Bundle
from core.policy.engine import available_policies, evaluate, load_policy

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "spec" / "vectors" / "valid"
INVALID = ROOT / "spec" / "vectors" / "invalid"

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


def _verify_json(path, *flags):
    result = subprocess.run(
        [str(_binary()), "--json", *flags, str(path)],
        capture_output=True, text=True,
    )
    return result.returncode, json.loads(result.stdout)


def _policy_json(curve, policy):
    result = subprocess.run(
        [
            sys.executable, "-m", "core.policy.engine",
            str(VECTORS / f"{curve}.ccert"), "--policy", policy, "--json",
        ],
        capture_output=True, text=True, cwd=ROOT,
    )
    return result.returncode, json.loads(result.stdout)


def _bundle(curve):
    return Bundle.from_obj(
        json.loads((VECTORS / f"{curve}.ccert").read_text(encoding="utf-8"))
    )


# -- the verifier ------------------------------------------------------


def test_an_accepted_bundle_produces_an_object():
    if not _ready("test_an_accepted_bundle_produces_an_object", "bn254"):
        return
    code, verdict = _verify_json(VECTORS / "bn254.ccert")
    assert code == 0
    assert verdict["result"] == "accepted"
    assert verdict["digest"] == _bundle("bn254").digest()
    assert verdict["proved"] == 10
    assert verdict["unproved"] == 0


def test_every_claim_appears_with_its_tier():
    if not _ready("test_every_claim_appears_with_its_tier", "bls12-381"):
        return
    _, verdict = _verify_json(VECTORS / "bls12-381.ccert")
    named = {outcome["claim"] for outcome in verdict["outcomes"]}
    assert "curve.family" in named
    assert "g2.twist" in named
    for outcome in verdict["outcomes"]:
        assert outcome["tier"] in {"proved", "derived", "candidate"}
        assert outcome["note"]


def test_a_refusal_carries_its_reason():
    """A refusal that arrives as a bare exit code tells an automated
    caller nothing about which claim went wrong."""
    if not _ready("test_a_refusal_carries_its_reason"):
        return
    path = INVALID / "foreign-curve.ccert"
    if not path.is_file():
        SKIPPED.append("test_a_refusal_carries_its_reason")
        return
    code, verdict = _verify_json(path)
    assert code != 0
    assert verdict["result"] == "refused"
    assert "different curve" in verdict["reason"]


def test_the_output_is_reproducible():
    """Sorted keys and no floating point, so two runs give the same bytes
    and a consumer may pin a hash of the verdict."""
    if not _ready("test_the_output_is_reproducible", "bn254"):
        return
    first = subprocess.run(
        [str(_binary()), "--json", str(VECTORS / "bn254.ccert")],
        capture_output=True, text=True,
    ).stdout
    again = subprocess.run(
        [str(_binary()), "--json", str(VECTORS / "bn254.ccert")],
        capture_output=True, text=True,
    ).stdout
    assert first == again


def test_require_proved_still_governs_the_exit_code():
    if not _ready("test_require_proved_still_governs_the_exit_code", "bls12-381"):
        return
    code, _ = _verify_json(VECTORS / "bls12-381.ccert", "--require-proved")
    assert code == 0          # one derived claim, no candidates


def test_the_json_is_written_without_a_dependency():
    """The verifier is meant to be readable end to end; a serialiser
    pulled in for one flag works against that.

    The writer moved to the library when the browser build needed it, so
    that the page and the command line emit one format rather than two
    that agree today.
    """
    source = (ROOT / "verifier" / "src" / "lib.rs").read_text(encoding="utf-8")
    assert "pub fn quote(" in source
    assert "pub fn report_json(" in source
    cargo = (ROOT / "verifier" / "Cargo.toml").read_text(encoding="utf-8")
    assert "serde" not in cargo


def test_the_browser_build_costs_the_command_line_nothing():
    """`wasm-bindgen` is declared under a wasm32 target, so a native
    compile never sees it and the dependency list a reader audits is
    exactly what it was."""
    cargo = (ROOT / "verifier" / "Cargo.toml").read_text(encoding="utf-8")
    assert 'cfg(target_arch = "wasm32")' in cargo

    # Read the declarations rather than the prose: the word appears in
    # comments explaining why the arrangement is what it is, and a test
    # that tripped over its own documentation would be useless.
    section, entries = None, {}
    for line in cargo.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.startswith("["):
            section = stripped
            continue
        if "=" in stripped and section:
            entries.setdefault(section, []).append(stripped.split("=")[0].strip())

    plain = entries.get("[dependencies]", [])
    assert "wasm-bindgen" not in plain, "the native build should not carry it"
    wasm_section = next(
        (key for key in entries if "wasm32" in key), None
    )
    assert wasm_section, "no wasm32 dependency section"
    assert "wasm-bindgen" in entries[wasm_section]
    # And pinned exactly: the library and the command line tool must agree,
    # and a mismatch fails with a message that does not say so.
    assert 'wasm-bindgen = "=0.2.127"' in cargo


def test_the_page_refuses_rather_than_pretends_without_the_module():
    """A build with no wasm toolchain must still say what it did not do.

    The invariant is about the page's behaviour, not about which file
    happens to be on disk: `verifier.generated.js` is the placeholder in a
    fresh tree and the real module after `tools\build_wasm.bat`, and both
    are correct states. So the check is that the page has somewhere to
    put a failure and says so, and — when the placeholder is what is
    present — that it refuses rather than resolving.

    An earlier version asserted the placeholder's wording outright and
    failed on any machine where the wasm build had succeeded, which is to
    say on the machines where things were going well.
    """
    app = (ROOT / "web" / "src" / "App.jsx").read_text(encoding="utf-8")
    assert "Not verified." in app
    assert "unavailable" in app

    # The placeholder is committed under its own name so a clone always
    # has one; `verifier.generated.js` is whichever of the two the build
    # put there, and both states are correct.
    placeholder = (ROOT / "web" / "src" / "verifier.placeholder.js").read_text(
        encoding="utf-8"
    )
    assert "not built for the browser" in placeholder
    assert "throw" in placeholder or "reject" in placeholder

    generated = ROOT / "web" / "src" / "verifier.generated.js"
    if not generated.is_file():
        # A build artefact, and a fresh clone has none. The half above
        # still ran; this half is skipped rather than crashed, because a
        # test that dies with FileNotFoundError on a clean checkout is
        # noise a reader learns to scroll past — and the next real failure
        # scrolls past with it.
        SKIPPED.append("test_the_page_refuses_rather_than_pretends_without_the_module")
        return
    shim = generated.read_text(encoding="utf-8")
    if "not built for the browser" in shim:
        # The placeholder. It must refuse, not resolve: a page that
        # quietly displayed an unverified file would be the exact
        # dishonesty the browser verifier removes.
        assert "throw" in shim or "reject" in shim
    else:
        # The real module. It must actually carry one.
        assert "SIZE_BYTES" in shim
        size = int(shim.rsplit("SIZE_BYTES = ", 1)[1].split(";")[0])
        assert size > 100_000, "the inlined module looks too small to be one"


def test_strict_is_stricter_than_require_proved():
    """A derived claim stands on proof — the verifier already refused any
    bundle where one rests on something unproved — and a caller may still
    want everything to stand on its own. Both readings are defensible, so
    both have a flag."""
    if not _ready("test_strict_is_stricter_than_require_proved", "bls12-381"):
        return
    path = VECTORS / "bls12-381.ccert"
    lenient = subprocess.run(
        [str(_binary()), "--require-proved", str(path)],
        capture_output=True, text=True,
    )
    strict = subprocess.run(
        [str(_binary()), "--strict", str(path)], capture_output=True, text=True
    )
    assert lenient.returncode == 0
    assert strict.returncode == 1          # the twist claim is derived
    assert "not proved outright" in strict.stderr


def test_strict_agrees_between_text_and_json():
    if not _ready("test_strict_agrees_between_text_and_json", "bls12-381"):
        return
    code, verdict = _verify_json(VECTORS / "bls12-381.ccert", "--strict")
    assert code == 1
    assert verdict["result"] == "accepted"   # the document is sound
    assert verdict["derived"] == 1           # the caller's bar is higher


# -- curve name aliases ------------------------------------------------


def test_common_spellings_resolve():
    """A tool that answers `unknown curve: bls12381` to someone who meant
    a hyphen is being unhelpful about punctuation."""
    from tools.build_curve import resolve

    for spelling in ("bls12381", "BLS12_381", "bls12-381", "bls381"):
        assert resolve(spelling) == "bls12-381", spelling
    for spelling in ("alt_bn128", "bn128", "BN254"):
        assert resolve(spelling) == "bn254", spelling
    for spelling in ("prime256v1", "secp256r1", "p256", "nistp256"):
        assert resolve(spelling) == "p-256", spelling
    assert resolve("k256") == "secp256k1"


def test_an_unknown_name_still_fails():
    from tools.build_curve import resolve

    try:
        resolve("not-a-curve-at-all")
    except KeyError:
        pass
    else:
        raise AssertionError("an unknown curve resolved to something")


def test_aliases_never_become_file_names():
    """One curve, one canonical name, one file. Otherwise two
    certificates for one curve could exist under different names and the
    byte comparison would stop meaning anything."""
    from tools.build_curve import ALIASES, ALL_CURVES

    for alias, canonical in ALIASES.items():
        assert alias not in ALL_CURVES, alias
        assert canonical in ALL_CURVES, canonical


# -- the policy engine -------------------------------------------------


def test_a_policy_verdict_names_the_bytes_it_is_about():
    if not _ready("test_a_policy_verdict_names_the_bytes_it_is_about", "bn254"):
        return
    _, verdict = _policy_json("bn254", "pairing-security-tnfs-2016")
    assert verdict["bundle_digest"] == _bundle("bn254").digest()
    assert verdict["policy"]["name"] == "pairing-security-tnfs-2016"
    assert verdict["result"] == "fails"


def test_a_model_dependent_criterion_says_so_in_json():
    """A consumer storing the verdict has to be able to tell which lines
    can move without any fact moving."""
    if not _ready("test_a_model_dependent_criterion_says_so_in_json", "bn254"):
        return
    _, verdict = _policy_json("bn254", "pairing-security-tnfs-2016")
    by_id = {outcome["id"]: outcome for outcome in verdict["outcomes"]}
    assert by_id["embedding-field-size"]["model"] == "tnfs-kim-barbulescu-2016"
    assert "model" not in by_id["subgroup-order-large"]


def test_the_json_matches_the_readable_verdict():
    if not _ready("test_the_json_matches_the_readable_verdict", "bls12-381"):
        return
    code, verdict = _policy_json("bls12-381", "pairing-suitability")
    computed = evaluate(_bundle("bls12-381"), load_policy("pairing-suitability"))
    assert verdict["result"] == computed.result
    assert code == (0 if computed.result == "passes" else 1)


# -- the whole matrix at once ------------------------------------------


def test_the_matrix_has_a_machine_form():
    """Eight curves against seven policies is fifty-six invocations to
    learn what one pass already knows."""
    result = subprocess.run(
        [
            sys.executable, "-m", "core.policy.engine",
            "--corpus", str(VECTORS), "--json",
        ],
        capture_output=True, text=True, cwd=ROOT,
    )
    matrix = json.loads(result.stdout)
    assert len(matrix["curves"]) >= 6
    assert len(matrix["policies"]) >= 5


def test_every_curve_in_the_matrix_carries_its_digest():
    """A verdict about no particular bytes is an opinion about a curve."""
    result = subprocess.run(
        [
            sys.executable, "-m", "core.policy.engine",
            "--corpus", str(VECTORS), "--json",
        ],
        capture_output=True, text=True, cwd=ROOT,
    )
    matrix = json.loads(result.stdout)
    for name, entry in matrix["curves"].items():
        assert entry["digest"].startswith("sha256:"), name


def test_the_matrix_agrees_with_the_single_verdicts():
    """One pass and fifty-six passes must say the same thing, or the
    convenience is a second opinion rather than a shortcut."""
    if not _ready("test_the_matrix_agrees_with_the_single_verdicts", "bn254"):
        return
    result = subprocess.run(
        [
            sys.executable, "-m", "core.policy.engine",
            "--corpus", str(VECTORS), "--json",
        ],
        capture_output=True, text=True, cwd=ROOT,
    )
    matrix = json.loads(result.stdout)
    for policy in ("pairing-security-tnfs-2016", "safecurves-2024"):
        alone = evaluate(_bundle("bn254"), load_policy(policy))
        assert matrix["curves"]["bn254"]["verdicts"][policy]["result"] == alone.result


def test_the_matrix_is_reproducible():
    """Sorted keys, so two runs give the same bytes."""
    runs = [
        subprocess.run(
            [
                sys.executable, "-m", "core.policy.engine",
                "--corpus", str(VECTORS), "--json",
            ],
            capture_output=True, text=True, cwd=ROOT,
        ).stdout
        for _ in range(2)
    ]
    assert runs[0] == runs[1]


# -- the 192-bit policy ------------------------------------------------


def test_the_192_bit_policy_exists_and_loads():
    assert "pairing-security-tnfs-192" in available_policies()
    assert load_policy("pairing-security-tnfs-192").criteria


def test_nothing_in_the_corpus_reaches_192():
    """True, and worth being able to see. Every curve here targets 128."""
    if not _ready("test_nothing_in_the_corpus_reaches_192", "bls12-381", "bn254"):
        return
    policy = load_policy("pairing-security-tnfs-192")
    for curve in ("bls12-381", "bn254"):
        assert evaluate(_bundle(curve), policy).result != "passes", curve


def test_its_threshold_comes_from_the_same_table_as_the_128_one():
    """12871 and 5004 are companions in one source. Neither is a
    recollection, which is the rule adopted after an earlier threshold
    turned out to have no derivation at all."""
    policy = load_policy("pairing-security-tnfs-192")
    criterion = next(c for c in policy.criteria if c.id == "embedding-field-size")
    assert criterion.value == "12871"
    assert "5004" in criterion.model["note"]
    assert "Barbulescu" in criterion.model["source"]


def test_the_generic_bound_carries_no_model():
    """Pollard rho is a theorem at 192 bits as much as at 128."""
    policy = load_policy("pairing-security-tnfs-192")
    rho = next(c for c in policy.criteria if c.id == "subgroup-order-large")
    assert rho.model is None
    assert rho.value == "382"


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
