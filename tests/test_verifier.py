"""Differential tests: Python writes, Rust reads.

These run against a golden bundle checked into `spec/vectors/valid`, so
they need neither PARI nor a rebuilt corpus. Each case takes that good
file, breaks one thing, and insists the verifier notices.

A verifier earns its keep in the cases where it refuses.
"""

import copy
import json
import subprocess
from pathlib import Path

import pytest

from core.bundle import canonical

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "spec" / "vectors" / "valid"
GOLDEN = VECTORS / "secp256k1.ccert"
ALL_VECTORS = sorted(VECTORS.glob("*.ccert"))
BINARY_CANDIDATES = [
    ROOT / "verifier" / "target" / "release" / "ccert-verify",
    ROOT / "verifier" / "target" / "release" / "ccert-verify.exe",
]


def binary() -> Path | None:
    for path in BINARY_CANDIDATES:
        if path.is_file():
            return path
    return None


needs_binary = pytest.mark.skipif(
    binary() is None, reason="run tools\\build_verifier.bat first"
)
needs_golden = pytest.mark.skipif(not GOLDEN.is_file(), reason="golden vector missing")


def run(path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(binary()), *args, str(path)], capture_output=True, text=True, timeout=120
    )


def golden() -> dict:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def claim(document: dict, name: str) -> dict:
    for record in document["claims"]:
        if record["claim"] == name:
            return record
    raise AssertionError(f"golden vector has no claim {name}")


def repack(document: dict) -> bytes:
    """Re-address the evidence pool so only the intended change is wrong."""
    document = copy.deepcopy(document)
    pool = {}
    for record in document["claims"]:
        reference = record["evidence"].get("ref")
        if reference is None:
            continue
        body = document["evidence"][reference]
        address = canonical.digest(body)
        record["evidence"]["ref"] = address
        pool[address] = body
    document["evidence"] = pool
    return canonical.encode(document) + b"\n"


@pytest.fixture
def write(tmp_path):
    def _write(payload, name="case.ccert") -> Path:
        path = tmp_path / name
        if isinstance(payload, dict):
            payload = repack(payload)
        elif isinstance(payload, str):
            # Bytes, never write_text: on Windows that rewrites every \n as
            # \r\n, which the verifier correctly refuses as a stray byte.
            payload = payload.encode("utf-8")
        path.write_bytes(payload)
        return path

    return _write


# -- the happy path -------------------------------------------------


@needs_binary
@pytest.mark.parametrize("vector", ALL_VECTORS, ids=lambda p: p.stem)
def test_accepts_every_good_vector(vector):
    """One of these is a curve the verifier was not written against."""
    result = run(vector)
    assert result.returncode == 0, result.stderr
    assert "0 not proved" in result.stdout


@needs_binary
def test_the_readme_example_matches_the_verifier():
    """The first screen of the README shows a run, and it must be a real
    one.

    A worked example is the first thing a reader trusts and the easiest
    thing to leave behind: two lines of it had drifted — an embedding note
    without its 2-adicity, a twist line without its largest factor — while
    the verifier had moved on. A stale example in the README is the same
    defect as a stale wasm in the page, minus the tooling to catch it, so
    this catches it.

    Every claim line inside the fenced block is required to appear
    verbatim in the verifier's output for the curve the block names, and
    the count line too. Prose around the block is the README's to write;
    the lines that quote the tool are the tool's to dictate."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    block = readme.split("$ ccert-verify", 1)[1].split("```", 1)[0]
    name = block.split("/", 1)[1].split(".ccert", 1)[0].strip()
    vector = VECTORS / f"{name}.ccert"
    if not vector.is_file():
        pytest.skip(f"{name} vector missing")
    output = run(vector, "--explain").stdout
    quoted = [
        line.rstrip()
        for line in block.splitlines()
        if line.strip().startswith("[") or "proved," in line
    ]
    assert quoted, "the README block quoted no verifier lines"
    for line in quoted:
        assert line.strip() in output, (
            f"the README shows a line the verifier does not:\n  {line.strip()}"
        )


@needs_binary
@needs_golden
def test_accepts_the_golden_bundle():
    result = run(GOLDEN)
    assert result.returncode == 0, result.stderr
    assert "0 not proved" in result.stdout


@needs_binary
@needs_golden
def test_every_claim_is_proved_or_rests_on_proof():
    assert run(GOLDEN, "--require-proved").returncode == 0


@needs_golden
def test_repacking_is_faithful(write):
    """If this fails, every tampering test below is testing the repack."""
    assert write(golden()).read_bytes() == GOLDEN.read_bytes()


def test_verifier_stays_readable():
    """The size budget is a ratchet, and it has to be moved on purpose.

    Two numbers, and they do different work. The per-file limit is the
    one that matters day to day: a single file past 800 lines has stopped
    being readable in one sitting, and `claims.rs` at 745 is the one to
    watch.

    The total was 1800 and the verifier was 4310 lines, so this assertion
    had been failing for a long time while reading as coverage — the same
    defect as a test that cannot fail, facing the other way. It is set
    here to the real figure plus a little headroom rather than quietly
    deleted, because the budget is worth keeping: what it exists to catch
    is growth nobody argued for.

    Where the lines went, so the next raise is an argument rather than a
    reflex: degree-4 towers (`fq4.rs`), one group law over a trait
    (`curve.rs`) so degrees 1, 2 and 4 share it, the elimination argument
    with its binding to the subject (`elimination.rs`), the sextic
    enumeration (`twist_class.rs`), and the wasm entry point in `lib.rs`.

    Raised twice since, and each time the ratchet caught the change that
    needed it rather than being moved out of the way in advance.

    4400 to 4500: the class index is now checked against the number the
    claim asserts, which nothing compared before; the twist enumeration is
    parameterised by the degree the claim names, so a degree-4 bundle can
    carry the label instead of omitting it; and the handler refuses to
    classify an order that did not come from the elimination.

    4500 to 4600: every level of a document now carries a closed set of
    keys — the bundle, a claim, its evidence reference, the subject, each
    payload, and the objects nested inside one. That is a table of payload
    shapes and a call at each reading site, and it is the kind of growth
    the budget exists to make deliberate rather than to prevent.
    """
    sizes = {
        path.name: len(path.read_text(encoding="utf-8").splitlines())
        for path in (ROOT / "verifier" / "src").glob("*.rs")
    }
    for name, lines in sizes.items():
        assert lines < 800, f"{name} alone is {lines} lines; split it"
    total = sum(sizes.values())
    assert total < 4600, (
        f"verifier grew to {total} lines; raise the budget with a reason "
        "or split something"
    )


# -- the certificate chain ------------------------------------------


@needs_binary
@needs_golden
def test_rejects_a_broken_chain_link(write):
    """Change one N so a step no longer reduces to the next number."""
    document = golden()
    reference = claim(document, "curve.order.prime")["evidence"]["ref"]
    steps = document["evidence"][reference]["steps"]
    steps[1]["N"] = str(int(steps[1]["N"]) + 2)
    result = run(write(document))
    assert result.returncode == 1
    assert "step" in result.stderr


@needs_binary
@needs_golden
def test_rejects_a_tampered_witness_point(write):
    document = golden()
    reference = claim(document, "field.characteristic")["evidence"]["ref"]
    step = document["evidence"][reference]["steps"][0]
    step["y"] = str(int(step["y"]) + 1)
    assert run(write(document)).returncode == 1


@needs_binary
@needs_golden
def test_rejects_a_truncated_chain(write):
    """Dropping the tail leaves the last q unproved."""
    document = golden()
    reference = claim(document, "curve.order.prime")["evidence"]["ref"]
    steps = document["evidence"][reference]["steps"]
    document["evidence"][reference]["steps"] = steps[:3]
    assert run(write(document)).returncode == 1


@needs_binary
@needs_golden
def test_rejects_a_chain_about_another_number(write):
    document = golden()
    record = claim(document, "curve.order.prime")
    record["asserts"]["n"] = str(int(record["asserts"]["n"]) + 2)
    assert run(write(document)).returncode == 1


@needs_binary
@needs_golden
def test_rejects_an_empty_chain(write):
    document = golden()
    reference = claim(document, "field.characteristic")["evidence"]["ref"]
    document["evidence"][reference]["steps"] = []
    assert run(write(document)).returncode == 1


# -- the embedding degree -------------------------------------------


@needs_binary
@needs_golden
def test_rejects_a_degree_that_is_not_the_order(write):
    """Halve the degree: it still divides n - 1, but the base is not one."""
    document = golden()
    record = claim(document, "curve.embedding")
    reference = record["evidence"]["ref"]
    degree = int(record["asserts"]["degree"])
    record["asserts"]["degree"] = str(degree // 2)
    document["evidence"][reference]["order"] = str(degree // 2)
    assert run(write(document)).returncode == 1


@needs_binary
@needs_golden
def test_rejects_an_incomplete_factorisation(write):
    """Drop a factor of n - 1 and the product no longer matches."""
    document = golden()
    reference = claim(document, "curve.embedding")["evidence"]["ref"]
    factors = document["evidence"][reference]["factors"]
    document["evidence"][reference]["factors"] = factors[:-1]
    result = run(write(document))
    assert result.returncode == 1
    assert "multiply back" in result.stderr


@needs_binary
@needs_golden
def test_rejects_a_composite_passed_off_as_a_factor(write):
    """A composite divisor could hide a smaller true order behind it."""
    document = golden()
    reference = claim(document, "curve.embedding")["evidence"]["ref"]
    factors = document["evidence"][reference]["factors"]
    large = max(range(len(factors)), key=lambda i: int(factors[i]["prime"]))
    factors[large] = {
        "prime": factors[large]["prime"],
        "exponent": factors[large]["exponent"],
    }
    result = run(write(document))
    assert result.returncode == 1
    assert "chain" in result.stderr


@needs_binary
@needs_golden
def test_rejects_a_degree_for_the_wrong_modulus(write):
    document = golden()
    reference = claim(document, "curve.embedding")["evidence"]["ref"]
    body = document["evidence"][reference]
    body["modulus"] = str(int(body["modulus"]) + 2)
    assert run(write(document)).returncode == 1


# -- the CM discriminant --------------------------------------------


@needs_binary
@needs_golden
def test_rejects_a_trace_that_does_not_follow_from_p_and_n(write):
    document = golden()
    record = claim(document, "curve.cm")
    record["asserts"]["trace"] = str(int(record["asserts"]["trace"]) + 1)
    assert run(write(document)).returncode == 1


@needs_binary
@needs_golden
def test_rejects_a_split_that_does_not_multiply_out(write):
    """Conductor squared times D must be the discriminant exactly."""
    document = golden()
    record = claim(document, "curve.cm")
    reference = record["evidence"]["ref"]
    bumped = str(int(record["asserts"]["conductor"]) + 1)
    record["asserts"]["conductor"] = bumped
    document["evidence"][reference]["conductor"] = bumped
    assert run(write(document)).returncode == 1


@needs_binary
@needs_golden
def test_rejects_evidence_about_a_different_discriminant(write):
    """The claim and the evidence backing it must speak of the same D."""
    document = golden()
    reference = claim(document, "curve.cm")["evidence"]["ref"]
    body = document["evidence"][reference]
    body["fundamental"] = str(int(body["fundamental"]) - 4)
    result = run(write(document))
    assert result.returncode == 1
    assert "different discriminant" in result.stderr


@needs_binary
@needs_golden
def test_rejects_wrong_factors_for_the_discriminant(write):
    document = golden()
    reference = claim(document, "curve.cm")["evidence"]["ref"]
    document["evidence"][reference]["factors"] = [{"exponent": "1", "prime": "5"}]
    result = run(write(document))
    assert result.returncode == 1
    assert "multiply back" in result.stderr


# -- the order argument ---------------------------------------------


@needs_binary
@needs_golden
def test_rejects_a_witness_off_the_curve(write):
    document = golden()
    reference = claim(document, "curve.order")["evidence"]["ref"]
    point = document["evidence"][reference]["point"]
    point["x"] = str(int(point["x"]) + 1)
    assert run(write(document)).returncode == 1


@needs_binary
@needs_golden
def test_rejects_a_plausible_but_wrong_order(write):
    """The case that matters: a number close enough to look right."""
    document = golden()
    for name in ("curve.order", "curve.order.prime"):
        record = claim(document, name)
        record["asserts"]["n"] = str(int(record["asserts"]["n"]) + 2)
    assert run(write(document)).returncode == 1


# -- structure ------------------------------------------------------


@needs_binary
@needs_golden
def test_rejects_proof_resting_on_a_candidate(write):
    """Downgrade the primality proof and the order claim must fall with it."""
    document = golden()
    record = claim(document, "curve.order.prime")
    reference = record["evidence"]["ref"]
    document["evidence"][reference] = {"type": "candidate.pseudoprime", "tool": "gp"}
    record["evidence"]["type"] = "candidate.pseudoprime"
    result = run(write(document))
    assert result.returncode == 1
    assert "depends on" in result.stderr


@needs_binary
@needs_golden
def test_rejects_altered_evidence(write):
    """Edit the pool without re-addressing: what content addressing is for."""
    document = golden()
    reference = claim(document, "curve.order")["evidence"]["ref"]
    document["evidence"][reference]["point"]["x"] = "12345"
    result = run(write(canonical.encode(document) + b"\n"))
    assert result.returncode == 1
    assert "altered" in result.stderr


@needs_binary
@needs_golden
def test_rejects_an_unknown_claim_type(write):
    raw = GOLDEN.read_text(encoding="utf-8")
    result = run(write(raw.replace('"claim":"curve.hasse"', '"claim":"curve.magic"')))
    assert result.returncode == 1
    assert "unknown claim type" in result.stderr


@needs_binary
@needs_golden
def test_rejects_an_unknown_evidence_type(write):
    raw = GOLDEN.read_text(encoding="utf-8")
    result = run(write(raw.replace('"type":"check.hasse"', '"type":"check.vibes"')))
    assert result.returncode == 1
    assert "unknown evidence type" in result.stderr


@needs_binary
@needs_golden
def test_rejects_an_unknown_top_level_field(write):
    document = golden()
    document["extra"] = "surprise"
    result = run(write(document))
    assert result.returncode == 1
    assert "unknown top-level field" in result.stderr


@needs_binary
@needs_golden
def test_rejects_a_future_version(write):
    document = golden()
    document["version"] = "1"
    assert run(write(document)).returncode == 1


@needs_binary
@needs_golden
def test_rejects_an_even_characteristic(write):
    document = golden()
    document["subject"]["field"]["p"] = str(int(document["subject"]["field"]["p"]) + 1)
    assert run(write(document)).returncode == 1


# -- encoding -------------------------------------------------------


@needs_binary
@needs_golden
def test_rejects_whitespace(write):
    raw = GOLDEN.read_text(encoding="utf-8")
    result = run(write(raw.replace('{"', '{ "', 1)))
    assert result.returncode == 1
    assert "whitespace" in result.stderr


@needs_binary
@needs_golden
def test_rejects_json_numbers(write):
    raw = GOLDEN.read_text(encoding="utf-8")
    result = run(write(raw.replace('"a":"0"', '"a":0')))
    assert result.returncode == 1
    assert "numbers are not allowed" in result.stderr


@needs_binary
@needs_golden
def test_rejects_unsorted_keys(write):
    raw = GOLDEN.read_text(encoding="utf-8")
    original = '"kind":"elliptic-curve","label":"secp256k1"'
    swapped = raw.replace(original, '"label":"secp256k1","kind":"elliptic-curve"')
    assert swapped != raw, "the substitution did nothing; this test proves nothing"
    assert run(write(swapped)).returncode == 1


@needs_binary
@needs_golden
def test_rejects_byte_order_mark(write):
    assert run(write("\ufeff".encode() + GOLDEN.read_bytes())).returncode == 1


@needs_binary
@needs_golden
def test_rejects_trailing_bytes(write):
    assert run(write(GOLDEN.read_bytes() + b"{}")).returncode == 1


@needs_binary
@needs_golden
def test_rejects_truncation(write):
    assert run(write(GOLDEN.read_bytes()[:-60])).returncode == 1


# -- the seed derivation --------------------------------------------

P256 = VECTORS / "p-256.ccert"
needs_p256 = pytest.mark.skipif(not P256.is_file(), reason="P-256 vector missing")


def p256() -> dict:
    return json.loads(P256.read_text(encoding="utf-8"))


@needs_binary
@needs_p256
def test_rejects_a_seed_that_does_not_reproduce_the_curve(write):
    """One flipped nibble in the seed and the relation collapses."""
    document = p256()
    reference = claim(document, "param.rigidity")["evidence"]["ref"]
    body = document["evidence"][reference]
    body["seed"] = body["seed"][:-1] + ("0" if body["seed"][-1] != "0" else "1")
    result = run(write(document))
    assert result.returncode == 1
    assert "does not reproduce" in result.stderr


@needs_binary
@needs_p256
def test_rejects_a_seed_for_a_different_curve(write):
    """The seed derives b, so changing b must break the check."""
    document = p256()
    document["subject"]["b"] = str(int(document["subject"]["b"]) + 1)
    assert run(write(document)).returncode == 1


@needs_binary
@needs_p256
def test_rejects_an_unknown_derivation_method(write):
    document = p256()
    record = claim(document, "param.rigidity")
    reference = record["evidence"]["ref"]
    record["asserts"]["method"] = "homebrew"
    document["evidence"][reference]["method"] = "homebrew"
    result = run(write(document))
    assert result.returncode == 1
    assert "unknown derivation method" in result.stderr


@needs_binary
@needs_p256
def test_rejects_a_short_seed(write):
    document = p256()
    reference = claim(document, "param.rigidity")["evidence"]["ref"]
    document["evidence"][reference]["seed"] = "C49D3608"
    result = run(write(document))
    assert result.returncode == 1
    assert "shorter than the standard" in result.stderr
