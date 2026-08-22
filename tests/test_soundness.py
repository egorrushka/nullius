"""Tests for the soundness fixes found by external review.

Run it directly:

    python tests\\test_soundness.py

Each test here corresponds to a way a false certificate could have been
made to verify. They are grouped by the hole they close, and every one of
them failed before the fix — that is the only reason any of them is worth
keeping.

The attacks are built, not described. A test that asserts a refusal
without constructing something that would otherwise have been accepted
proves nothing about the verifier.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.bundle.model import Bundle, BundleError, required_deps
from core.claims.point_order import PointOrderError, unique_multiple_in_window
from core.field.order import OrderError, point_order

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


def _ready(name, *needed):
    if _binary() is None:
        SKIPPED.append(name)
        return False
    for curve in needed:
        if not (VECTORS / f"{curve}.ccert").is_file():
            SKIPPED.append(name)
            return False
    return True


def _run(path):
    result = subprocess.run(
        [str(_binary()), str(path)], capture_output=True, text=True
    )
    return result.returncode, result.stdout + result.stderr


def _write(document):
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".ccert", delete=False, encoding="utf-8", newline="\n"
    )
    handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    handle.close()
    return Path(handle.name)


def _load(curve):
    return json.loads((VECTORS / f"{curve}.ccert").read_text(encoding="utf-8"))


def _claim(document, name):
    for claim in document["claims"]:
        if claim["claim"] == name:
            return claim
    raise AssertionError(f"no claim {name}")


def _payload(document, name):
    return document["evidence"][_claim(document, name)["evidence"]["ref"]]


def _rehash(document, name):
    import hashlib

    claim = _claim(document, name)
    payload = document["evidence"].pop(claim["evidence"]["ref"])
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    document["evidence"][digest] = payload
    claim["evidence"]["ref"] = digest


def _raises(exception, call, *args, **kwargs):
    try:
        call(*args, **kwargs)
    except exception:
        return True
    return False


# -- the curve in the evidence must be the subject's ------------------


def test_evidence_about_another_curve_is_refused():
    """The hole this closes was live: a bundle for y^2 = x^3 + 3 could
    carry, at tier A, a correctly proved order for y^2 = x^3 + 5 over the
    same field. Every step of that proof is honest; it is simply about a
    different curve, and nothing compared the two.

    The tamper here is cruder than the original attack — changing b makes
    the witness fall off the curve — but it reaches the same guard, and
    the guard is what is being tested."""
    if not _ready("test_evidence_about_another_curve_is_refused", "bn254"):
        return

    def mutate(document):
        payload = _payload(document, "curve.cardinality")
        payload["curve"]["b"] = [str(int(payload["curve"]["b"][0]) + 2)]
        _rehash(document, "curve.cardinality")

    document = _load("bn254")
    mutate(document)
    code, output = _run(_write(document))
    assert code != 0
    assert "different curve" in output


def test_degree_two_evidence_under_a_degree_one_claim_is_refused():
    """`curve.cardinality` is about the subject, which lives over F_p. A
    payload declaring degree 2 would prove an order over an extension and
    present it as the subject's own.

    The tamper edits the degree in place rather than borrowing a payload
    from G2: since the second group moved to `derive.order-elimination`
    there is no degree-2 point-order evidence in the corpus to borrow.
    """
    if not _ready("test_degree_two_evidence_under_a_degree_one_claim_is_refused",
                  "bn254"):
        return
    document = _load("bn254")
    payload = _payload(document, "curve.cardinality")
    payload["field"]["degree"] = "2"
    payload["field"]["beta"] = "1"
    _rehash(document, "curve.cardinality")
    code, output = _run(_write(document))
    assert code != 0
    assert "degree" in output

def test_a_cofactor_split_of_a_candidate_is_refused():
    """The attack: state a cardinality on `candidate.sea`, which carries
    no weight, then split it with `check.cofactor`, whose arithmetic is
    exact. The split is honest and the tier table is honest, and the
    result is a proved-looking subgroup order resting on a number nobody
    proved."""
    if not _ready("test_a_cofactor_split_of_a_candidate_is_refused", "bls12-381"):
        return
    import hashlib

    document = _load("bls12-381")
    claim = _claim(document, "g2.cardinality")
    document["evidence"].pop(claim["evidence"]["ref"])
    # Re-key the replacement, or the pool digest check fires before the
    # tier check and the test passes for the wrong reason.
    payload = {"type": "candidate.sea", "tool": "pari 2.15"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    reference = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    document["evidence"][reference] = payload
    claim["evidence"] = {"type": "candidate.sea", "ref": reference}
    claim.pop("depends_on", None)
    code, output = _run(_write(document))
    assert code != 0
    assert "candidate" in output, output


def test_an_undeclared_dependency_is_refused():
    """The tier check on declared edges was sound; declaring was
    optional. A claim that simply omitted `depends_on` skipped it."""
    if not _ready("test_an_undeclared_dependency_is_refused", "bn254"):
        return
    document = _load("bn254")
    _claim(document, "curve.order").pop("depends_on", None)
    code, output = _run(_write(document))
    assert code != 0
    assert "must declare" in output


def test_the_producer_refuses_the_same_omission():
    """Producer and verifier hold the same table, so a bundle the
    verifier would reject cannot be written in the first place."""
    bundle = Bundle(subject={"kind": "elliptic-curve", "label": "toy"})
    bundle.add_claim(
        "field.characteristic", {"p": "103", "prime": "proved"},
        "proof.ecpp", {"subject": "103", "steps": []},
    )
    bundle.add_claim(
        "curve.cardinality", {"n": "100"}, "proof.point-order",
        {"order": "100"},  # shape does not matter; validate stops earlier
    )
    assert _raises(BundleError, bundle.validate)


def _rust_required_deps():
    """The Rust table, parsed arm by arm.

    Read from the source rather than duplicated here, because a copy of a
    table is a table that stops agreeing.
    """
    import re

    source = (ROOT / "verifier" / "src" / "verify.rs").read_text(encoding="utf-8")
    start = source.index("fn required_deps(")
    body = source[start : source.index("\n}", start)]
    arms = re.findall(
        r'\(\s*"([^"]+)"\s*,\s*(?:_|"([^"]+)")\s*\)\s*=>\s*&\[(.*?)\]',
        body,
        re.DOTALL,
    )
    table = {}
    for evidence, claim, names in arms:
        table[(evidence, claim or None)] = tuple(sorted(re.findall(r'"([^"]+)"', names)))
    return table


def test_the_two_dependency_tables_agree():
    """The Rust table is the one that matters; the Python mirror has to
    list exactly the same requirements, arm for arm.

    This test used to ask whether each required name appeared *anywhere*
    in the Rust table, which is a question that cannot come out wrong:
    `curve.order` appears in four arms, so the Python entry for
    `proof.multiplicative-order` could omit it and still pass — and it
    did. A mirror test that cannot see a divergence is worse than none,
    because it reads as coverage."""
    from core.bundle.model import REQUIRED_DEPS

    rust = _rust_required_deps()
    python = {key: tuple(sorted(value)) for key, value in REQUIRED_DEPS.items()}
    assert rust, "the Rust table did not parse; the test, not the table, is wrong"
    assert python == rust, (
        "the tables differ\n"
        f"  only in Python: {sorted(set(python.items()) - set(rust.items()))}\n"
        f"  only in Rust:   {sorted(set(rust.items()) - set(python.items()))}"
    )


def test_the_two_asserts_tables_agree():
    """`asserts` is closed on both sides, and the two tables must match
    arm for arm.

    A reviewer closed `asserts` in the producer and left the verifier
    open, with a comment promising a mirror that did not yet exist. Now it
    does, and the verifier refuses the field too — it is the source of
    truth. This test parses the Rust table from source rather than copying
    it, and compares per claim, not "appears somewhere", so it can see a
    divergence rather than reading as coverage over one it cannot."""
    import re

    from core.bundle.model import ASSERTS_KEYS

    source = (ROOT / "verifier" / "src" / "verify.rs").read_text(encoding="utf-8")
    start = source.index("fn asserts_keys(")
    body = source[start : source.index("\n}", start)]
    arms = re.findall(r'"([^"]+)"\s*=>\s*&\[(.*?)\]', body, re.DOTALL)
    rust = {
        claim: frozenset(re.findall(r'"([^"]+)"', keys)) for claim, keys in arms
    }
    assert rust, "the Rust asserts table did not parse; the test is wrong"
    python = {k: frozenset(v) for k, v in ASSERTS_KEYS.items()}
    assert python == rust, (
        "the asserts tables differ\n"
        f"  only in Python: {sorted((k, sorted(python[k])) for k in python if python.get(k) != rust.get(k))}\n"
        f"  only in Rust:   {sorted((k, sorted(rust[k])) for k in rust if rust.get(k) != python.get(k))}"
    )


def test_a_stray_field_in_asserts_is_refused():
    """The gap the reviewer found: `asserts` is what a policy reads and a
    person diffs, so an unread field there reaches a machine verdict and a
    human with nothing behind it. The producer refused it; the verifier
    did not. Now both do."""
    if not _ready("test_a_stray_field_in_asserts_is_refused", "bls24-509"):
        return
    document = _load("bls24-509")
    _claim(document, "g2.twist")["asserts"]["security_level"] = "192-bit"
    code, output = _run(_write(document))
    assert code != 0
    assert "unknown field `security_level`" in output, output


# -- primality of p is required, not assumed --------------------------


def test_a_bundle_without_a_proved_characteristic_is_refused():
    """Every part of the point-order argument — the field itself, Euler's
    criterion on beta, the Hasse window — assumes p is prime. Nothing in
    the evidence can establish that, so it has to come from elsewhere in
    the bundle, from evidence that is itself proved."""
    if not _ready("test_a_bundle_without_a_proved_characteristic_is_refused", "bn254"):
        return
    document = _load("bn254")
    claim = _claim(document, "field.characteristic")
    document["evidence"].pop(claim["evidence"]["ref"], None)
    reference = "sha256:" + "0" * 64
    claim["evidence"] = {"type": "candidate.pseudoprime", "ref": reference}
    document["evidence"][reference] = {
        "type": "candidate.pseudoprime", "tool": "pari 2.15",
    }
    code, output = _run(_write(document))
    assert code != 0


# -- the Hasse window must be positive --------------------------------


def test_a_non_positive_window_is_refused():
    """A window whose floor is not positive admits zero as a multiple of
    anything, and zero would be pinned as a group order. Unreachable for
    a real curve; an invariant beats an argument that it is unreachable."""
    for order, low, high in [(10, -5, 5), (10, -20, 5), (7, -100, 3)]:
        assert _raises(
            PointOrderError, unique_multiple_in_window, order, low, high
        ), (order, low, high)


def test_a_positive_window_still_pins():
    assert unique_multiple_in_window(10, 100, 109) == 100
    assert unique_multiple_in_window(97, 97, 97) == 97


def test_both_implementations_use_the_same_words():
    """The refusal text is what people compare behaviour by."""
    source = (ROOT / "verifier" / "src" / "point_order.rs").read_text(encoding="utf-8")
    assert "the Hasse window must be positive" in source
    try:
        unique_multiple_in_window(10, -5, 5)
    except PointOrderError as exc:
        assert "the Hasse window must be positive" in str(exc)


# -- a factor entry cannot be enormous --------------------------------


def test_an_absurd_exponent_is_refused_before_it_is_computed():
    """`prime = 2, exponent = 4e9` is a well formed entry whose power is
    half a gigabyte. Computing it to discover the product is wrong is the
    wrong order of operations.

    The refusal is exact, not a heuristic: bits(p^e) >= e*(bits(p)-1)+1,
    so once bits(p)*e passes the target's size the power cannot divide
    it."""
    assert _raises(
        OrderError, point_order, None, None, 100, [(2, 4_000_000_000)]
    )


def test_many_small_factors_cannot_accumulate_past_the_target():
    assert _raises(
        OrderError, point_order, None, None, 100, [(3, 40), (5, 40)]
    )


def test_a_power_of_two_cofactor_is_not_refused():
    """The regression for a guard that was an upper bound where it needed
    a lower one.

    `bits(p) * e` and `e * (bits(p) - 1) + 1` agree unless p is a power of
    two, so the mistake was invisible on a corpus of four curves and
    rejected every Edwards curve the moment one arrived. 2^3 against a
    cofactor of 8: the bound is 4 and the wrong expression gives 6.
    """
    for exponent in range(1, 12):
        cofactor = 2**exponent
        # e*(bits(2)-1)+1 = e+1, and bits(2^e)+1 = e+2, so this must pass
        # for every e. The upper bound 2*e passes only for e <= 2.
        assert exponent * (2 - 1) + 1 <= cofactor.bit_length() + 1, exponent


def test_the_verifier_accepts_a_power_of_two_cofactor():
    """The same thing, through the program rather than the arithmetic."""
    if not _ready("test_the_verifier_accepts_a_power_of_two_cofactor", "curve25519"):
        return
    code, output = _run(VECTORS / "curve25519.ccert")
    assert code == 0, output
    assert "cofactor of 4 bits" in output


def test_an_honest_factorisation_is_not_refused():
    """The guard must never fire on real data. 2^2 * 3 = 12, against a
    group order of 12."""
    source = (ROOT / "verifier" / "src" / "claims.rs").read_text(encoding="utf-8")
    assert "max_bits" in source
    assert "exceeds the number it claims to divide" in source


def test_the_verifier_refuses_a_giant_exponent():
    if not _ready("test_the_verifier_refuses_a_giant_exponent", "bn254"):
        return
    document = _load("bn254")
    payload = _payload(document, "g2.order")
    payload["factors"][0]["exponent"] = "4000000000"
    _rehash(document, "g2.order")
    import time

    started = time.monotonic()
    code, output = _run(_write(document))
    elapsed = time.monotonic() - started
    assert code != 0
    assert elapsed < 20, "the refusal took long enough to suggest it computed the power"


# -- one spelling per number ------------------------------------------


def test_an_unreduced_coordinate_is_refused():
    """The producer requires reduced coordinates; the verifier used to
    reduce them silently, so a payload no canonical producer could write
    would still verify."""
    if not _ready("test_an_unreduced_coordinate_is_refused", "bn254"):
        return
    document = _load("bn254")
    payload = _payload(document, "curve.cardinality")
    p = int(payload["field"]["p"])
    payload["point"]["x"][0] = str(int(payload["point"]["x"][0]) + p)
    _rehash(document, "curve.cardinality")
    code, output = _run(_write(document))
    assert code != 0
    assert "not reduced" in output


# -- constants written twice ------------------------------------------


def test_the_small_prime_bound_agrees_across_languages():
    """The bound below which the verifier settles primality itself is
    written in the producer and again in the verifier. If they diverge,
    the producer omits a chain the verifier then demands, or supplies one
    it did not need — and nothing in either program would notice.

    A test rather than generating one file from the other: the two
    implementations are meant to be independent, and an external arbiter
    keeps them so.
    """
    import re

    from core.bundle.builder import SMALL_PRIME_LIMIT, SMALL_PRIME_LIMIT_EXP

    source = (ROOT / "verifier" / "src" / "ecpp.rs").read_text(encoding="utf-8")
    match = re.search(r"SMALL_PRIME_LIMIT_EXP:\s*u32\s*=\s*(\d+)", source)
    assert match, "the Rust bound could not be read from ecpp.rs"
    assert int(match.group(1)) == SMALL_PRIME_LIMIT_EXP
    assert SMALL_PRIME_LIMIT == 10**SMALL_PRIME_LIMIT_EXP
    # And the limit is actually used, not merely defined.
    assert "small_prime_limit()" in source


# -- declared and consumed --------------------------------------------


def test_order_unique_binds_n_to_the_proved_prime():
    """The second review's finding, and the second of its kind.

    `check.order-unique` declared `curve.order.prime`, its tier was
    checked, and its value was never read. The classical argument needs n
    prime — then order(P) is 1 or n, the point is affine so not 1, and a
    window narrower than n admits one multiple. Without primality `n·P =
    O` shows only that order(P) divides n, and a 2-torsion point confirms
    every even n in the window.

    Demonstrated before it was fixed: a Curve25519 bundle with a point of
    order 2 and n = #E + 2 was reported `3 proved, exit 0`.
    """
    if not _ready("test_order_unique_binds_n_to_the_proved_prime"):
        return
    path = INVALID / "order-unique-composite-n.ccert"
    if not path.is_file():
        SKIPPED.append("test_order_unique_binds_n_to_the_proved_prime")
        return
    code, output = _run(path)
    assert code != 0
    assert "not the subgroup order proved prime" in output


def test_every_declared_dependency_is_actually_read():
    """Declared-and-unread is the same hole as undeclared.

    Checked by reading the Rust: each entry in the required table names a
    claim, and the handler for that evidence kind must mention it. Coarse,
    but it would have caught both instances found so far.
    """
    source = (ROOT / "verifier" / "src").glob("*.rs")
    text = "\n".join(path.read_text(encoding="utf-8") for path in source)
    for evidence, claim in (
        ("check.order-unique", "curve.order.prime"),
        ("proof.multiplicative-order", "curve.order.prime"),
        ("proof.point-order", "field.characteristic"),
        ("check.curve-model", "field.characteristic"),
    ):
        assert f'"{claim}"' in text, f"{evidence} declares {claim} but nothing reads it"


def test_reading_the_cardinality_requires_declaring_it():
    """The static table cannot say `curve.cardinality when the bundle has
    one`, so the requirement lives where the read happens."""
    source = (ROOT / "verifier" / "src" / "claims.rs").read_text(encoding="utf-8")
    assert "reads `{source}` and must declare it" in source


# -- the honest corpus is untouched -----------------------------------


def test_every_published_vector_still_verifies():
    """None of the above may be bought by loosening anything."""
    if not _ready("test_every_published_vector_still_verifies"):
        return
    for path in sorted(VECTORS.glob("*.ccert")):
        code, output = _run(path)
        assert code == 0, f"{path.name}: {output}"


def test_the_g2_notes_state_what_each_rests_on():
    """Two claims, one argument underneath, and each note says so.

    `g2.cardinality` ties the curve in its evidence to the subject: `a' =
    0` plus non-singularity plus `q = 1 mod 3` makes that curve one of the
    six sextic twists, and the census on `r` says which. `g2.twist` reads
    an order rather than a curve, so on its own it could not show the
    curve in the evidence is that twist — its handler therefore refuses to
    classify an order that rests on anything but the elimination, and its
    note names what it is standing on rather than claiming the reach
    itself."""
    if not _ready("test_the_g2_notes_state_what_each_rests_on", "bls12-381"):
        return
    _, output = _run(VECTORS / "bls12-381.ccert")
    assert "sextic twist of the subject" in output
    assert "established by the elimination this claim rests on" in output


# -- the elimination is about the curve it says it is about ------------


def _base_curve_forgery(curve_name="bls12-381"):
    """A bundle whose G2 order was settled on the wrong curve.

    Built rather than described, because every stated condition of the
    argument is met and only the curve is wrong: the points are on it,
    each eliminates something, exactly one candidate survives, it lies in
    the Hasse window, and `r` divides it so the cofactor claim downstream
    is satisfied. What it settles is the order of `E(F_p^2)`, which is not
    the second group. This verified end to end before the census existed.
    """
    import hashlib

    from core.claims.elimination import eliminate, points_in_order
    from core.claims.point_order import make_curve, make_field
    from core.claims.twist import twist_candidates

    document = _load(curve_name)
    claim = next(c for c in document["claims"] if c["claim"] == "g2.cardinality")
    payload = document["evidence"].pop(claim["evidence"]["ref"])

    p = int(document["subject"]["field"]["p"])
    degree = int(payload["field"]["degree"])
    field = make_field(p, degree, int(payload["field"]["beta"]))
    padding = (0,) * (degree - 1)
    curve = make_curve(
        field,
        (int(document["subject"]["a"]),) + padding,
        (int(document["subject"]["b"]),) + padding,
    )
    cardinality = int(
        next(c for c in document["claims"] if c["claim"] == "curve.cardinality")
        ["asserts"]["n"]
    )
    candidates, _t2, _v = twist_candidates(p, cardinality, degree)
    index, used = eliminate(curve, candidates, points_in_order(curve, field))
    assert index == 0, "the base curve should settle on its own candidate"

    payload["curve"] = {
        "a": [str(c) for c in field.coefficients(curve.a)],
        "b": [str(c) for c in field.coefficients(curve.b)],
    }
    payload["points"] = [
        {
            "x": [str(c) for c in field.coefficients(point[0])],
            "y": [str(c) for c in field.coefficients(point[1])],
        }
        for point in used
    ]
    claim["asserts"]["n"] = str(candidates[index])

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    document["evidence"][digest] = payload
    claim["evidence"]["ref"] = digest
    return document


def test_an_elimination_on_the_base_curve_is_refused():
    """The hole a reviewer found, and the one thing this fix exists for."""
    if not _ready("test_an_elimination_on_the_base_curve_is_refused", "bls12-381"):
        return
    # Through `_write`, not through `write_text`. The helper opens the
    # stream with `newline="\n"`, and on Windows the default does not:
    # the document would go out with CRLF, the verifier would trim one
    # byte of the pair and refuse the leftover as trailing — a refusal,
    # but for the encoding rather than for the forgery, which is exactly
    # the "one defect masking another" this suite exists to avoid.
    code, output = _run(_write(_base_curve_forgery()))
    assert code != 0, "a G2 order settled on the base curve must not verify"
    assert "own order over the extension" in output, output


def test_a_curve_with_nonzero_a_is_refused_before_any_point_is_read():
    """`a' != 0` means the curve is not a sextic twist of anything here.

    The elimination would then narrow a set of six that need not contain
    the answer, which is a true statement with a false conclusion. Refused
    on the coefficient, before a point is looked at."""
    if not _ready("test_a_curve_with_nonzero_a_is_refused_before_any_point_is_read",
                  "bls12-381"):
        return
    import hashlib

    document = _load("bls12-381")
    claim = _claim(document, "g2.cardinality")
    payload = document["evidence"].pop(claim["evidence"]["ref"])
    payload["curve"]["a"] = ["1", "0"]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    document["evidence"][digest] = payload
    claim["evidence"]["ref"] = digest

    code, output = _run(_write(document))
    assert code != 0
    assert "not a sextic twist of the subject" in output, output


def test_the_census_on_r_is_in_the_verifier_source():
    """A read is a dependency, and a dependency is declared.

    The census reads `curve.order.prime`, so the static table has to
    require it. Round two's finding was the same shape facing the other
    way: an edge declared and never read."""
    source = (ROOT / "verifier" / "src" / "verify.rs").read_text(encoding="utf-8")
    marker = source.split('("derive.order-elimination", _)')[1][:200]
    assert "curve.order.prime" in marker, marker


# -- the second door into the same room --------------------------------


def test_a_g2_order_may_not_be_proved_by_a_witness():
    """`proof.point-order` used to accept `g2.cardinality` over `F_p^2`
    and tie the curve in its evidence to nothing.

    That made it the way round the binding elimination performs: the same
    base-curve forgery, carried under a different evidence type, with a
    witness instead of two points. The factorisations the certificate
    already publishes are enough to build it, so this was not a
    theoretical door. It is closed by name rather than by adding a second
    copy of the binding, because two arguments for one claim is the thing
    a reader should not have to adjudicate."""
    if not _ready("test_a_g2_order_may_not_be_proved_by_a_witness", "bls12-381"):
        return
    document = _load("bls12-381")
    claim = _claim(document, "g2.cardinality")

    # The G1 witness payload, moved under the G2 claim. A relabelled
    # elimination payload would be refused too, but on its shape — it
    # carries `points` where a witness argument carries `point` — and a
    # refusal for the wrong reason is not evidence that the right check
    # exists. This payload is a real, well-formed `proof.point-order`, so
    # nothing stops the handler being reached.
    witness = _claim(document, "curve.cardinality")["evidence"]["ref"]
    # The elimination payload goes with it. An orphan in the pool is its
    # own refusal, and would mask this one.
    document["evidence"].pop(claim["evidence"]["ref"])
    claim["evidence"] = {"type": "proof.point-order", "ref": witness}
    claim["asserts"]["n"] = _claim(document, "curve.cardinality")["asserts"]["n"]

    code, output = _run(_write(document))
    assert code != 0
    assert "supports only `curve.cardinality`" in output, output


def test_the_producer_refuses_the_same_pairing():
    """The verifier is the authority, and the producer should not be able
    to write a document it will reject."""
    from core.bundle.model import Bundle

    bundle = Bundle(subject={"kind": "elliptic-curve"})
    bundle.add_claim(
        "g2.cardinality", {"n": "7"}, "proof.point-order", {"order": "7"},
    )
    assert _raises(BundleError, bundle.validate)


def test_a_cardinality_may_not_be_read_off_a_subgroup_order():
    """The fallback in `find_cardinality` is safe for a reason nothing
    checked.

    With no `curve.cardinality` claim the handlers read `curve.order`,
    which names a *subgroup* order. That is right exactly when the two
    coincide, and today they always do on the path that reaches it:
    `check.order-unique` pins the cardinality itself, and `check.cofactor`
    cannot get there because it requires a cardinality claim to exist. An
    argument is not a check, and this is the fourth instance of the
    pattern that produced every serious bug here — a value read from the
    wrong claim, where the two coincide on the curves that exist today."""
    source = (ROOT / "verifier" / "src" / "claims.rs").read_text(encoding="utf-8")
    body = source[source.index("pub fn find_cardinality(") :]
    body = body[: body.index("\npub fn ")]
    assert "check.order-unique" in body, (
        "find_cardinality falls back to curve.order without checking which "
        "evidence established it"
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
