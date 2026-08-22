"""Builds the certificates a verifier must refuse.

    python -m tools.make_invalid_vectors
    python -m tools.make_invalid_vectors --check

The valid vectors say what a certificate looks like. These say what the
format rules out, which is the half a second implementation actually
needs: anyone can accept a good file, and a verifier is only worth
anything for what it turns away.

Each mutation is named for the defect it introduces, and each writes two
files: the certificate, and a `.expect` holding a substring the refusal
must contain. That second file is the point. A verifier that rejects
every one of these for the wrong reason has told you nothing — one defect
masking another is exactly how a hole survives a test suite, and it is
how two of these very mutations behaved when they were first written.

Most mutations work on the parsed object and are written back through the
canonical serialiser, so the file stays well formed and only the flaw
under test differs. The exceptions are the encoding cases, which have to
be made at the byte level because being malformed *is* the defect.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VALID = ROOT / "spec" / "vectors" / "valid"
INVALID = ROOT / "spec" / "vectors" / "invalid"

__all__ = ["MUTATIONS", "build_all"]


# -- helpers ----------------------------------------------------------


def _encode(document: dict) -> bytes:
    """Canonical bytes, the same shape the producer writes."""
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        .encode("utf-8")
        + b"\n"
    )


def _claim(document: dict, name: str) -> dict:
    for claim in document["claims"]:
        if claim["claim"] == name:
            return claim
    raise KeyError(name)


def _payload(document: dict, name: str) -> dict:
    return document["evidence"][_claim(document, name)["evidence"]["ref"]]


def _rekey(document: dict, name: str) -> None:
    """Re-address an evidence entry after editing it.

    Needed whenever the defect is not the hash itself. Without it the
    pool check fires first and the mutation never reaches the handler it
    was written for.
    """
    claim = _claim(document, name)
    payload = document["evidence"].pop(claim["evidence"]["ref"])
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    document["evidence"][digest] = payload
    claim["evidence"]["ref"] = digest


# -- the mutations ----------------------------------------------------
#
# Each takes a parsed bundle and edits it in place, or returns bytes for
# the encoding cases. The docstring is what the vector's README says.


def foreign_curve(document: dict) -> None:
    """Evidence proving an order for a different curve over the same field.

    Every step of the proof is honest. It is about y^2 = x^3 + b' rather
    than the subject's curve, and until this was caught the verifier had
    no reason to notice.
    """
    payload = _payload(document, "curve.cardinality")
    payload["curve"]["b"] = [str(int(payload["curve"]["b"][0]) + 2)]
    _rekey(document, "curve.cardinality")


def wrong_degree(document: dict) -> None:
    """Degree-2 evidence under a claim about the subject's own curve."""
    source = _claim(document, "g2.cardinality")
    target = _claim(document, "curve.cardinality")
    document["evidence"].pop(target["evidence"]["ref"])
    target["evidence"]["ref"] = source["evidence"]["ref"]
    target["asserts"]["n"] = source["asserts"]["n"]


def undeclared_dependency(document: dict) -> None:
    """A cofactor split that does not declare what it rests on."""
    _claim(document, "curve.order").pop("depends_on", None)


def candidate_source(document: dict) -> None:
    """A proved-looking split of a number nobody proved.

    The arithmetic is exact and the tier table is honest about each kind
    on its own. The hole was that nothing checked the standing of the
    value being divided.
    """
    claim = _claim(document, "g2.cardinality")
    document["evidence"].pop(claim["evidence"]["ref"])
    payload = {"type": "candidate.sea", "tool": "pari 2.15.4"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    document["evidence"][digest] = payload
    claim["evidence"] = {"type": "candidate.sea", "ref": digest}
    claim.pop("depends_on", None)


def unproved_characteristic(document: dict) -> None:
    """A cardinality over a characteristic nobody proved prime.

    The field, Euler's criterion and the Hasse window all assume it.
    """
    claim = _claim(document, "field.characteristic")
    document["evidence"].pop(claim["evidence"]["ref"], None)
    payload = {"type": "candidate.pseudoprime", "tool": "pari 2.15.4"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    document["evidence"][digest] = payload
    claim["evidence"] = {"type": "candidate.pseudoprime", "ref": digest}


def undersized_witness(document: dict) -> None:
    """A witness whose exact order leaves several candidates in the window.

    Everything here is true: the point is on the curve, its order is
    exactly what the payload says, and the factorisation is complete and
    proved. The witness is simply too small to single out one multiple,
    and a verifier that picked the nearest admissible one would produce
    output indistinguishable from a proof.

    Note that this cannot be faked by shrinking the stated order and
    leaving the point alone — that is a different defect, caught earlier
    by the check that the order annihilates the witness. The point has to
    be moved into a small subgroup.

    Built over the base field: the G2 order is settled by elimination
    now, which has no witness to undersize.
    """
    sys.path.insert(0, str(ROOT))
    from core.field.fp import CurveFp, Fp
    from core.field.order import point_order

    payload = _payload(document, "curve.cardinality")
    p = int(payload["field"]["p"])
    field = Fp(p)
    curve = CurveFp(
        field,
        field.element(int(payload["curve"]["a"][0])),
        field.element(int(payload["curve"]["b"][0])),
    )
    point = (
        field.element(int(payload["point"]["x"][0])),
        field.element(int(payload["point"]["y"][0])),
    )
    order = int(payload["order"])
    factors = [(int(e["prime"]), int(e["exponent"])) for e in payload["factors"]]

    smallest = min(prime for prime, _ in factors)
    reduced = curve.multiply(point, order // smallest)
    assert point_order(curve, reduced, order, factors) == smallest

    payload["point"] = {
        "x": [str(reduced[0][0])],
        "y": [str(reduced[1][0])],
    }
    payload["order"] = str(smallest)
    # Exponent one, not whatever the full order had. The reduced point has
    # order exactly `smallest`, and leaving the old exponent would make
    # the factorisation disagree with the order beside it — a different
    # defect, caught earlier, and not the one this vector is about.
    payload["factors"] = [
        {"prime": str(smallest), "exponent": "1"}
    ]
    _rekey(document, "curve.cardinality")


def chain_for_another_number(document: dict) -> None:
    """A primality chain that is valid, but not for the factor it sits on."""
    # Built from P-256's CM claim, which is the one place in the corpus
    # where a single payload carries two chains large enough to need
    # them. The G2 cardinality used to serve here and no longer can: it
    # is settled by elimination now and carries no factors at all.
    payload = _payload(document, "curve.cm")
    with_steps = [entry for entry in payload["factors"] if "steps" in entry]
    if len(with_steps) < 2:
        raise RuntimeError("this bundle has too few chains to swap")
    with_steps[0]["steps"], with_steps[1]["steps"] = (
        with_steps[1]["steps"],
        with_steps[0]["steps"],
    )
    _rekey(document, "curve.cm")


def giant_exponent(document: dict) -> None:
    """An exponent whose power would cost hundreds of megabytes.

    Well formed, and refused on the size of the entry rather than after
    computing it.
    """
    payload = _payload(document, "g2.order")
    payload["factors"][0]["exponent"] = "4000000000"
    _rekey(document, "g2.order")


def unreduced_coordinate(document: dict) -> None:
    """A coordinate written as x + p rather than x.

    Arithmetically the same point; not the same document. The format has
    one spelling per number, and a verifier that reduced silently would
    accept a file no canonical producer could write.
    """
    payload = _payload(document, "curve.cardinality")
    p = int(payload["field"]["p"])
    payload["point"]["x"][0] = str(int(payload["point"]["x"][0]) + p)
    _rekey(document, "curve.cardinality")


def broken_evidence_hash(document: dict) -> None:
    """Evidence edited without re-addressing it."""
    _payload(document, "curve.cardinality")["order"] = "7"


def square_beta(document: dict) -> None:
    """An extension modulus that factors, so the quotient is not a field."""
    payload = _payload(document, "g2.cardinality")
    payload["field"]["beta"] = "4"
    _rekey(document, "g2.cardinality")


def mismatched_cofactor(document: dict) -> None:
    """A split whose parts do not multiply back to the group order."""
    claim = _claim(document, "g2.order")
    claim["asserts"]["cofactor"] = str(int(claim["asserts"]["cofactor"]) + 1)


def overstated_largest_factor(document: dict) -> None:
    """A largest prime factor larger than any factor present.

    Subgroup-security policies read this number, so an unchecked claim
    about it would let a curve look safer than it is.
    """
    claim = _claim(document, "g2.order")
    claim["asserts"]["largest_prime_factor"] = str(
        int(claim["asserts"]["largest_prime_factor"]) * 2
    )


def wrong_family_parameter(document: dict) -> None:
    """A family parameter one away from the real one.

    The polynomials then generate a different characteristic, and the
    refusal comes from arithmetic the verifier redoes rather than from a
    table it consults.
    """
    claim = _claim(document, "curve.family")
    payload = _payload(document, "curve.family")
    payload["u"] = str(int(payload["u"]) + 1)
    claim["asserts"]["u"] = payload["u"]
    _rekey(document, "curve.family")


def wrong_family_name(document: dict) -> None:
    """A BN curve claiming to be BLS12.

    Caught by the divisibility condition rather than by comparing the
    generated numbers: a BN parameter does not generate a BLS12 curve at
    all, and the exactness check on the division by three is where that
    becomes visible.
    """
    claim = _claim(document, "curve.family")
    payload = _payload(document, "curve.family")
    payload["family"] = "bls12"
    claim["asserts"]["family"] = "bls12"
    _rekey(document, "curve.family")


def unknown_family(document: dict) -> None:
    """A family the verifier has never heard of.

    The list is closed: a verifier that skipped families it did not
    recognise would let a bundle assert membership in anything.
    """
    claim = _claim(document, "curve.family")
    payload = _payload(document, "curve.family")
    payload["family"] = "kss16"
    claim["asserts"]["family"] = "kss16"
    _rekey(document, "curve.family")


def wrong_twist_class(document: dict) -> None:
    """A twist class index that is one of the six, but not the right one."""
    claim = _claim(document, "g2.twist")
    payload = _payload(document, "g2.twist")
    payload["index"] = "3" if payload["index"] != "3" else "1"
    claim["asserts"]["class"] = payload["index"]
    _rekey(document, "g2.twist")


def twist_class_disagrees_with_evidence(document: dict) -> None:
    """A claim stating one twist class while its evidence proves another.

    The evidence is untouched and re-derives correctly; only the number
    the claim asserts is moved. That number is the one the pairing
    policies read, so before it was checked a verdict could be computed
    from a figure nothing established — an assertion wearing the evidence
    of its neighbour.
    """
    claim = _claim(document, "g2.twist")
    stated = claim["asserts"]["class"]
    claim["asserts"]["class"] = "3" if stated != "3" else "1"


def twist_class_at_the_wrong_degree(document: dict) -> None:
    """A class index labelled with a degree it does not index into.

    The six classes over F_p^4 are a different set from the six over
    F_p^2, so an index without a degree is a number without a meaning.
    Relabelling one as the other has to be refused rather than read as a
    convention, and it is — at the first quantity that depends on the
    degree, which is `v`. The whole enumeration is built from the trace
    over F_p^degree, so a relabelled claim disagrees with its own evidence
    before the index is ever reached. The expectation names `v` rather
    than the index because that is what the verifier actually says, and a
    vector whose stated reason differs from the real one is the defect
    this directory exists to catch.
    """
    claim = _claim(document, "g2.twist")
    claim["asserts"]["degree"] = "4" if claim["asserts"]["degree"] == "2" else "2"


def wrong_twist_v(document: dict) -> None:
    """A v that does not satisfy 4q = t2^2 + 3v^2.

    The verifier recomputes it rather than taking it, so the number in
    the evidence is a convenience for a reader and not a source of truth.
    """
    payload = _payload(document, "g2.twist")
    payload["v"] = str(int(payload["v"]) + 1)
    _rekey(document, "g2.twist")


def overstated_two_adicity(document: dict) -> None:
    """A two-adicity larger than the exponent of two in r - 1.

    A SNARK policy reads this number to decide how large a proving domain
    the curve admits, so an unchecked assertion about it would let a curve
    look more capable than it is. The verifier recomputes it from the
    factorisation it has already proved complete.
    """
    claim = _claim(document, "curve.embedding")
    claim["asserts"]["two_adicity"] = str(
        int(claim["asserts"]["two_adicity"]) + 1
    )


def wrong_cm_trace(document: dict) -> None:
    """A CM trace computed from the subgroup order rather than the
    cardinality.

    On a curve with cofactor one the two coincide, which is why several
    handlers read `curve.order` and were right to. Here the cofactor is
    126 bits wide and the trace is a trace for no curve at all.
    """
    claim = _claim(document, "curve.cm")
    p = int(document["subject"]["field"]["p"])
    r = int(_claim(document, "curve.order")["asserts"]["n"])
    claim["asserts"]["trace"] = str(p + 1 - r)


def unsupported_twist_factor(document: dict) -> None:
    """A largest prime factor of the twist asserted without support.

    A twist-security policy reads this number, so an assertion nothing
    establishes is worse than no assertion: it reads as a fact.
    """
    claim = _claim(document, "twist.cardinality")
    claim["asserts"]["largest_prime_factor"] = str(
        int(claim["asserts"]["largest_prime_factor"]) * 2
    )


def wrong_model_parameter(document: dict) -> None:
    """A Montgomery parameter that does not give the stated coefficients.

    Converting quietly and certifying the Weierstrass result would give a
    document whose subject is a curve nobody uses under a name everybody
    recognises. The conversion is a claim precisely so that a wrong one
    can be caught.
    """
    claim = _claim(document, "curve.model")
    claim["asserts"]["A"] = str(int(claim["asserts"]["A"]) + 2)


def unknown_model(document: dict) -> None:
    """A curve model the verifier cannot convert.

    The list is closed: a model nobody can convert is not a claim, and
    skipping unrecognised ones would let a bundle assert membership in
    any shape at all.
    """
    claim = _claim(document, "curve.model")
    claim["asserts"]["model"] = "hessian"


def singular_montgomery(document: dict) -> None:
    """A = 2, so x^3 + A x^2 + x has a repeated root.

    A degenerate parameter is not an awkward coefficient; it means there
    is no curve, and the refusal should say which condition failed.
    """
    claim = _claim(document, "curve.model")
    claim["asserts"]["A"] = "2"


def wrong_model_parameter(document: dict) -> None:
    """A Montgomery parameter that gives different Weierstrass coefficients.

    The conversion is the claim: without it, a certificate for Curve25519
    would carry a Weierstrass curve nobody uses under a name everybody
    recognises, and a reader would have to take the map on faith.
    """
    claim = _claim(document, "curve.model")
    key = "A" if "A" in claim["asserts"] else "d"
    claim["asserts"][key] = str(int(claim["asserts"][key]) + 1)


def unknown_model(document: dict) -> None:
    """A curve model nothing can convert.

    The list is closed for the same reason the family list is: a model a
    verifier cannot recompute is not a claim, and skipping the ones it
    does not recognise would let a bundle assert anything.
    """
    claim = _claim(document, "curve.model")
    claim["asserts"]["model"] = "huff"


def singular_montgomery(document: dict) -> None:
    """A = 2, which makes x^3 + A x^2 + x have a repeated root.

    Degenerate rather than merely unusual: there is no curve, so the
    refusal names the condition rather than reporting a mismatch.
    """
    claim = _claim(document, "curve.model")
    if "A" not in claim["asserts"]:
        raise RuntimeError("this bundle is not a Montgomery curve")
    claim["asserts"]["A"] = "2"


def order_unique_composite_n(document: dict) -> None:
    """A composite order confirmed by a point of order two.

    `check.order-unique` needs n prime: then order(P) is 1 or n, the point
    is affine so it is not 1, and a window narrower than n admits exactly
    one multiple. Without primality `n·P = O` shows only that order(P)
    divides n — and a 2-torsion point satisfies every even n in the
    window.

    The vector uses Curve25519, whose cofactor of 8 guarantees a point of
    order 2, and asserts n = #E + 2: composite, inside the window, larger
    than 4·sqrt(p), and not the group order. The dependency on
    `curve.order.prime` was declared and tier-checked all along; its value
    was simply never read.
    """
    import hashlib

    p = int(document["subject"]["field"]["p"])
    # x = A/3 is a root of x^3 + ax + b for the Weierstrass form of a
    # Montgomery curve with parameter A, so (x, 0) has order two.
    model = _claim(document, "curve.model")["asserts"]
    x2 = int(model["A"]) * pow(3, -1, p) % p
    cardinality = int(_claim(document, "curve.cardinality")["asserts"]["n"])

    keep = {"field.characteristic", "curve.order.prime"}
    document["claims"] = [c for c in document["claims"] if c["claim"] in keep]
    refs = {c["evidence"]["ref"] for c in document["claims"]}
    document["evidence"] = {
        key: value for key, value in document["evidence"].items() if key in refs
    }

    payload = {
        "point": {"x": str(x2), "y": "0"},
        "type": "check.order-unique",
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    document["evidence"][digest] = payload
    document["claims"].append({
        "claim": "curve.order",
        "asserts": {"n": str(cardinality + 2), "cofactor": "1"},
        "evidence": {"type": "check.order-unique", "ref": digest},
        "depends_on": ["curve.order.prime", "field.characteristic"],
    })


def elimination_without_points(document: dict) -> None:
    """An elimination argument with nothing to eliminate with.

    A group order annihilates every point, so the candidates are narrowed
    by points and by nothing else. An empty list narrows nothing, and six
    survivors is a refusal rather than a choice.
    """
    payload = _payload(document, "g2.cardinality")
    payload["points"] = []
    _rekey(document, "g2.cardinality")


def elimination_useless_point(document: dict) -> None:
    """A point that rules nothing out, added after the argument closed.

    Padding in an argument is where a reader stops reading, so a point
    that eliminates no candidate is refused rather than ignored.
    """
    payload = _payload(document, "g2.cardinality")
    payload["points"] = payload["points"] + [dict(payload["points"][0])]
    _rekey(document, "g2.cardinality")


def elimination_point_off_curve(document: dict) -> None:
    """A point that is not on the curve it is meant to be eliminating on."""
    payload = _payload(document, "g2.cardinality")
    payload["points"][0]["y"][0] = str(int(payload["points"][0]["y"][0]) + 1)
    _rekey(document, "g2.cardinality")


def an_asserts_object_with_a_field_nobody_reads(document: dict) -> None:
    """A claim wearing a false attribute inside its own `asserts`.

    `asserts` is the object a policy reads and a person diffs, and it was
    the one level the closed key sets did not cover. A field like
    `"security_level": "192-bit"` there is read by nobody and believed by
    the reader it is aimed at. A reviewer found the gap; this vector keeps
    it shut, on the verifier side where truth lives.
    """
    _claim(document, "g2.twist")["asserts"]["security_level"] = "192-bit"


def a_claim_with_a_field_nobody_reads(document: dict) -> None:
    """A claim carrying its own verdict, in a field no check covers.

    `"tier": "proved"` next to a claim, in a document people read and
    diff. Nothing in the verifier would ever look at it, which is the
    problem rather than the reassurance: a reader would, and the format
    exists so that what a reader sees is what a verifier checked.
    """
    _claim(document, "curve.cardinality")["tier"] = "proved"


def a_subject_with_an_extra_field(document: dict) -> None:
    """A subject with a line asserting something outside the format.

    The top level of a bundle has always refused unknown fields. Nothing
    below it did, so this was the way to put an unchecked sentence into a
    certificate and have it verify.
    """
    document["subject"]["audited_by"] = "nobody"


def an_evidence_payload_with_an_extra_field(document: dict) -> None:
    """Padding inside the evidence itself.

    The same defect as an elimination point that rules nothing out, which
    this format already refuses: a step in an argument that decides
    nothing is where a reader stops reading.
    """
    _payload(document, "curve.order")["shortcut"] = "trust me"
    _rekey(document, "curve.order")


def a_chain_step_with_an_extra_field(document: dict) -> None:
    """A line inside an Atkin-Morain chain that no check covers.

    A step is six numbers. The seventh would be read by nobody and
    diffed by everybody, and a primality chain is the last place in a
    certificate where an unexamined sentence should be able to sit.
    """
    _payload(document, "field.characteristic")["steps"][0]["comment"] = "trust me"
    _rekey(document, "field.characteristic")


def a_factor_entry_with_an_extra_field(document: dict) -> None:
    """Padding inside a factorisation, where a policy reads its numbers.

    The largest prime factor of a cofactor is what a subgroup-security
    criterion decides on. An entry carrying anything beyond its prime,
    exponent and chain is an entry making a claim outside the format.
    """
    _payload(document, "curve.order")["factors"][0]["note"] = "believed prime"
    _rekey(document, "curve.order")


def a_witness_point_with_an_extra_field(document: dict) -> None:
    """A point is an abscissa and an ordinate."""
    _payload(document, "curve.cardinality")["point"]["z"] = "1"
    _rekey(document, "curve.cardinality")


def elimination_on_the_base_curve(document: dict) -> None:
    """An elimination run on the subject's own curve over the extension.

    The mutation a reviewer found, and the only one here whose every
    stated condition is met. The curve is honest, the points are honest
    and found by the same abscissa scan a producer uses, each of them
    eliminates something, exactly one candidate survives, and it lies in
    the Hasse window. What it settles is the order of `E(F_p^2)` — which
    `r` divides, so the cofactor claim downstream is satisfied too — and
    that group is not the second one. Before the census on `r` existed the
    whole bundle verified, and the argument was wrong about which curve it
    was talking about rather than wrong about any step.
    """
    sys.path.insert(0, str(ROOT))
    from core.claims.elimination import eliminate, points_in_order
    from core.claims.point_order import make_curve, make_field
    from core.claims.twist import twist_candidates

    payload = _payload(document, "g2.cardinality")
    p = int(document["subject"]["field"]["p"])
    subject_a = int(document["subject"]["a"])
    subject_b = int(document["subject"]["b"])
    degree = int(payload["field"]["degree"])
    beta = int(payload["field"]["beta"])
    cardinality = int(_claim(document, "curve.cardinality")["asserts"]["n"])

    field = make_field(p, degree, beta)
    padding = (0,) * (degree - 1)
    curve = make_curve(field, (subject_a,) + padding, (subject_b,) + padding)
    candidates, _t2, _v = twist_candidates(p, cardinality, degree)
    index, used = eliminate(curve, candidates, points_in_order(curve, field))
    if index != 0:
        raise RuntimeError("the base curve did not settle on its own candidate")

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
    _rekey(document, "g2.cardinality")
    _claim(document, "g2.cardinality")["asserts"]["n"] = str(candidates[index])


def elimination_wrong_survivor(document: dict) -> None:
    """An order that is not the candidate the points left standing."""
    claim = _claim(document, "g2.cardinality")
    claim["asserts"]["n"] = str(int(claim["asserts"]["n"]) + 1)


def degree_four_without_xi(document: dict) -> None:
    """A tower field missing its second parameter.

    `F_p^4` is `F_p^2[v]/(v^2 - xi)`, and without xi a reader cannot
    rebuild the field. Every coefficient in the payload then means
    something else, and the arithmetic would agree with itself while
    agreeing with nothing.
    """
    payload = _payload(document, "g2.cardinality")
    payload["field"].pop("xi", None)
    _rekey(document, "g2.cardinality")


def square_xi(document: dict) -> None:
    """A tower modulus that factors.

    xi must be a non-residue *in F_p^2*, which is stricter than being one
    in F_p. A square there makes the quotient a ring with zero divisors,
    and every order computed in it is void.
    """
    payload = _payload(document, "g2.cardinality")
    p = int(payload["field"]["p"])
    beta = int(payload["field"]["beta"])
    # (1 + u)^2 = 1 + beta + 2u, a square by construction.
    payload["field"]["xi"] = [str((1 + beta) % p), "2"]
    _rekey(document, "g2.cardinality")


def unfactored_cofactor_with_a_claim(document: dict) -> None:
    """A largest prime factor asserted where nothing was factored.

    The cofactor factorisation is optional — BLS24-315's is a 983-bit
    composite and will not be produced — but an assertion about it
    without one reads as established and is not.
    """
    claim = _claim(document, "g2.order")
    claim["asserts"]["largest_prime_factor"] = "1000003"


# -- byte-level cases -------------------------------------------------


def whitespace(raw: bytes) -> bytes:
    """Valid JSON, non-canonical bytes: one space after a separator."""
    return raw.replace(b'","', b'", "', 1)


def reordered_keys(raw: bytes) -> bytes:
    """Valid JSON whose top-level keys are not sorted."""
    document = json.loads(raw)
    ordered = {
        key: document[key]
        for key in ("version", "format", "subject", "claims", "evidence")
        if key in document
    }
    return json.dumps(ordered, separators=(",", ":")).encode("utf-8") + b"\n"


def trailing_bytes(raw: bytes) -> bytes:
    """A second newline after the document."""
    return raw + b"\n"


MUTATIONS: dict[str, tuple[str, object, str]] = {
    # name: (source curve, mutation, expected substring of the refusal)
    "foreign-curve": ("bn254", foreign_curve, "different curve"),
    "wrong-degree": ("bls12-381", wrong_degree, "degree"),
    "undeclared-dependency": ("bn254", undeclared_dependency, "must declare"),
    "candidate-source": ("bls12-381", candidate_source, "candidate"),
    "unproved-characteristic": ("bn254", unproved_characteristic, "candidate"),
    "undersized-witness": ("curve25519", undersized_witness, "multiples"),
    "chain-for-another-number": (
        "p-256", chain_for_another_number, "chain",
    ),
    "giant-exponent": ("bls12-381", giant_exponent, "exceeds"),
    "unreduced-coordinate": ("bn254", unreduced_coordinate, "not reduced"),
    "broken-evidence-hash": ("bn254", broken_evidence_hash, "hash"),
    "square-beta": ("bls12-381", square_beta, "square"),
    "mismatched-cofactor": ("bls12-381", mismatched_cofactor, "multiply"),
    "overstated-largest-factor": (
        "bls12-381", overstated_largest_factor, "largest",
    ),
    "wrong-family-parameter": (
        "bn254", wrong_family_parameter, "family polynomial",
    ),
    # Refused by the divisibility condition rather than by a mismatch of
    # numbers: a BN parameter does not generate a BLS12 curve at all, and
    # the exactness check is where that shows.
    "wrong-family-name": ("bn254", wrong_family_name, "generates no BLS12 curve"),
    "unknown-family": ("bn254", unknown_family, "unknown family"),
    "wrong-twist-class": ("bls12-381", wrong_twist_class, "twist class"),
    "twist-class-disagrees-with-evidence": (
        "bls12-381", twist_class_disagrees_with_evidence,
        "the evidence proves",
    ),
    "twist-class-at-the-wrong-degree": (
        "bls24-509", twist_class_at_the_wrong_degree,
        "the stated v is not the one",
    ),
    "wrong-twist-v": ("bls12-381", wrong_twist_v, "stated v"),
    "overstated-two-adicity": (
        "bls12-381", overstated_two_adicity, "two-adicity",
    ),
    "wrong-cm-trace": ("bls12-381", wrong_cm_trace, "trace"),
    "unsupported-twist-factor": (
        "secp256k1", unsupported_twist_factor, "largest prime factor",
    ),
    # Written once. These three keys appeared twice in this table; a dict
    # literal takes the last spelling and says nothing, so the duplicates
    # cost nothing and told a reader the list was longer than it is.
    "wrong-model-parameter": (
        "curve25519", wrong_model_parameter, "do not give the subject",
    ),
    "unknown-model": ("curve25519", unknown_model, "unknown curve model"),
    "singular-montgomery": ("curve25519", singular_montgomery, "singular"),
    "order-unique-composite-n": (
        "curve25519", order_unique_composite_n,
        "is not the subgroup order proved prime",
    ),
    "elimination-without-points": (
        "bn254", elimination_without_points, "no points are offered",
    ),
    "elimination-useless-point": (
        "bn254", elimination_useless_point, "eliminates nothing",
    ),
    "elimination-point-off-curve": (
        "bn254", elimination_point_off_curve, "not on the curve",
    ),
    "elimination-wrong-survivor": (
        "bn254", elimination_wrong_survivor, "not the order asserted",
    ),
    "chain-step-with-an-unread-field": (
        "secp256k1", a_chain_step_with_an_extra_field, "unknown field `comment`",
    ),
    "factor-entry-with-an-unread-field": (
        "bls12-381", a_factor_entry_with_an_extra_field, "unknown field `note`",
    ),
    "witness-point-with-an-unread-field": (
        "bls12-381", a_witness_point_with_an_extra_field, "unknown field `z`",
    ),
    "claim-with-an-unread-field": (
        "bls12-381", a_claim_with_a_field_nobody_reads, "unknown field `tier`",
    ),
    "asserts-with-an-unread-field": (
        "bls24-509", an_asserts_object_with_a_field_nobody_reads,
        "unknown field `security_level`",
    ),
    "subject-with-an-unread-field": (
        "secp256k1", a_subject_with_an_extra_field, "unknown field `audited_by`",
    ),
    "evidence-with-an-unread-field": (
        "secp256k1", an_evidence_payload_with_an_extra_field,
        "unknown field `shortcut`",
    ),
    "elimination-on-the-base-curve": (
        "bls12-381", elimination_on_the_base_curve,
        "own order over the extension",
    ),
    "degree-four-without-xi": (
        "bls24-315", degree_four_without_xi, "xi",
    ),
    "square-xi": ("bls24-315", square_xi, "square"),
    "unfactored-cofactor-with-a-claim": (
        "bls24-315", unfactored_cofactor_with_a_claim, "no factorisation",
    ),
    "whitespace": ("secp256k1", whitespace, "offset"),
    "reordered-keys": ("secp256k1", reordered_keys, "out of order"),
    "trailing-bytes": ("secp256k1", trailing_bytes, "trailing"),
}


def _readme(out: Path) -> None:
    """Write the catalogue, from the mutations themselves.

    Generated rather than maintained: a hand-written list of what the
    vectors cover is a list that stops being true.
    """
    lines = [
        "# Certificates a verifier must refuse",
        "",
        "Generated by `tools/make_invalid_vectors.py`. Do not edit by hand.",
        "",
        "The valid vectors say what a certificate looks like. These say what",
        "the format rules out, and that is the half an implementation",
        "actually needs: accepting a good file is easy, and a verifier earns",
        "its keep on what it turns away.",
        "",
        "Each vector has two companions:",
        "",
        "- `<name>.expect` — a substring the refusal must contain. **A",
        "  refusal for the wrong reason counts as a failure.** One defect",
        "  masking another is how a hole survives a test suite, and three of",
        "  the mutations below did exactly that when first written.",
        "- `<name>.why` — what the defect is and why it matters.",
        "",
        "To check a verifier against them:",
        "",
        "```",
        "python -m tools.make_invalid_vectors --check",
        "```",
        "",
        "| Vector | Built from | Refusal must mention |",
        "| --- | --- | --- |",
    ]
    for name, (curve, mutate, expected) in sorted(MUTATIONS.items()):
        lines.append(f"| `{name}` | {curve} | {expected} |")
    lines.append("")
    for name, (curve, mutate, expected) in sorted(MUTATIONS.items()):
        doc = [line.strip() for line in (mutate.__doc__ or "").strip().splitlines()]
        lines += ["", f"### `{name}`", "", doc[0]]
        body = " ".join(line for line in doc[1:]).strip()
        if body:
            lines += ["", body]
    lines.append("")
    (out / "README.md").write_text("\n".join(lines), encoding="utf-8")


def build_all(out: Path = INVALID) -> list[Path]:
    """Write every vector and its expectation. Returns the paths written."""
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, (curve, mutate, expected) in sorted(MUTATIONS.items()):
        source = VALID / f"{curve}.ccert"
        if not source.is_file():
            raise SystemExit(f"missing source vector: {source}")
        raw = source.read_bytes()

        if mutate.__module__ == __name__ and mutate.__code__.co_varnames[0] == "raw":
            produced = mutate(raw)
        else:
            document = json.loads(raw)
            mutate(document)
            produced = _encode(document)

        path = out / f"{name}.ccert"
        path.write_bytes(produced)
        (out / f"{name}.expect").write_text(expected + "\n", encoding="utf-8")
        (out / f"{name}.why").write_text(
            (mutate.__doc__ or "").strip() + "\n", encoding="utf-8"
        )
        written.append(path)
    _readme(out)
    return written


def check(binary: Path, out: Path = INVALID) -> int:
    """Run the verifier over every vector. Refusal for the wrong reason fails."""
    failures = 0
    for name in sorted(MUTATIONS):
        path = out / f"{name}.ccert"
        expected = (out / f"{name}.expect").read_text(encoding="utf-8").strip()
        result = subprocess.run(
            [str(binary), str(path)], capture_output=True, text=True
        )
        output = result.stdout + result.stderr
        if result.returncode == 0:
            print(f"ACCEPTED  {name}  <- must have been refused")
            failures += 1
        elif expected.lower() not in output.lower():
            print(f"WRONG     {name}  <- refused, but not for `{expected}`")
            print(f"          {output.strip().splitlines()[-1][:100]}")
            failures += 1
        else:
            print(f"ok        {name}")
    print()
    print(f"{len(MUTATIONS) - failures} refused correctly, {failures} wrong")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(INVALID))
    parser.add_argument(
        "--check", action="store_true", help="run the verifier over them"
    )
    parser.add_argument("--verifier", help="path to ccert-verify")
    args = parser.parse_args(argv)

    out = Path(args.out)
    written = build_all(out)
    print(f"wrote {len(written)} vector(s) to {out}")

    if not args.check:
        return 0

    if args.verifier:
        binary = Path(args.verifier)
    else:
        for candidate in (
            ROOT / "verifier" / "target" / "release" / "ccert-verify.exe",
            ROOT / "verifier" / "target" / "release" / "ccert-verify",
        ):
            if candidate.is_file():
                binary = candidate
                break
        else:
            print("no verifier found; build it first", file=sys.stderr)
            return 2
    return check(binary, out)


if __name__ == "__main__":
    raise SystemExit(main())
