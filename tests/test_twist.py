"""Tests for the sextic-twist classification.

Run it directly:

    python tests\\test_twist.py

This closes the gap the format admitted from the start: a bundle proved
an order for a curve over `F_p^2`, named the claim after G2, and nothing
tied the two together. The relation is now arithmetic — the proved order
is one of the six a sextic twist of the subject can have, and a verifier
enumerates all six from the trace.

The distinction the tests keep insisting on: matching an order shows the
*number* belongs to a twist, not that the *curve* in the evidence is that
twist. Two curves can share an order. Losing that distinction would turn
an honest claim into an overstated one, which is the failure this whole
exercise is about.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.bundle.pairing import KNOWN_PAIRING_CURVES
from core.claims.twist import TwistError, classify, twist_candidates

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "spec" / "vectors" / "valid"

SKIPPED = []

BLS = KNOWN_PAIRING_CURVES["bls12-381"]
BN = KNOWN_PAIRING_CURVES["bn254"]
BLS_H1 = 76329603384216526031706109802092473003
BLS_H2 = 0x5D543A95414E7F1091D50792876A202CD91DE4547085ABAA68A205B2E5A7DDFA628F1CB4D9E82EF21537E293A6691AE1616EC6E786F0C70CF1C38E31C7238E5

BLS_N1 = BLS_H1 * BLS["r"]
BLS_N2 = BLS_H2 * BLS["r"]
BN_N1 = BN["r"]
BN_N2 = (2 * BN["p"] - BN["r"]) * BN["r"]


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


# -- the enumeration --------------------------------------------------


def test_there_are_exactly_six_candidates():
    """Six, because a sextic twist has six classes. A different count
    would mean the formulas are not the ones being cited."""
    for p, n1 in ((BLS["p"], BLS_N1), (BN["p"], BN_N1)):
        candidates, _t2, _v = twist_candidates(p, n1)
        assert len(candidates) == 6
        assert len(set(candidates)) == 6


def test_every_candidate_lies_in_the_hasse_window():
    """A candidate outside the window could not be a group order at all,
    so its presence would mean the derivation is wrong."""
    for p, n1 in ((BLS["p"], BLS_N1), (BN["p"], BN_N1)):
        candidates, _t2, _v = twist_candidates(p, n1)
        q = p * p
        for value in candidates:
            assert abs(value - (q + 1)) <= 2 * p


def test_the_real_twist_orders_are_among_them():
    assert BLS_N2 in twist_candidates(BLS["p"], BLS_N1)[0]
    assert BN_N2 in twist_candidates(BN["p"], BN_N1)[0]


def test_the_classes_are_the_expected_ones():
    """Pinned, because the index is part of the format: whoever writes a
    second implementation has to produce the same numbering."""
    assert classify(BLS["p"], BLS_N1, BLS_N2)[0] == 4
    assert classify(BN["p"], BN_N1, BN_N2)[0] == 2


def test_v_is_positive_and_exact():
    """v is determined only up to sign, and the set of six does not
    depend on the choice — but the indices do, so the sign is pinned."""
    for p, n1 in ((BLS["p"], BLS_N1), (BN["p"], BN_N1)):
        _candidates, t2, v = twist_candidates(p, n1)
        assert v > 0
        assert 4 * p * p == t2 * t2 + 3 * v * v


def test_a_foreign_order_is_not_classified():
    assert _raises(TwistError, classify, BLS["p"], BLS_N1, BLS_N2 + 1)
    assert _raises(TwistError, classify, BLS["p"], BLS_N1, BN_N2)


def test_a_curve_that_is_not_j_zero_is_refused():
    """The decomposition 4q = t2^2 + 3v^2 exists only for j = 0. On a
    curve where it does not, this must refuse rather than return
    something."""
    refused = 0
    for cardinality in range(1000, 1040):
        try:
            twist_candidates(1009, cardinality)
        except TwistError:
            refused += 1
    assert refused > 0, "nothing in the sample was refused, so nothing was tested"


def test_an_inexact_square_root_is_refused():
    """isqrt floors. Accepting a floored root would build all six
    candidates on a v that is not the right one."""
    assert _raises(TwistError, twist_candidates, 1009, 1)


# -- the search and the record are different things --------------------


def test_the_search_may_skip_a_point_the_record_may_not_keep():
    """The one place the producer and the verifier deliberately differ.

    A verifier refuses a point that eliminates nothing: the record must
    not carry padding. A producer walking abscissas in a fixed order meets
    such points before a later one closes the argument, and refusing at
    the first would abandon certificates that exist.

    The example is real and small enough to check by hand. Over F_19 the
    curve `y^2 = x^3 + 17` has 27 points, so `t = -7`, `4p - t^2 = 27`,
    `v = 3`, and the six candidate orders are pairwise distinct. Walking
    abscissas from zero: x = 0 rules out three of them, x = 2 and x = 3
    rule out nothing at all, and x = 4 closes the argument on the true
    order. A producer that stopped at x = 2 would report no certificate
    for a curve that plainly has one, and the two points it would have
    written down are the same either way."""
    from core.claims.elimination import eliminate, points_in_order
    from core.field.fp import CurveFp, Fp

    field = Fp(19)
    curve = CurveFp(field, field.element(0), field.element(17))
    candidates = [27, 13, 19, 21, 28, 12]
    assert len(set(candidates)) == 6

    index, used = eliminate(curve, candidates, points_in_order(curve, field))
    assert candidates[index] == 27, "the true order must be the survivor"
    # Two points kept out of four met. The two skipped are the reason this
    # function may not refuse on the first that decides nothing.
    assert len(used) == 2


def test_a_recorded_argument_with_padding_is_refused():
    """The producer replays what it kept, the way a verifier will.

    Skipping during the search is right; writing a useless point down is
    not, and the two are only a line apart. The replay is what keeps a
    producer from emitting a document its own verifier rejects."""
    from core.claims.elimination import EliminationError, _replay
    from core.claims.point_order import make_curve, make_field

    document = json.loads((VECTORS / "bls12-381.ccert").read_text(encoding="utf-8"))
    claim = next(c for c in document["claims"] if c["claim"] == "curve.cardinality")
    p = int(document["subject"]["field"]["p"])
    cardinality = int(claim["asserts"]["n"])
    candidates, _t, _v = twist_candidates(p, cardinality, 2)

    field = make_field(p, 2, -1)
    curve = make_curve(field, (0, 0), (4, 4))
    point = next(iter(_first_points(curve, field, 1)))

    # The honest record: one point, and it settles the argument.
    _replay(curve, candidates, [point], candidates.index(
        int(next(c for c in document["claims"]
                 if c["claim"] == "g2.cardinality")["asserts"]["n"])
    ))
    # The same point twice. The second eliminates nothing, because the
    # first already did — which is exactly the padding a verifier refuses.
    assert _raises(
        EliminationError, _replay, curve, candidates, [point, point], 4
    )


def _first_points(curve, field, count):
    from core.claims.elimination import points_in_order

    out = []
    for point in points_in_order(curve, field):
        out.append(point)
        if len(out) == count:
            break
    return out


# -- the claim in a bundle --------------------------------------------


def test_every_pairing_curve_carries_a_twist_claim():
    """All four now, not the two over a quadratic extension.

    BLS24-315 and BLS24-509 went without because the six classes over
    F_p^4 are a different set from the six over F_p^2 and an unlabelled
    index would have meant one thing for BLS12 and another for BLS24. The
    label is the fix, so the degree is asserted here too — a class without
    the set it indexes is a number without a meaning."""
    curves = ("bls12-381", "bn254", "bls24-315", "bls24-509")
    if not _ready("test_every_pairing_curve_carries_a_twist_claim", *curves):
        return
    for curve in curves:
        document = json.loads(
            (VECTORS / f"{curve}.ccert").read_text(encoding="utf-8")
        )
        claim = next(c for c in document["claims"] if c["claim"] == "g2.twist")
        assert claim["asserts"]["related"] == "sextic-twist"
        assert claim["asserts"]["degree"] in ("2", "4"), curve
        assert claim["evidence"]["type"] == "derive.twist-class"


def test_the_note_names_the_set_the_index_indexes():
    """A class index is meaningless until the six are named.

    The note used to end by saying the curve in the evidence was not
    thereby shown to be the twist. That was the honest thing to say while
    nothing checked it, and it stopped being true when
    `derive.order-elimination` began checking `a' = 0` and taking the
    census on `r`. The handler now refuses to classify an order that rests
    on anything else, so the note states the relation instead of
    disclaiming it — and states which degree's six it counted."""
    if not _ready("test_the_note_names_the_set_the_index_indexes",
                  "bn254", "bls24-509"):
        return
    _, output = _run(VECTORS / "bn254.ccert")
    assert "six over F_p^2" in output
    assert "is that twist" in output
    _, output = _run(VECTORS / "bls24-509.ccert")
    assert "six over F_p^4" in output


def test_the_cardinality_note_states_the_binding_it_now_has():
    """The note has moved twice, and each move followed the evidence.

    It first said the relation was not established by the bundle, which
    stopped being true once `g2.twist` existed. It then said the curve in
    the evidence was not shown to be the twist, which stopped being true
    once `derive.order-elimination` began checking `a' = 0` and running
    the census on `r`: with the subject at `a = 0` and `q = 1 mod 3`,
    every non-singular `y^2 = x^3 + b'` over the extension is one of the
    six, and the census says which. The note says exactly that and no
    more."""
    if not _ready("test_the_cardinality_note_states_the_binding_it_now_has", "bls12-381"):
        return
    _, output = _run(VECTORS / "bls12-381.ccert")
    assert "sextic twist of the subject" in output
    assert "not the subject's own curve over the extension" in output


def test_a_wrong_class_index_is_refused():
    if not _ready("test_a_wrong_class_index_is_refused", "bn254"):
        return
    import hashlib

    document = json.loads((VECTORS / "bn254.ccert").read_text(encoding="utf-8"))
    claim = next(c for c in document["claims"] if c["claim"] == "g2.twist")
    payload = document["evidence"].pop(claim["evidence"]["ref"])
    payload["index"] = "3"
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    document["evidence"][digest] = payload
    claim["evidence"]["ref"] = digest
    claim["asserts"]["class"] = "3"

    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".ccert", delete=False, encoding="utf-8", newline="\n"
    )
    handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    handle.close()
    code, output = _run(Path(handle.name))
    assert code != 0
    assert "twist class" in output


# -- the policies notice its absence ----------------------------------


def test_a_missing_twist_claim_blocks_a_pass():
    """Silence is not consent. A bundle with no twist relation must be
    undecided under the pairing policies, not passing."""
    from core.bundle.model import Bundle
    from core.policy.engine import evaluate, load_policy

    if not _ready("test_a_missing_twist_claim_blocks_a_pass", "bls12-381"):
        return
    document = json.loads(
        (VECTORS / "bls12-381.ccert").read_text(encoding="utf-8")
    )
    claim = next(c for c in document["claims"] if c["claim"] == "g2.twist")
    document["evidence"].pop(claim["evidence"]["ref"])
    document["claims"] = [
        c for c in document["claims"] if c["claim"] != "g2.twist"
    ]
    bundle = Bundle.from_obj(document)

    verdict = evaluate(bundle, load_policy("pairing-suitability"))
    assert verdict.count("undecided") >= 1
    assert verdict.result != "passes"


def test_the_intact_bundle_still_passes():
    from core.bundle.model import Bundle
    from core.policy.engine import evaluate, load_policy

    if not _ready("test_the_intact_bundle_still_passes", "bls12-381"):
        return
    document = json.loads(
        (VECTORS / "bls12-381.ccert").read_text(encoding="utf-8")
    )
    verdict = evaluate(Bundle.from_obj(document), load_policy("pairing-suitability"))
    assert verdict.result == "passes"


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
