"""Tests that the specification and the code describe the same format.

Run it directly:

    python tests\\test_spec.py

A specification is a promise that a second implementation can be written
from it alone. That promise breaks quietly: an evidence kind is added to
the model, the verifier learns it, the corpus uses it, and the document
still describes the format as it was six months ago. Nothing fails, and
the spec slowly becomes fiction.

So the tables in the document are read back and compared against the ones
the code actually uses. This is the same reasoning as the policy mirror
test, applied to prose instead of JavaScript.

What this cannot check is whether the prose is *correct* — only that it is
complete and consistent with the code. A wrong description of a right
table passes here.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.bundle.model import CLAIM_TYPES, EVIDENCE_TIERS, TIER_MEANING

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "spec" / "ccert-v0.md"

SKIPPED = []

# A table cell holding `an.identifier` in backticks.
CODE_SPAN = re.compile(r"`([a-z][A-Za-z0-9._-]*)`")


def _ready(name):
    if not SPEC.is_file():
        SKIPPED.append(name)
        return False
    return True


def _rows(heading_pattern):
    """Rows of the first markdown table after a matching heading."""
    text = SPEC.read_text(encoding="utf-8")
    start = re.search(heading_pattern, text)
    if start is None:
        return []
    rows = []
    for line in text[start.end():].splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            if rows:
                break
            continue
        if set(stripped) <= set("|-: "):
            continue
        rows.append([cell.strip() for cell in stripped.strip("|").split("|")])
    return rows


def _evidence_table():
    """Evidence type -> tier, as the document states it."""
    table = {}
    for row in _rows(r"\| Evidence type"):
        names = CODE_SPAN.findall(row[0])
        if names and row[1] in TIER_MEANING:
            table[names[0]] = row[1]
    return table


def _claim_table():
    names = set()
    for row in _rows(r"\| Claim\b"):
        found = CODE_SPAN.findall(row[0])
        if found:
            names.add(found[0])
    return names


# -- the tables were found --------------------------------------------


def test_the_evidence_table_parses():
    """A failure here makes every other check in this file vacuous."""
    if not _ready("test_the_evidence_table_parses"):
        return
    table = _evidence_table()
    assert table, "the evidence table could not be read from the spec"
    assert len(table) >= 8


def test_the_claim_table_parses():
    if not _ready("test_the_claim_table_parses"):
        return
    assert len(_claim_table()) >= 8


# -- evidence types ---------------------------------------------------


def test_every_evidence_kind_is_documented():
    """The direction that bites: a kind shipped and never written up."""
    if not _ready("test_every_evidence_kind_is_documented"):
        return
    missing = sorted(set(EVIDENCE_TIERS) - set(_evidence_table()))
    assert not missing, f"undocumented: {', '.join(missing)}"


def test_the_spec_documents_nothing_imaginary():
    if not _ready("test_the_spec_documents_nothing_imaginary"):
        return
    extra = sorted(set(_evidence_table()) - set(EVIDENCE_TIERS))
    assert not extra, f"documented but unimplemented: {', '.join(extra)}"


def test_the_documented_tiers_are_the_real_ones():
    """Listing a kind is not enough; the tier must match, because the tier
    is the whole of what the table decides."""
    if not _ready("test_the_documented_tiers_are_the_real_ones"):
        return
    table = _evidence_table()
    wrong = [
        f"{kind}: code {tier}, spec {table[kind]}"
        for kind, tier in sorted(EVIDENCE_TIERS.items())
        if kind in table and table[kind] != tier
    ]
    assert not wrong, "; ".join(wrong)


# -- claim types ------------------------------------------------------


def test_every_claim_type_is_documented():
    if not _ready("test_every_claim_type_is_documented"):
        return
    missing = sorted(CLAIM_TYPES - _claim_table())
    assert not missing, f"undocumented: {', '.join(missing)}"


def test_no_claim_type_is_invented():
    if not _ready("test_no_claim_type_is_invented"):
        return
    extra = sorted(_claim_table() - CLAIM_TYPES)
    assert not extra, f"documented but unimplemented: {', '.join(extra)}"


# -- the parts a reader depends on ------------------------------------


def test_the_extension_field_rules_are_stated():
    """Someone writing a second verifier needs these three, or their
    implementation will disagree with ours on real certificates."""
    if not _ready("test_the_extension_field_rules_are_stated"):
        return
    text = SPEC.read_text(encoding="utf-8")
    assert "field.degree" in text
    assert "quadratic residue" in text
    assert "coefficient lists" in text or "coefficient list" in text


def test_the_twist_limits_are_recorded_as_lifted():
    """A limit that moved has to say so, not simply stop being mentioned.

    This test has been rewritten twice, and both times because the spec
    was overstating a limit rather than understating one. First the curve
    in the G2 evidence was not shown to be the twist; then the class label
    was missing at degree 4. Neither holds now. What the section must not
    do is quietly drop the entry: a reader who learned either limit should
    find out that it lifted, and the difference between "no longer true"
    and "no longer mentioned" is the difference between a document a
    reader can trust and one they have to re-derive."""
    if not _ready("test_the_twist_limits_are_recorded_as_lifted"):
        return
    text = SPEC.read_text(encoding="utf-8")
    assert "sextic twist" in text
    section = text[text.index("## What is deliberately absent"):]
    assert "twist" in section.lower(), "the entry must not simply vanish"
    assert "no longer among the absences" in section, (
        "the section must record that the limit lifted, not just omit it"
    )
    for stale in ("not thereby shown to be that twist",
                  "absent from a degree-4 bundle"):
        assert stale not in section.lower(), (
            f"the section still states a limit that no longer holds: {stale}"
        )


def test_the_closed_key_rule_is_documented_and_real():
    """A rule the verifier enforces has to be findable in the spec.

    Both halves matter and neither substitutes for the other. The
    document must state that every level carries a closed set of keys,
    because a producer reading only the spec would otherwise write a
    field that verifies today and is refused tomorrow. And the verifier
    must actually refuse one, because a rule stated and unenforced is
    worse than a rule absent — a reader would rely on it.
    """
    if not _ready("test_the_closed_key_rule_is_documented_and_real"):
        return
    text = SPEC.read_text(encoding="utf-8")
    assert "closed set of keys" in text
    assert "no `--canonical-check`" in text, (
        "the decision not to re-encode has to be recorded as a decision"
    )
    source = (ROOT / "verifier" / "src" / "json.rs").read_text(encoding="utf-8")
    assert "pub fn closed_keys" in source


def test_the_prefix_is_not_read_as_a_tier():
    """Three kinds begin `derive.` and they are not all the same tier.

    `derive.twist-sum` is D; `derive.twist-class` and
    `derive.order-elimination` are A. A reader who took the prefix for a
    tier would be wrong about two of the three, so the document says
    outright that it is not one — and says why the names are left alone,
    because renaming an evidence type moves the bytes of every certificate
    carrying it and tidier names do not justify moving published
    digests."""
    if not _ready("test_the_prefix_is_not_read_as_a_tier"):
        return
    text = SPEC.read_text(encoding="utf-8")
    assert "prefix does not encode the tier" in text
    derived = {name: tier for name, tier in _evidence_table().items()
               if name.startswith("derive.")}
    assert len(set(derived.values())) > 1, (
        "the prefixes agree on a tier now; the paragraph explaining that "
        "they do not should go with them"
    )


def test_the_record_may_not_carry_a_useless_point():
    """The producer skips one and the verifier refuses one, and the
    document has to say which side is normative.

    Without that, two correct implementations look like a divergence and
    a reader cannot tell which to believe."""
    if not _ready("test_the_record_may_not_carry_a_useless_point"):
        return
    text = SPEC.read_text(encoding="utf-8")
    assert "Every point in the evidence must eliminate at least one" in text
    assert "a rule about the record, not about the search" in text


def test_the_corpus_uses_only_documented_kinds():
    """The strongest check available: read the certificates themselves."""
    if not _ready("test_the_corpus_uses_only_documented_kinds"):
        return
    import json

    corpus = ROOT / "corpus"
    if not corpus.is_dir():
        return
    documented = set(_evidence_table())
    claims_documented = _claim_table()
    for path in sorted(corpus.glob("*.ccert")):
        document = json.loads(path.read_text(encoding="utf-8"))
        for claim in document["claims"]:
            assert claim["claim"] in claims_documented, f"{path.name}: {claim['claim']}"
            kind = claim["evidence"]["type"]
            assert kind in documented, f"{path.name}: {kind}"


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
                print(f"skip  {name}  (spec/ccert-v0.md not found)")
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
