"""Tests that the JavaScript policy engine agrees with the Python one.

Run it directly:

    python tests\\test_policy_mirror.py

The browser viewer cannot import Python, so the tier table is written out
a second time in JavaScript. Two copies of the same table is a standing
invitation to drift, and drift here is quiet: an evidence kind added on
one side and forgotten on the other does not crash anything. The viewer
simply reports the claim as undecided, and a curve that is fully proved
looks unresolvable to anyone reading the web page.

That already happened once. The point-order and cofactor kinds went into
the Python model and the Rust verifier, and the JavaScript table kept the
older list. This file exists so it cannot happen silently again.

The same reasoning applies to any other constant duplicated across
languages. If one shows up later, it belongs here too.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.bundle.model import EVIDENCE_TIERS, TIER_MEANING

ROOT = Path(__file__).resolve().parent.parent
POLICY_JS = ROOT / "web" / "src" / "policy.js"

SKIPPED = []

ENTRY = re.compile(r'"([A-Za-z0-9._-]+)"\s*:\s*"([ADX])"')


def _table(name):
    """One object literal from policy.js, as a dict.

    Read with a regular expression rather than a JavaScript parser: the
    file is ours, the shape is fixed, and a dependency for this would cost
    more than it saves. A malformed table produces an empty dict, which
    the tests below treat as a failure rather than a pass.
    """
    if not POLICY_JS.is_file():
        return None
    text = POLICY_JS.read_text(encoding="utf-8")
    match = re.search(
        rf"export const {name}\s*=\s*{{(.*?)}};", text, re.DOTALL
    )
    if match is None:
        return {}
    return dict(ENTRY.findall(match.group(1)))


def _ready(name):
    if not POLICY_JS.is_file():
        SKIPPED.append(name)
        return False
    return True


# -- the tier table ---------------------------------------------------


def test_the_javascript_table_was_found():
    """A failure here means the regular expression stopped matching, and
    every other test in this file would pass vacuously."""
    if not _ready("test_the_javascript_table_was_found"):
        return
    table = _table("TIER_OF_EVIDENCE")
    assert table, "TIER_OF_EVIDENCE could not be read from policy.js"
    assert len(table) >= 8


def test_every_python_evidence_kind_is_in_javascript():
    """The direction that bites: a kind added to the producer and
    forgotten in the viewer."""
    if not _ready("test_every_python_evidence_kind_is_in_javascript"):
        return
    table = _table("TIER_OF_EVIDENCE")
    missing = sorted(set(EVIDENCE_TIERS) - set(table))
    assert not missing, f"absent from policy.js: {', '.join(missing)}"


def test_javascript_invents_nothing():
    """The other direction: a kind the viewer would accept and the
    producer has never heard of."""
    if not _ready("test_javascript_invents_nothing"):
        return
    table = _table("TIER_OF_EVIDENCE")
    extra = sorted(set(table) - set(EVIDENCE_TIERS))
    assert not extra, f"unknown to the Python model: {', '.join(extra)}"


def test_the_tiers_themselves_agree():
    """Same kinds is not enough; the same kind must carry the same tier."""
    if not _ready("test_the_tiers_themselves_agree"):
        return
    table = _table("TIER_OF_EVIDENCE")
    disagreements = [
        f"{kind}: python {tier}, javascript {table[kind]}"
        for kind, tier in sorted(EVIDENCE_TIERS.items())
        if kind in table and table[kind] != tier
    ]
    assert not disagreements, "; ".join(disagreements)


def test_the_new_pairing_kinds_are_present():
    """Named explicitly, because these are the ones that drifted."""
    if not _ready("test_the_new_pairing_kinds_are_present"):
        return
    table = _table("TIER_OF_EVIDENCE")
    assert table.get("proof.point-order") == "A"
    assert table.get("check.cofactor") == "A"


# -- the tier labels --------------------------------------------------


def test_the_tier_letters_match():
    if not _ready("test_the_tier_letters_match"):
        return
    text = POLICY_JS.read_text(encoding="utf-8")
    match = re.search(r"export const TIER_LABEL\s*=\s*{(.*?)};", text, re.DOTALL)
    assert match, "TIER_LABEL could not be read from policy.js"
    letters = set(re.findall(r"\b([ADX])\s*:", match.group(1)))
    assert letters == set(TIER_MEANING), (
        f"python has {sorted(TIER_MEANING)}, javascript has {sorted(letters)}"
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
                print(f"skip  {name}  (web/src/policy.js not found)")
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
