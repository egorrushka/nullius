"""Ties the verifier in the page to the verifier in the tree.

The page says it re-checks a certificate rather than displaying one, and
that claim rests on the browser module being the same program as
`ccert-verify`. Nothing enforced it. `tools\\dist.bat` builds the binary
if it is missing and the corpus if it is missing, and never asks about
the wasm at all: `web_build.bat` uses whatever `verifier.generated.js`
happens to be lying there.

So a release could ship — and did — a page whose verifier predated the
certificates beside it. The symptom was loud rather than quiet: two valid
BLS24 certificates were refused in the browser and accepted by the binary
built ten minutes earlier, because the old module enumerated twist
classes at degree 2 unconditionally and the new certificates state the
degree they index into. A reader would have concluded the certificates
were broken. They were not; the page was.

A loud wrong answer is better than a quiet one and still unacceptable in
a tool whose entire claim is that you need not take its word.

## What this does

`stamp()` hashes the verifier's sources — every `.rs` under
`verifier/src` and its `Cargo.toml` — into one line. `inline_wasm.py`
writes that line into the generated module as it builds it, and
`make_release.py` refuses to assemble a release whose page carries a
different one.

Sources rather than the compiled `.wasm`, deliberately. Hashing the
artifact would only say the artifact had not been edited since; hashing
what it was built from says whether it is still the program the tree
describes, which is the question a reader is actually asking.

## What it does not do

It cannot tell whether the wasm was built from *those* sources, only
whether the sources have moved since it was stamped. A liar with a build
script can defeat it. It is not aimed at a liar: it is aimed at the
ordinary case where somebody edits the verifier, runs `dist.bat`, and has
no reason to think about a step that step never mentions.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GENERATED = ROOT / "web" / "src" / "verifier.generated.js"
PLACEHOLDER_MARK = "verifier-stamp: placeholder"
PREFIX = "// verifier-stamp: "


def stamp(root: Path = ROOT) -> str:
    """One hex line over everything the browser module is built from.

    Sorted by path so the answer does not depend on the order a directory
    happens to be walked, and the path goes into the hash beside the
    bytes so that renaming a file is a change rather than a shuffle.
    """
    digest = hashlib.sha256()
    source = root / "verifier" / "src"
    files = sorted(source.glob("*.rs")) + [root / "verifier" / "Cargo.toml"]
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def stamp_of(generated: Path = GENERATED) -> str | None:
    """The stamp a generated module carries, or None if it carries none.

    None is not the same as a mismatch and the caller must not treat it
    as one. A module built before this check existed has no stamp and is
    unknown rather than wrong; the placeholder has no verifier at all and
    is honest about it.
    """
    if not generated.is_file():
        return None
    for line in generated.read_text(encoding="utf-8").splitlines()[:20]:
        if line.startswith(PREFIX):
            return line[len(PREFIX):].strip()
    return None


def status(root: Path = ROOT, generated: Path | None = None) -> tuple[str, str]:
    """Returns a state and a sentence to print.

    States: `placeholder`, `fresh`, `stale`, `unstamped`, `missing`.
    Only `stale` and `unstamped` are refusals — the first because the
    page would judge by a program the tree no longer contains, the second
    because nobody can say what it would judge by.
    """
    generated = GENERATED if generated is None else generated
    if not generated.is_file():
        return "missing", (
            "no browser verifier; the page will carry the placeholder and say "
            "so, which is honest but means the page checks nothing"
        )
    carried = stamp_of(generated)
    if carried == "placeholder":
        return "placeholder", (
            "the page carries the placeholder, not a verifier. It refuses with "
            "a reason rather than pretending, and a reader is told. Run "
            "tools\\build_wasm.bat to give the page a real one."
        )
    if carried is None:
        return "unstamped", (
            "the browser verifier carries no stamp, so nothing can say which "
            "sources it was built from. Rebuild it: tools\\build_wasm.bat"
        )
    current = stamp(root)
    if carried != current:
        return "stale", (
            "the browser verifier was built from different sources than the "
            "ones in this tree, so the page would judge certificates by a "
            "program that is no longer here. This is exactly how a valid "
            "certificate comes to be refused in the browser and accepted on "
            "the command line. Rebuild it: tools\\build_wasm.bat"
        )
    return "fresh", "the browser verifier matches the sources in this tree"


PAGE = ROOT / "web" / "dist" / "index.html"


def _payload_of(generated: Path) -> str | None:
    """The base64 wasm the generated module carries, if it carries one.

    `inline_wasm.py` writes it as `const ENCODED = "..."`. The
    placeholder has none, and returns None.
    """
    text = generated.read_text(encoding="utf-8")
    marker = 'const ENCODED = "'
    if marker not in text:
        return None
    rest = text.split(marker, 1)[1]
    return rest.split('"', 1)[0]


def page_status(
    page: Path | None = None, generated: Path | None = None
) -> tuple[str, str]:
    """Whether the built page carries the module now in the tree.

    `status()` answers a different question and the difference is the
    whole point of this function existing. It compares the *source*
    module against the verifier's sources; the release is assembled from
    `web/dist/index.html`, which is a third artefact, built from the
    module by a step nobody is forced to re-run.

    So the sequence that defeats `status()` on its own: edit the
    verifier, rebuild the wasm, and assemble a release without rebuilding
    the page. The module is fresh, the stamp agrees, and the page still
    carries the module from before the edit — which is the original
    failure exactly, wearing the check meant to catch it.

    The comparison is on the base64 payload rather than on the stamp
    line, because the page is minified and a comment does not survive
    that. The payload is the wasm itself; it cannot be dropped without
    dropping the verifier with it.
    """
    page = PAGE if page is None else page
    generated = GENERATED if generated is None else generated
    if not page.is_file():
        return "missing", "no page built yet; run tools\\web_build.bat"
    if not generated.is_file():
        return "missing", "no browser module; run tools\\build_wasm.bat"

    payload = _payload_of(generated)
    text = page.read_text(encoding="utf-8", errors="replace")
    if payload is None:
        # The placeholder. The page should carry it too, and if it does
        # the page says so in its own banner.
        return "placeholder", (
            "the module in the tree is the placeholder, so the page checks "
            "nothing and tells its reader as much"
        )
    if payload not in text:
        return "stale", (
            "the built page does not carry the browser module now in the "
            "tree. Rebuilding the wasm does not rebuild the page: run "
            "tools\\web_build.bat, or tools\\dist.bat which does both"
        )
    return "fresh", "the built page carries the module now in the tree"


def _probe() -> int:
    """Exercise the refusal, safely, without anyone typing a regex.

    This started life as a line of shell in a checklist, and a check that
    needs a hand-typed regular expression to run is a check that gets run
    wrong or not at all. The refusing direction is the one that matters —
    a stamp that only ever says yes has never been tested — so it gets a
    command of its own.

    The generated module is restored from an in-memory copy and the
    restore is verified byte for byte before this returns. A probe that
    could leave the tree damaged would be worse than no probe.
    """
    if not GENERATED.is_file():
        print("no web/src/verifier.generated.js; run tools\\build_wasm.bat first")
        return 1

    original = GENERATED.read_bytes()
    failures = []
    try:
        for label, text in (
            ("stale", f"{PREFIX}deadbeef\n"),
            ("unstamped", "export const nothing = 1;\n"),
            ("placeholder", f"{PREFIX}placeholder\n"),
        ):
            GENERATED.write_bytes(text.encode("utf-8"))
            state, sentence = status()
            ok = state == label
            print(f"  {'ok  ' if ok else 'WRONG'} {label:12s} -> {state}: {sentence}")
            if not ok:
                failures.append(label)
    finally:
        GENERATED.write_bytes(original)

    if GENERATED.read_bytes() != original:
        print("  WRONG the probe failed to restore the module")
        return 2

    # The page branch, which cannot be exercised by rebuilding.
    #
    # The obvious manual test — rebuild the wasm, then assemble without
    # rebuilding the page — does not work, and finding that out cost a
    # round of testing. An unchanged source tree compiles to an identical
    # wasm, so the payload in the page still matches and the page is
    # genuinely fresh. Nothing is wrong; the test was.
    #
    # Reaching the branch needs the payload to actually differ, so the
    # probe alters it in a copy and puts the original back, the same way
    # it does above.
    payload = _payload_of(GENERATED)
    if PAGE.is_file() and payload is not None:
        page_original = PAGE.read_bytes()
        try:
            # The mutation removes the payload outright — every occurrence
            # — and the probe checks that it did before drawing any
            # conclusion. An earlier version altered only the opening
            # characters of one occurrence, which passed against a
            # hand-made fixture and failed against a real built page.
            needle = payload.encode("utf-8")
            altered = page_original.replace(needle, b"AAAAcorrupted")
            if altered == page_original:
                # The page does not carry this module's payload. That is
                # not a probe failure and not a corruption: it is the
                # ordinary state right after `build_wasm.bat`, which
                # rebuilds the module but not the page. The page branch
                # has nothing to exercise until `web_build.bat` runs, so
                # it is skipped with a plain reason rather than failed —
                # judging tree-readiness is the release's job, not the
                # probe's.
                print("  skip page    -> page predates this module; run "
                      "tools\\web_build.bat (not a probe failure)")
            else:
                PAGE.write_bytes(altered)
                state, sentence = page_status()
                ok = state == "stale"
                print(f"  {'ok  ' if ok else 'WRONG'} page stale   -> {state}: {sentence}")
                if not ok:
                    failures.append("page")
        finally:
            PAGE.write_bytes(page_original)
        # Restoration is a byte question, not a freshness question: the
        # probe put back exactly what it took. Whether the tree is
        # release-ready is a separate check (`page_status`, run by the
        # release), not the probe's job.
        if PAGE.read_bytes() != page_original:
            print("  WRONG the probe failed to restore the page")
            return 2
        print("  page restored (bytes match)")
    else:
        print("  skip page    -> no built page, or the module is the placeholder")
    if GENERATED.read_bytes() != original:
        print("  WRONG the probe failed to restore the module")
        failures.append("restored")
    else:
        print("  module restored (bytes match)")
    return 1 if failures else 0


if __name__ == "__main__":
    import sys

    if "--probe" in sys.argv:
        raise SystemExit(_probe())
    state, sentence = status()
    print(f"{state}: {sentence}")
    raise SystemExit(0 if state not in ("stale", "unstamped") else 1)
