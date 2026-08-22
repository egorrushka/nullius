"""Tests for the assembled release.

Run it directly, after tools\\dist.bat:

    python tests\\test_release.py

A release is the one artefact nobody checks by running the suite: it is
assembled last, by a different script, out of files that were correct
somewhere else. The failures it can have are its own — a stale page, a
certificate copied but not listed, a digest table that describes the
previous build.

So the checks below open the release the way a stranger would. They read
DIGESTS.txt and hash the files beside it, they run the shipped verifier
on the shipped certificates, and they look for each curve's name in the
page. None of them trust anything the producer said.
"""

import hashlib
import inspect
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.build_curve import ALL_CURVES

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / "release" / "ccert-viewer"
ARCHIVE = ROOT / "release" / "ccert-viewer.zip"

SKIPPED = []


def _ready(name):
    if not RELEASE.is_dir():
        SKIPPED.append(name)
        return False
    return True


def _verifier():
    for name in ("ccert-verify.exe", "ccert-verify"):
        candidate = RELEASE / name
        if candidate.is_file():
            return candidate
    return None


# -- the folder is complete -------------------------------------------


def test_the_expected_files_are_present():
    if not _ready("test_the_expected_files_are_present"):
        return
    for name in ("curve-certificates.html", "README.txt", "DIGESTS.txt", "check-all.bat"):
        assert (RELEASE / name).is_file(), name
    assert _verifier() is not None, "no verifier in the release"
    assert (RELEASE / "certificates").is_dir()


def test_every_known_curve_ships():
    """A curve built, verified and then left out of the release would go
    unnoticed: everything upstream passes."""
    if not _ready("test_every_known_curve_ships"):
        return
    shipped = {path.stem for path in (RELEASE / "certificates").glob("*.ccert")}
    missing = sorted(set(ALL_CURVES) - shipped)
    assert not missing, f"not in the release: {', '.join(missing)}"


def test_nothing_extra_ships():
    if not _ready("test_nothing_extra_ships"):
        return
    shipped = {path.stem for path in (RELEASE / "certificates").glob("*.ccert")}
    assert not shipped - set(ALL_CURVES)


def test_the_archive_exists_and_is_not_empty():
    if not _ready("test_the_archive_exists_and_is_not_empty"):
        return
    assert ARCHIVE.is_file()
    assert ARCHIVE.stat().st_size > 100_000


# -- the digest table describes this build ----------------------------


def test_digests_match_the_files_beside_them():
    """The page shows a digest per certificate, and it has to be the
    digest of the file sitting next to it. A stale table would make the
    release look tampered with to anyone who checked."""
    if not _ready("test_digests_match_the_files_beside_them"):
        return
    lines = (RELEASE / "DIGESTS.txt").read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 2, "the digest table has no entries"
    counted = 0
    for line in lines[1:]:
        digest, name = line.split()
        raw = (RELEASE / "certificates" / name).read_bytes().rstrip(b"\n")
        actual = "sha256:" + hashlib.sha256(raw).hexdigest()
        assert actual == digest, f"{name}: the table does not describe this file"
        counted += 1
    assert counted == len(list((RELEASE / "certificates").glob("*.ccert")))


def test_the_certificates_are_copied_verbatim():
    """Not re-encoded on the way in: the corpus file and the shipped file
    must be the same bytes, or the digest means nothing."""
    if not _ready("test_the_certificates_are_copied_verbatim"):
        return
    source = ROOT / "spec" / "vectors" / "valid"
    if not source.is_dir():
        return
    for path in (RELEASE / "certificates").glob("*.ccert"):
        original = source / path.name
        if original.is_file():
            assert path.read_bytes() == original.read_bytes(), path.name


# -- the shipped verifier works on the shipped files ------------------


def test_the_shipped_verifier_accepts_every_shipped_certificate():
    """The whole promise of the release, exercised end to end."""
    if not _ready("test_the_shipped_verifier_accepts_every_shipped_certificate"):
        return
    binary = _verifier()
    for path in sorted((RELEASE / "certificates").glob("*.ccert")):
        result = subprocess.run(
            [str(binary), str(path)], capture_output=True, text=True
        )
        assert result.returncode == 0, f"{path.name}: {result.stdout}{result.stderr}"
        assert "not proved" in result.stdout


def test_the_shipped_verifier_refuses_a_tampered_certificate():
    """A verifier that accepts anything would pass every test above."""
    if not _ready("test_the_shipped_verifier_refuses_a_tampered_certificate"):
        return
    import tempfile

    binary = _verifier()
    source = next((RELEASE / "certificates").glob("*.ccert"))
    text = source.read_text(encoding="utf-8")
    # Move a single digit inside the subject. The pool digests are
    # unaffected, so this reaches a claim handler rather than the envelope
    # check, which is the part worth exercising.
    broken = text.replace('"prime":"proved"', '"prime":"asserted"', 1)
    assert broken != text, "the tamper did not apply; the format changed"

    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".ccert", delete=False, encoding="utf-8", newline="\n"
    )
    handle.write(broken)
    handle.close()
    result = subprocess.run(
        [str(binary), handle.name], capture_output=True, text=True
    )
    assert result.returncode != 0


# -- the page --------------------------------------------------------


# -- the page and the binary must be the same program ------------------


def test_the_stamp_changes_when_the_verifier_does():
    """A stamp that did not move when the sources did would be scenery."""
    from tools import wasm_stamp

    before = wasm_stamp.stamp()
    scratch = ROOT / "verifier" / "src" / "_stamp_probe.rs"
    scratch.write_text("// temporary\n", encoding="utf-8")
    try:
        assert wasm_stamp.stamp() != before, (
            "adding a source file left the stamp unchanged"
        )
    finally:
        scratch.unlink()
    assert wasm_stamp.stamp() == before


def test_a_stale_browser_verifier_is_a_refusal():
    """The failure this check exists for, reproduced.

    A release shipped a page whose browser module predated the
    certificates beside it. Two valid BLS24 certificates were refused in
    the page and accepted by the binary built minutes earlier, because the
    old module enumerated twist classes at degree 2 unconditionally. A
    reader would have concluded the certificates were broken.

    `stale` and `unstamped` are refusals; `placeholder` is not, because a
    page carrying the placeholder says so in its own banner and checks
    nothing rather than checking wrongly."""
    from tools import wasm_stamp

    scratch = tempfile.TemporaryDirectory()
    generated = Path(scratch.name) / "verifier.generated.js"

    generated.write_text("// verifier-stamp: deadbeef\n", encoding="utf-8")
    assert wasm_stamp.status(generated=generated)[0] == "stale"

    generated.write_text("export const x = 1;\n", encoding="utf-8")
    assert wasm_stamp.status(generated=generated)[0] == "unstamped"

    generated.write_text("// verifier-stamp: placeholder\n", encoding="utf-8")
    assert wasm_stamp.status(generated=generated)[0] == "placeholder"

    generated.write_text(
        f"// verifier-stamp: {wasm_stamp.stamp()}\n", encoding="utf-8"
    )
    assert wasm_stamp.status(generated=generated)[0] == "fresh"


def test_the_placeholder_says_it_is_one():
    """The placeholder has to carry the mark, or a page built without a
    verifier reads as unstamped and blocks a release that is fine."""
    placeholder = ROOT / "web" / "src" / "verifier.placeholder.js"
    assert placeholder.is_file()
    assert placeholder.read_text(encoding="utf-8").startswith(
        "// verifier-stamp: placeholder"
    )


def test_the_probe_restores_what_it_corrupts():
    """The probe edits a real file in the tree, so it must put it back.

    It exists because the refusing direction of this check was, for a
    while, a line of shell in a checklist — and a check that needs a
    hand-typed regular expression to run is one that gets run wrong or not
    at all. Giving it a command of its own only helps if the command is
    safe to run, so the restore is verified byte for byte and this test
    watches it happen."""
    from tools import wasm_stamp

    generated = wasm_stamp.GENERATED
    existed = generated.is_file()
    before = generated.read_bytes() if existed else None
    if not existed:
        generated.write_bytes(
            (ROOT / "web" / "src" / "verifier.placeholder.js").read_bytes()
        )
    try:
        assert wasm_stamp._probe() == 0
        assert generated.read_bytes() == (
            before
            if existed
            else (ROOT / "web" / "src" / "verifier.placeholder.js").read_bytes()
        )
    finally:
        if existed:
            generated.write_bytes(before)
        else:
            generated.unlink()


def test_the_page_branch_cannot_be_reached_by_rebuilding():
    """Why the probe owns this check instead of a line in a checklist.

    The obvious manual test is: rebuild the wasm, then assemble a release
    without rebuilding the page. It does not work. An unchanged source
    tree compiles to an identical wasm, the payload in the page still
    matches, and the page is genuinely fresh — nothing is wrong, the test
    was. Finding that out cost a round of testing on someone else's
    machine.

    Reaching the branch needs the payload to actually differ, which the
    probe arranges in a copy and undoes. This test states the fact so the
    next person does not propose the rebuild again."""
    from tools import wasm_stamp

    source = (ROOT / "tools" / "wasm_stamp.py").read_text(encoding="utf-8")
    assert "page stale" in source, "the probe must exercise the page branch"

    # Identical bytes in and out: the same module gives the same verdict,
    # which is exactly why rebuilding proves nothing.
    generated = ROOT / "web" / "src" / "verifier.placeholder.js"
    assert wasm_stamp._payload_of(generated) is None


def test_a_page_built_around_an_older_module_is_a_refusal():
    """The hole the first version of this check left open.

    `stamp()` compares the module in `web/src` against the verifier's
    sources. A release is assembled from `web/dist`, built from that
    module by a step nobody is obliged to re-run. So: edit the verifier,
    rebuild the wasm, assemble without rebuilding the page — fresh stamp,
    stale page, and the original failure wearing the check meant to catch
    it.

    The comparison is on the base64 payload rather than the stamp line,
    because the page is minified and a comment does not survive that. The
    payload is the wasm; it cannot be dropped without dropping the
    verifier with it."""
    from tools import wasm_stamp

    scratch = tempfile.TemporaryDirectory()
    generated = Path(scratch.name) / "verifier.generated.js"
    page = Path(scratch.name) / "index.html"
    generated.write_text(
        '// verifier-stamp: abc\nconst ENCODED = "AGFzbQABPAYLOAD";\n',
        encoding="utf-8",
    )

    page.write_text('<html>const E="AGFzbQABPAYLOAD";</html>', encoding="utf-8")
    assert wasm_stamp.page_status(page, generated)[0] == "fresh"

    # Twice, because a real built page is not the one-occurrence fixture
    # this test started as. The probe's mutation once altered only the
    # opening characters of one occurrence, which passed here and failed
    # against the real page: the payload survived and the probe reported
    # `fresh` where it should have said `stale`. The fixture was the thing
    # that was wrong, so it now looks more like what it stands for.
    page.write_text(
        '<html>a="AGFzbQABPAYLOAD"; b="AGFzbQABPAYLOAD";</html>', encoding="utf-8"
    )
    assert wasm_stamp.page_status(page, generated)[0] == "fresh"

    page.write_text('<html>const E="AGFzbQABOLDBUILD";</html>', encoding="utf-8")
    assert wasm_stamp.page_status(page, generated)[0] == "stale"

    generated.write_text(
        "// verifier-stamp: placeholder\nexport function load() { throw 0; }\n",
        encoding="utf-8",
    )
    assert wasm_stamp.page_status(page, generated)[0] == "placeholder"


def test_the_release_refuses_to_assemble_on_a_stale_verifier():
    """The check has to be wired into the script, not merely available."""
    source = (ROOT / "tools" / "make_release.py").read_text(encoding="utf-8")
    assert "wasm_stamp.status()" in source
    assert "wasm_stamp.page_status(page)" in source, (
        "the shipped page must be checked, not only the module it was "
        "supposed to be built from"
    )
    assert "refusing to assemble" in source


# -- what the page says about what it checked --------------------------


def test_the_page_does_not_call_every_extension_quadratic():
    """BLS24 puts its second group over F_p^4.

    The wording was fixed at "over a quadratic extension" and printed a
    bit length from F_p^4 in the same line — the sentence and the number
    described different curves. The degree is in the evidence; it is read
    from there."""
    source = (ROOT / "web" / "src" / "App.jsx").read_text(encoding="utf-8")
    # The rendered string, not the file. The comment beside the fix still
    # names the old wording, and should: a reader who saw "quadratic" on
    # the page ought to be able to find out what happened to it. What must
    # not survive is the template literal that printed it.
    assert "`over a quadratic extension" not in source
    assert "evidence?.field?.degree" in source


def test_the_marks_say_stated_when_nothing_checked_them():
    """A refused document must not be surrounded by green.

    The tier marks are the document's account of itself. While the
    verifier agrees, the difference does not show; when it refuses, a wall
    of `proved` around one red line sends a reader away with the opposite
    of the truth."""
    source = (ROOT / "web" / "src" / "App.jsx").read_text(encoding="utf-8")
    assert 'entry.verdict.result !== "accepted"' in source
    assert '{stated ? "stated" : TIER_LABEL[tier]}' in source
    css = (ROOT / "web" / "src" / "index.css").read_text(encoding="utf-8")
    assert ".claim.stated" in css


def test_the_page_stands_alone():
    """No server, no internet. A page that fetches its own assets works on
    the machine that built it and nowhere else."""
    if not _ready("test_the_page_stands_alone"):
        return
    html = (RELEASE / "curve-certificates.html").read_text(encoding="utf-8")
    assert 'src="http' not in html
    assert 'src="./assets' not in html and 'src="/assets' not in html
    assert len(html) > 50_000, "the page looks like a stub"


def test_the_page_knows_every_shipped_curve():
    if not _ready("test_the_page_knows_every_shipped_curve"):
        return
    html = (RELEASE / "curve-certificates.html").read_text(encoding="utf-8")
    for path in (RELEASE / "certificates").glob("*.ccert"):
        assert path.stem in html or path.stem.upper() in html, path.stem


def test_the_readme_covers_what_is_actually_shipped():
    """A release note describing a corpus of two while shipping four is
    the kind of small dishonesty that costs trust cheaply."""
    if not _ready("test_the_readme_covers_what_is_actually_shipped"):
        return
    readme = (RELEASE / "README.txt").read_text(encoding="utf-8")
    for name in ("secp256k1", "P-256", "BLS12-381", "BN254"):
        assert name in readme, f"the README does not mention {name}"


# -- standalone runner ------------------------------------------------


def main():
    tests = [
        (name, fn)
        for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn)
    ]
    passed, failed = 0, []
    for name, fn in tests:
        # A test that needs a pytest fixture cannot run here, and every
        # test in this file must run in both places. Reported as the rule
        # it breaks rather than as the `TypeError` it would otherwise
        # raise: the danger is not this failure, it is the same mistake in
        # a file whose runner tolerates it, where the test would quietly
        # never run at all.
        required = [
            parameter
            for parameter in inspect.signature(fn).parameters.values()
            if parameter.default is inspect.Parameter.empty
            and parameter.kind not in (
                parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD,
            )
        ]
        if required:
            names = ", ".join(p.name for p in required)
            failed.append((name, f"takes {names}; use tempfile so it runs here too"))
            print(f"FAIL  {name}")
            continue
        try:
            fn()
        except Exception as exc:  # report every failure, do not stop at the first
            failed.append((name, f"{type(exc).__name__}: {exc}"))
            print(f"FAIL  {name}")
        else:
            if name in SKIPPED:
                print(f"skip  {name}  (run tools\\dist.bat first)")
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
