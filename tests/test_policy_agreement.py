"""Cross-checks the JavaScript policy engine against the Python one.

Run it directly:

    python tests\\test_policy_agreement.py

There are two policy engines because the page runs in a browser and the
producer does not. Both read the same YAML and the same certificates, and
they are expected to reach the same verdict on every pair. When they do
not, the page tells a visitor something the project does not believe, and
it does so quietly: nothing crashes, a curve simply looks safer or worse
than it is.

The tier table is already compared by test_policy_mirror. This goes
further and compares the output: every bundle against every policy, both
engines, verdict for verdict. It is the only check that would have caught
the JavaScript engine ignoring a criterion's `times` key, which made it
compare 381 against a threshold meant for 4572.

Needs Node, and skips itself with a note when Node is absent.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.bundle.model import Bundle
from core.policy.engine import available_policies, evaluate, load_policy

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "web" / "public" / "data"
POLICY_JS = ROOT / "web" / "src" / "policy.js"

SKIPPED = []

# Reads policy.js as a module, runs it over the exported corpus, and
# prints one line per pair. Written to a temporary file rather than passed
# with -e so the import path stays relative to the repository.
DRIVER = """
import { readFileSync } from "fs";
const source = readFileSync(process.argv[2], "utf8")
  .replace(/export const/g, "const")
  .replace(/export function/g, "function");
const engine = await import(
  "data:text/javascript," + encodeURIComponent(source + "\\nexport { evaluate };")
);
const index = JSON.parse(readFileSync(process.argv[3] + "/index.json", "utf8"));
const out = [];
for (const entry of index.bundles) {
  const bundle = JSON.parse(readFileSync(process.argv[3] + "/" + entry.file, "utf8"));
  for (const policy of index.policies) {
    const verdict = engine.evaluate(bundle, policy);
    out.push({
      bundle: entry.file,
      policy: policy.name,
      result: verdict.result,
      undecided: verdict.count("undecided"),
      details: verdict.outcomes.map((o) => [o.criterion.id, o.status]),
      models: verdict.outcomes
        .filter((o) => o.model)
        .map((o) => [o.criterion.id, o.model]),
    });
  }
}
console.log(JSON.stringify(out));
"""


def _node_available():
    try:
        subprocess.run(["node", "--version"], capture_output=True, check=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def _ready(name):
    if not DATA.is_dir() or not (DATA / "index.json").is_file():
        SKIPPED.append(name)
        return False
    if not _node_available():
        SKIPPED.append(name)
        return False
    return True


_CACHE = {}


def _javascript_verdicts():
    """Every (bundle, policy) verdict, as the browser would compute it."""
    if "js" in _CACHE:
        return _CACHE["js"]
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".mjs", delete=False, encoding="utf-8"
    )
    handle.write(DRIVER)
    handle.close()
    result = subprocess.run(
        ["node", handle.name, str(POLICY_JS), str(DATA)],
        capture_output=True, text=True, cwd=ROOT,
    )
    if result.returncode != 0:
        raise AssertionError(f"the JavaScript engine failed:\n{result.stderr}")
    verdicts = {
        (row["bundle"], row["policy"]): row for row in json.loads(result.stdout)
    }
    _CACHE["js"] = verdicts
    return verdicts


def _python_verdicts():
    if "py" in _CACHE:
        return _CACHE["py"]
    verdicts = {}
    for path in sorted(DATA.glob("*.ccert")):
        bundle = Bundle.from_obj(json.loads(path.read_text(encoding="utf-8")))
        for name in available_policies():
            verdict = evaluate(bundle, load_policy(name))
            verdicts[(path.name, name)] = {
                "result": verdict.result,
                "undecided": verdict.count("undecided"),
                "details": [
                    [outcome.criterion.id, outcome.status]
                    for outcome in verdict.outcomes
                ],
                "models": [
                    [outcome.criterion.id, outcome.criterion.model["name"]]
                    for outcome in verdict.outcomes
                    if outcome.criterion.model
                ],
            }
    _CACHE["py"] = verdicts
    return verdicts


# -- the comparison ---------------------------------------------------


def test_both_engines_see_the_same_pairs():
    """A missing pair would make every comparison below vacuous for it."""
    if not _ready("test_both_engines_see_the_same_pairs"):
        return
    assert set(_javascript_verdicts()) == set(_python_verdicts())
    assert len(_python_verdicts()) >= 8


def test_the_verdicts_agree():
    if not _ready("test_the_verdicts_agree"):
        return
    javascript, python = _javascript_verdicts(), _python_verdicts()
    disagreements = [
        f"{bundle} / {policy}: python {python[(bundle, policy)]['result']}, "
        f"javascript {javascript[(bundle, policy)]['result']}"
        for bundle, policy in sorted(python)
        if python[(bundle, policy)]["result"] != javascript[(bundle, policy)]["result"]
    ]
    assert not disagreements, "; ".join(disagreements)


def test_each_criterion_agrees_not_just_the_summary():
    """Two engines can reach the same verdict for different reasons, and
    then diverge on the next certificate added."""
    if not _ready("test_each_criterion_agrees_not_just_the_summary"):
        return
    javascript, python = _javascript_verdicts(), _python_verdicts()
    for key in sorted(python):
        assert python[key]["details"] == javascript[key]["details"], key


def test_the_undecided_counts_agree():
    """Undecided blocks a pass, so a count that differs is a verdict that
    differs on the next criterion added."""
    if not _ready("test_the_undecided_counts_agree"):
        return
    javascript, python = _javascript_verdicts(), _python_verdicts()
    for key in sorted(python):
        assert python[key]["undecided"] == javascript[key]["undecided"], key


def test_the_models_agree():
    """The command line prints the model beside a verdict on a pass as
    well as a failure, because a threshold drawn from an estimate can
    move without any fact moving. The page could not print it at all: the
    field never reached the outcome objects. A gap in how trust is
    presented rather than in the verdict, and invisible to a test that
    compared only statuses."""
    if not _ready("test_the_models_agree"):
        return
    javascript, python = _javascript_verdicts(), _python_verdicts()
    for key in sorted(python):
        assert python[key]["models"] == javascript[key]["models"], key


def test_at_least_one_criterion_carries_a_model():
    """Otherwise the comparison above is vacuous."""
    if not _ready("test_at_least_one_criterion_carries_a_model"):
        return
    python = _python_verdicts()
    assert any(entry["models"] for entry in python.values())


# -- the case the page exists to show ---------------------------------


def test_the_browser_reproduces_the_tnfs_flip():
    """BN254 passing one model and failing the other, computed in the
    browser rather than asserted by us. This is the demonstration the
    viewer is for, so it is checked where a visitor would see it."""
    if not _ready("test_the_browser_reproduces_the_tnfs_flip"):
        return
    javascript = _javascript_verdicts()
    old = javascript.get(("bn254.ccert", "pairing-security-pre-tnfs"))
    new = javascript.get(("bn254.ccert", "pairing-security-tnfs-2016"))
    if old is None or new is None:
        SKIPPED.append("test_the_browser_reproduces_the_tnfs_flip")
        return
    assert old["result"] == "passes"
    assert new["result"] == "fails"
    flipped = {
        criterion
        for (criterion, status), (_, was) in zip(new["details"], old["details"])
        if status != was
    }
    assert flipped == {"embedding-field-size"}


def test_the_browser_computes_the_field_size_the_same_way():
    """The page must reach the same number as the producer, not merely
    the same verdict. It got this wrong twice: first by ignoring the
    operation entirely, then by applying the bit-length transform before
    the exponentiation instead of after."""
    if not _ready("test_the_browser_computes_the_field_size_the_same_way"):
        return
    javascript, python = _javascript_verdicts(), _python_verdicts()
    key = ("bls12-381.ccert", "pairing-security-tnfs-2016")
    if key not in javascript:
        SKIPPED.append("test_the_browser_computes_the_field_size_the_same_way")
        return
    assert dict(javascript[key]["details"]) == dict(python[key]["details"])
    assert dict(javascript[key]["details"])["embedding-field-size"] == "fail"


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
        print("  needs Node and an exported corpus: python tools\\export_web.py")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
