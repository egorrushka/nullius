"""The export is a bridge, and bridges are where things get dropped.

These check that what reaches the browser is the same file that was
verified, and that the two policy engines have not drifted apart.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from core.bundle import canonical
from core.bundle.model import Bundle

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "spec" / "vectors" / "valid"
POLICY_JS = ROOT / "web" / "src" / "policy.js"

pytest.importorskip("yaml", reason="pip install pyyaml")

from core.policy.engine import available_policies, evaluate, load_policy  # noqa: E402


@pytest.fixture(scope="module")
def exported(tmp_path_factory):
    out = tmp_path_factory.mktemp("data")
    corpus = tmp_path_factory.mktemp("corpus")
    for vector in VECTORS.glob("*.ccert"):
        shutil.copyfile(vector, corpus / vector.name)
    result = subprocess.run(
        ["python", str(ROOT / "tools" / "export_web.py"),
         "--corpus", str(corpus), "--out", str(out)],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return out


def test_bundles_are_copied_byte_for_byte(exported):
    """A repackaged file would show a digest it does not have."""
    for vector in VECTORS.glob("*.ccert"):
        assert (exported / vector.name).read_bytes() == vector.read_bytes()


def test_index_digests_match_the_files(exported):
    index = json.loads((exported / "index.json").read_text(encoding="utf-8"))
    for entry in index["bundles"]:
        raw = (exported / entry["file"]).read_bytes()
        assert entry["digest"] == canonical.digest_bytes(raw.rstrip(b"\n"))


def test_every_policy_is_exported(exported):
    index = json.loads((exported / "index.json").read_text(encoding="utf-8"))
    assert {p["name"] for p in index["policies"]} == set(available_policies())


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_both_policy_engines_agree(exported, tmp_path):
    """Two implementations of one grammar. A disagreement is a real bug."""
    script = tmp_path / "run.mjs"
    script.write_text(
        f'''
import {{ readFileSync }} from "node:fs";
import {{ evaluate }} from "{POLICY_JS.as_posix()}";
const dir = "{exported.as_posix()}";
const index = JSON.parse(readFileSync(dir + "/index.json", "utf8"));
const out = {{}};
for (const entry of index.bundles) {{
  const bundle = JSON.parse(readFileSync(dir + "/" + entry.file, "utf8"));
  for (const policy of index.policies) {{
    const verdict = evaluate(bundle, policy);
    out[entry.label + "|" + policy.name] = {{
      result: verdict.result,
      outcomes: Object.fromEntries(
        verdict.outcomes.map((o) => [o.criterion.id, o.status])),
    }};
  }}
}}
console.log(JSON.stringify(out));
''',
        encoding="utf-8",
    )
    result = subprocess.run(
        ["node", str(script)], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stderr
    from_js = json.loads(result.stdout)

    index = json.loads((exported / "index.json").read_text(encoding="utf-8"))
    from_python = {}
    for entry in index["bundles"]:
        bundle = Bundle.from_obj(
            json.loads((exported / entry["file"]).read_text(encoding="utf-8"))
        )
        for name in available_policies():
            verdict = evaluate(bundle, load_policy(name))
            from_python[f"{entry['label']}|{name}"] = {
                "result": verdict.result,
                "outcomes": {o.criterion.id: o.status for o in verdict.outcomes},
            }

    assert from_python == from_js


def test_release_is_self_contained(tmp_path):
    """The page must not reach for anything beside it: no server, no CDN."""
    page = ROOT / "web" / "dist" / "index.html"
    if not page.is_file():
        pytest.skip("run tools\\web_build.bat first")
    text = page.read_text(encoding="utf-8")
    for pattern in ("src=\"http", "href=\"http", "src=\"./assets", "src=\"/assets"):
        assert pattern not in text, f"the page still loads {pattern}"


def test_release_page_carries_the_corpus():
    page = ROOT / "web" / "dist" / "index.html"
    if not page.is_file():
        pytest.skip("run tools\\web_build.bat first")
    text = page.read_text(encoding="utf-8")
    for vector in VECTORS.glob("*.ccert"):
        label = vector.stem
        assert label in text, f"{label} is missing from the built page"
