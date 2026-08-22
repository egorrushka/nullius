"""Guards the skeleton itself: the layout is part of the design."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "spec/ccert-v0.md",
    "spec/claims/README.md",
    "core/bundle/__init__.py",
    "core/policy/__init__.py",
    "verifier/Cargo.toml",
    "verifier/src/main.rs",
]


@pytest.mark.parametrize("rel", REQUIRED)
def test_present(rel):
    assert (ROOT / rel).exists(), f"missing: {rel}"


def test_no_verdicts_in_spec():
    """Tier C must not leak into the bundle format."""
    text = (ROOT / "spec" / "ccert-v0.md").read_text(encoding="utf-8")
    assert "Tier C never appears inside a bundle" in text
