"""What changed between two certificates.

    python -m tools.ccert_diff old.ccert new.ccert
    python -m tools.ccert_diff --json old.ccert new.ccert

A byte diff of a certificate is useless: the payloads are walls of
decimal digits and one added claim reorders the evidence pool. The
question people actually have when a digest moves is "what does the
document say now that it did not before", and that is a question about
claims, not bytes.

Two rules shape the output.

**Silence about what did not move.** A run that added one claim should
print one line. Anything else buries the answer.

**Tier changes are called out first.** A claim that dropped from proved
to derived is the most consequential thing that can happen to a
certificate and the least visible in a diff, since the words around it
barely change.

The tool does not verify. Both files may be nonsense and this will still
describe the difference between them, which is what you want when
investigating why one of them stopped verifying.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

__all__ = ["diff", "Change"]

TIER_ORDER = {"A": 3, "D": 2, "X": 1}


class Change:
    """One difference, in a form both renderers can use."""

    def __init__(self, kind: str, claim: str, detail: str, severity: str = "info"):
        self.kind = kind
        self.claim = claim
        self.detail = detail
        self.severity = severity

    def as_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "claim": self.claim,
            "detail": self.detail,
            "severity": self.severity,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging only
        return f"Change({self.kind}, {self.claim}, {self.detail!r})"


def _claims(document: dict) -> dict[str, dict]:
    return {claim["claim"]: claim for claim in document.get("claims", [])}


def _tier(document: dict, claim: dict, tiers: dict[str, str]) -> str:
    """The tier of a claim, from the evidence type.

    Read from the table rather than from the document, because a document
    does not state tiers — that is the point of the format, and a diff
    that took the producer's word for it would be reporting the wrong
    thing.
    """
    return tiers.get(claim.get("evidence", {}).get("type", ""), "?")


def _subject_changes(old: dict, new: dict) -> list[Change]:
    changes = []
    old_subject = old.get("subject", {})
    new_subject = new.get("subject", {})
    for key in sorted(set(old_subject) | set(new_subject)):
        before, after = old_subject.get(key), new_subject.get(key)
        if before == after:
            continue
        # A changed subject means the two documents are about different
        # curves, which makes every other difference below meaningless.
        changes.append(
            Change(
                "subject",
                key,
                f"{before!r} -> {after!r}",
                severity="alarming",
            )
        )
    return changes


def _assert_changes(name: str, old: dict, new: dict) -> list[Change]:
    changes = []
    before, after = old.get("asserts", {}), new.get("asserts", {})
    for key in sorted(set(before) | set(after)):
        if before.get(key) == after.get(key):
            continue
        if key not in before:
            changes.append(Change("assert-added", name, f"{key} = {after[key]}"))
        elif key not in after:
            changes.append(
                Change("assert-removed", name, f"{key} was {before[key]}", "notable")
            )
        else:
            changes.append(
                Change(
                    "assert-changed",
                    name,
                    f"{key}: {before[key]} -> {after[key]}",
                    "alarming",
                )
            )
    return changes


def diff(old: dict, new: dict, tiers: dict[str, str]) -> list[Change]:
    """Every difference that matters, ordered by how much it matters."""
    changes = _subject_changes(old, new)

    before, after = _claims(old), _claims(new)

    for name in sorted(set(before) & set(after)):
        old_tier = _tier(old, before[name], tiers)
        new_tier = _tier(new, after[name], tiers)
        if old_tier != new_tier:
            # Weakening is the thing worth shouting about. A claim that
            # went from proved to derived reads almost identically in the
            # rendered output and means something quite different.
            weakened = TIER_ORDER.get(new_tier, 0) < TIER_ORDER.get(old_tier, 0)
            changes.append(
                Change(
                    "tier-weakened" if weakened else "tier-strengthened",
                    name,
                    f"{old_tier} -> {new_tier}",
                    "alarming" if weakened else "notable",
                )
            )

        old_kind = before[name].get("evidence", {}).get("type")
        new_kind = after[name].get("evidence", {}).get("type")
        if old_kind != new_kind:
            changes.append(
                Change("evidence-changed", name, f"{old_kind} -> {new_kind}", "notable")
            )

        old_deps = set(before[name].get("depends_on", ()))
        new_deps = set(after[name].get("depends_on", ()))
        for gone in sorted(old_deps - new_deps):
            changes.append(
                Change("dependency-removed", name, gone, "alarming")
            )
        for added in sorted(new_deps - old_deps):
            changes.append(Change("dependency-added", name, added))

        changes.extend(_assert_changes(name, before[name], after[name]))

    for name in sorted(set(after) - set(before)):
        changes.append(
            Change("claim-added", name, _tier(new, after[name], tiers))
        )
    for name in sorted(set(before) - set(after)):
        changes.append(
            Change(
                "claim-removed",
                name,
                _tier(old, before[name], tiers),
                "alarming",
            )
        )

    order = {"alarming": 0, "notable": 1, "info": 2}
    changes.sort(key=lambda change: (order[change.severity], change.claim, change.kind))
    return changes


def _digest(raw: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(raw.rstrip(b"\n")).hexdigest()


def _render(changes: list[Change], old_path: Path, new_path: Path,
            old_raw: bytes, new_raw: bytes) -> None:
    print(f"old:  {old_path}  {_digest(old_raw)}")
    print(f"new:  {new_path}  {_digest(new_raw)}")
    if old_raw == new_raw:
        print("\nidentical bytes")
        return
    if not changes:
        # Worth reporting rather than hiding: the two documents say the
        # same things and are not the same file, which means something
        # about the encoding moved.
        print("\nthe bytes differ but no claim does; the encoding changed")
        return

    print()
    marks = {"alarming": "!!", "notable": " *", "info": "  "}
    for change in changes:
        print(f"{marks[change.severity]}  {change.kind:<20} {change.claim:<24} {change.detail}")

    alarming = sum(1 for change in changes if change.severity == "alarming")
    print(f"\n{len(changes)} change(s), {alarming} worth a second look")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("old")
    parser.add_argument("new")
    parser.add_argument("--json", action="store_true", help="machine-readable")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from core.bundle.model import EVIDENCE_TIERS

    try:
        old_raw = Path(args.old).read_bytes()
        new_raw = Path(args.new).read_bytes()
        old = json.loads(old_raw)
        new = json.loads(new_raw)
    except (OSError, ValueError) as exc:
        print(f"FAIL  {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    changes = diff(old, new, EVIDENCE_TIERS)

    if args.json:
        print(
            json.dumps(
                {
                    "changes": [change.as_dict() for change in changes],
                    "identical": old_raw == new_raw,
                    "new_digest": _digest(new_raw),
                    "old_digest": _digest(old_raw),
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
        )
    else:
        _render(changes, Path(args.old), Path(args.new), old_raw, new_raw)

    # Non-zero when something weakened, so this can gate a release without
    # anyone reading the output.
    return 1 if any(c.severity == "alarming" for c in changes) else 0


if __name__ == "__main__":
    raise SystemExit(main())
