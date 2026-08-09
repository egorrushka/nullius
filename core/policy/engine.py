"""The policy layer.

A policy decides whether a curve is acceptable. It does not compute
anything, and that is the whole point of keeping it here rather than in the
bundle: facts are one artefact, opinions are another, and the same facts
must be able to yield opposite verdicts under different policies without
anybody rewriting a certificate.

Three rules hold this apart from the rest of the project.

**A policy reads, never derives.** Every comparison it makes is against a
number already stated and already proved. If a policy needs a quantity the
bundle does not contain, the answer is "cannot decide" — never a guess, and
never a quiet pass.

**Missing evidence is not approval.** A criterion whose claim is absent
comes back undecided, and an undecided criterion keeps the whole verdict
from being a pass. Silence is the most dangerous default in this domain.

**Unproved facts do not count.** By default a policy reads only claims that
are proved or derived from proof. A candidate — something a program merely
reported — is treated as absent.

The comparison grammar is deliberately tiny: a field, an operator, a value,
and at most three modifiers. It is not a language and must not become one.
No expression here is ever evaluated as code.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any

# Packages installed the usual way land on the system drive, which on a
# machine that gets rolled back to a clean image every reboot is the same as
# not installing them. A vendor directory beside the project survives that,
# and costs four lines here.
_VENDOR = Path(__file__).resolve().parents[2] / "vendor"
if _VENDOR.is_dir() and str(_VENDOR) not in sys.path:
    sys.path.insert(0, str(_VENDOR))

from core.bundle import canonical
from core.bundle.model import Bundle, TIER_MEANING

__all__ = [
    "Policy",
    "PolicyError",
    "Criterion",
    "Outcome",
    "Verdict",
    "load_policy",
    "available_policies",
    "evaluate",
]

POLICY_DIR = Path(__file__).resolve().parent / "policies"

OPERATORS = {
    "eq": (lambda a, b: a == b, "must equal"),
    "ne": (lambda a, b: a != b, "must differ from"),
    "lt": (lambda a, b: a < b, "must be below"),
    "le": (lambda a, b: a <= b, "must be at most"),
    "gt": (lambda a, b: a > b, "must exceed"),
    "ge": (lambda a, b: a >= b, "must be at least"),
}

TRANSFORMS = {
    "none": lambda value: value,
    "abs": abs,
    "bits": lambda value: abs(value).bit_length(),
}

CRITERION_KEYS = {
    "id",
    "description",
    "claim",
    "field",
    "transform",
    "op",
    "value",
    "value_from",
    "citation",
}
VALUE_FROM_KEYS = {"claim", "field", "transform", "minus", "over"}
POLICY_KEYS = {"name", "title", "source", "accept_tiers", "criteria"}


class PolicyError(ValueError):
    """The policy file is malformed. Never silently tolerated."""


@dataclass(frozen=True)
class Criterion:
    id: str
    description: str
    claim: str
    field: str
    op: str
    transform: str = "none"
    value: str | None = None
    value_from: dict[str, Any] | None = None
    citation: str | None = None


@dataclass(frozen=True)
class Policy:
    name: str
    title: str
    source: str
    criteria: tuple[Criterion, ...]
    accept_tiers: tuple[str, ...] = ("A", "D")


@dataclass(frozen=True)
class Outcome:
    criterion: Criterion
    status: str  # pass, fail, undecided
    detail: str


@dataclass
class Verdict:
    policy: Policy
    outcomes: list[Outcome] = dataclass_field(default_factory=list)

    def count(self, status: str) -> int:
        return sum(1 for outcome in self.outcomes if outcome.status == status)

    @property
    def result(self) -> str:
        """A pass requires every criterion to pass. Nothing else does."""
        if self.count("fail"):
            return "fails"
        if self.count("undecided"):
            return "cannot be decided"
        return "passes"


# -- loading --------------------------------------------------------


def _require_keys(obj: dict, allowed: set[str], where: str) -> None:
    if not isinstance(obj, dict):
        raise PolicyError(f"{where}: expected a mapping")
    unknown = set(obj) - allowed
    if unknown:
        raise PolicyError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")


def load_policy(source: str | Path) -> Policy:
    """Read a policy file. A named policy is looked up in the policy directory."""
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise PolicyError(
            "policies are YAML; install the parser with: pip install pyyaml"
        ) from exc

    path = Path(source)
    if not path.suffix:
        path = POLICY_DIR / f"{source}.yaml"
    if not path.is_file():
        known = ", ".join(available_policies()) or "none installed"
        raise PolicyError(f"no policy at {path} (available: {known})")

    # safe_load, always: a policy is data, and data does not get to run.
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    _require_keys(document, POLICY_KEYS, path.name)

    for key in ("name", "title", "source"):
        if not isinstance(document.get(key), str):
            raise PolicyError(f"{path.name}: `{key}` is required and must be text")

    tiers = tuple(document.get("accept_tiers", ["A", "D"]))
    for tier in tiers:
        if tier not in TIER_MEANING:
            raise PolicyError(f"{path.name}: unknown tier `{tier}`")

    raw_criteria = document.get("criteria")
    if not isinstance(raw_criteria, list) or not raw_criteria:
        raise PolicyError(f"{path.name}: a policy needs at least one criterion")

    criteria = []
    seen: set[str] = set()
    for entry in raw_criteria:
        _require_keys(entry, CRITERION_KEYS, f"{path.name}: criterion")
        for key in ("id", "description", "claim", "field", "op"):
            if not isinstance(entry.get(key), str):
                raise PolicyError(f"{path.name}: criterion needs a `{key}`")
        if entry["id"] in seen:
            raise PolicyError(f"{path.name}: criterion `{entry['id']}` appears twice")
        seen.add(entry["id"])
        if entry["op"] not in OPERATORS:
            raise PolicyError(f"{path.name}: unknown operator `{entry['op']}`")
        transform = entry.get("transform", "none")
        if transform not in TRANSFORMS:
            raise PolicyError(f"{path.name}: unknown transform `{transform}`")
        has_value = "value" in entry
        has_reference = "value_from" in entry
        if has_value == has_reference:
            raise PolicyError(
                f"{path.name}: criterion `{entry['id']}` needs exactly one of "
                "`value` or `value_from`"
            )
        if has_reference:
            _require_keys(
                entry["value_from"], VALUE_FROM_KEYS, f"{path.name}: value_from"
            )
            inner = entry["value_from"].get("transform", "none")
            if inner not in TRANSFORMS:
                raise PolicyError(f"{path.name}: unknown transform `{inner}`")

        criteria.append(
            Criterion(
                id=entry["id"],
                description=entry["description"],
                claim=entry["claim"],
                field=entry["field"],
                op=entry["op"],
                transform=transform,
                value=str(entry["value"]) if has_value else None,
                value_from=entry.get("value_from"),
                citation=entry.get("citation"),
            )
        )

    return Policy(
        name=document["name"],
        title=document["title"],
        source=document["source"],
        criteria=tuple(criteria),
        accept_tiers=tiers,
    )


def available_policies() -> list[str]:
    return sorted(path.stem for path in POLICY_DIR.glob("*.yaml"))


# -- evaluation -----------------------------------------------------


def _literal(text: str) -> int:
    """A plain decimal, or `2^k` for the powers that thresholds are written in."""
    text = text.strip()
    if "^" in text:
        base, _, exponent = text.partition("^")
        try:
            return int(base) ** int(exponent)
        except ValueError:
            raise PolicyError(f"malformed power: {text!r}") from None
    try:
        return canonical.as_int(text)
    except canonical.CanonicalError:
        raise PolicyError(f"malformed number: {text!r}") from None


class _Undecided(Exception):
    """Raised when the bundle simply does not say."""


def _read(bundle: Bundle, policy: Policy, claim: str, field: str, transform: str) -> int:
    record = bundle.by_name(claim)
    if record is None:
        raise _Undecided(f"the bundle makes no claim `{claim}`")
    if record.tier not in policy.accept_tiers:
        raise _Undecided(
            f"`{claim}` is only {TIER_MEANING[record.tier].split(':')[0]}, "
            "which this policy does not accept"
        )
    raw = record.asserts.get(field)
    if raw is None:
        raise _Undecided(f"`{claim}` does not state `{field}`")
    try:
        value = canonical.as_int(raw, field=f"{claim}.{field}")
    except canonical.CanonicalError:
        raise _Undecided(f"`{claim}.{field}` is not a number") from None
    return TRANSFORMS[transform](value)


def _threshold(bundle: Bundle, policy: Policy, criterion: Criterion) -> tuple[int, str]:
    if criterion.value is not None:
        return _literal(criterion.value), criterion.value
    reference = criterion.value_from or {}
    value = _read(
        bundle,
        policy,
        reference["claim"],
        reference["field"],
        reference.get("transform", "none"),
    )
    label = f"{reference['claim']}.{reference['field']}"
    if "minus" in reference:
        value -= int(reference["minus"])
        label += f" - {reference['minus']}"
    if "over" in reference:
        divisor = int(reference["over"])
        if divisor == 0:
            raise PolicyError("division by zero in a policy threshold")
        value //= divisor
        label += f" / {divisor}"
    return value, label


def evaluate(bundle: Bundle, policy: Policy) -> Verdict:
    """Apply a policy to a bundle. Computes nothing; only reads and compares."""
    verdict = Verdict(policy=policy)
    for criterion in policy.criteria:
        try:
            observed = _read(
                bundle, policy, criterion.claim, criterion.field, criterion.transform
            )
            threshold, label = _threshold(bundle, policy, criterion)
        except _Undecided as reason:
            verdict.outcomes.append(Outcome(criterion, "undecided", str(reason)))
            continue

        compare, phrase = OPERATORS[criterion.op]
        held = compare(observed, threshold)
        shown = observed if observed.bit_length() < 40 else f"~2^{observed.bit_length()}"
        wanted = threshold if threshold.bit_length() < 40 else label
        verdict.outcomes.append(
            Outcome(
                criterion,
                "pass" if held else "fail",
                f"{shown} {phrase} {wanted}",
            )
        )
    return verdict


# -- command line ---------------------------------------------------


def _print(verdict: Verdict, path: Path) -> None:
    policy = verdict.policy
    print(f"bundle:   {path}")
    print(f"policy:   {policy.title}")
    print(f"source:   {policy.source}\n")

    marks = {"pass": "  pass  ", "fail": "  FAIL  ", "undecided": "   ?    "}
    for outcome in verdict.outcomes:
        print(f"[{marks[outcome.status]}]  {outcome.criterion.id:<22}  {outcome.detail}")
        if outcome.status != "pass":
            print(f"{'':<34}{outcome.criterion.description}")

    print(
        f"\n{verdict.count('pass')} met, {verdict.count('fail')} not met, "
        f"{verdict.count('undecided')} undecided"
    )
    print(f"\nUnder this policy the curve {verdict.result}.")
    if verdict.count("undecided"):
        print(
            "Undecided is not approval: the bundle does not carry the evidence\n"
            "these criteria ask for."
        )


def _matrix(directory: Path) -> int:
    """Every bundle against every policy, as a table.

    This is the view that makes the design legible: the columns disagree
    with each other, and none of the underlying files changed.
    """
    import json

    bundles = sorted(directory.glob("*.ccert"))
    if not bundles:
        print(f"no bundles in {directory}")
        return 2
    policies = [load_policy(name) for name in available_policies()]

    width = max(len(path.stem) for path in bundles) + 2
    header = "".join(f"{policy.name:<26}" for policy in policies)
    print(f"{'curve':<{width}}{header}")

    for path in bundles:
        try:
            bundle = Bundle.from_obj(json.loads(path.read_text(encoding="utf-8")))
            bundle.validate()
        except ValueError as exc:
            print(f"{path.stem:<{width}}unreadable: {exc}")
            continue
        cells = []
        for policy in policies:
            verdict = evaluate(bundle, policy)
            summary = verdict.result
            if verdict.count("undecided"):
                summary += f" ({verdict.count('undecided')} unknown)"
            cells.append(f"{summary:<26}")
        print(f"{path.stem:<{width}}{''.join(cells)}")

    print("\nSame facts throughout. Only the criteria differ.")
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Apply a policy to a bundle.")
    parser.add_argument("bundle", nargs="?", default="corpus/secp256k1.ccert")
    parser.add_argument("--policy", default="safecurves-2024")
    parser.add_argument("--list", action="store_true", help="show installed policies")
    parser.add_argument(
        "--corpus", metavar="DIR", help="every bundle in DIR against every policy"
    )
    args = parser.parse_args(argv)

    if args.list:
        for name in available_policies():
            print(name)
        return 0

    if args.corpus:
        return _matrix(Path(args.corpus))

    path = Path(args.bundle)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        bundle = Bundle.from_obj(document)
        bundle.validate()
        policy = load_policy(args.policy)
    except (OSError, ValueError) as exc:
        print(f"FAIL  {type(exc).__name__}: {exc}")
        return 2

    verdict = evaluate(bundle, policy)
    _print(verdict, path)
    return 0 if verdict.result == "passes" else 1


if __name__ == "__main__":
    raise SystemExit(main())
