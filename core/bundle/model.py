"""The bundle: subject, claims, and a flat pool of evidence.

Three decisions are baked into this module, and each is load-bearing.

**Tier is derived, never asserted.** A producer does not get to label its
own output "proved". The tier of a claim follows from the kind of evidence
attached to it, through the table below. A claim with no evidence is tier
X, and stays tier X no matter how confident the thing that produced it was.

**The evidence pool is flat and content-addressed.** Evidence does not nest
inside claims. It lives in one dictionary keyed by the hash of its own
canonical encoding, and claims point at it by that hash. A verifier walks
a loop, not a recursion, and its size budget stays a budget.

**No timings inside the bundle.** This changes the draft spec, and on
purpose: a wall-clock measurement would make the same certificate hash
differently on a fast machine and a slow one, which destroys the property
that two independent runs produce identical bytes. Timings belong in a
run log next to the file, not in the hashed document.

Note that provenance *is* hashed. A candidate produced by PARI 2.15 and
one produced by 2.17 are different objects, because for an unproved claim
the identity of the producer is part of what is being said. Tier A
evidence carries no provenance, so it is stable everywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import canonical
from .canonical import CanonicalError, as_int, as_str, digest

__all__ = [
    "BundleError",
    "Claim",
    "Bundle",
    "CLAIM_TYPES",
    "EVIDENCE_TIERS",
    "TIER_MEANING",
    "FORMAT",
    "VERSION",
]

FORMAT = "ccert"
VERSION = "0"

TIER_MEANING = {
    "A": "proved: the evidence establishes the claim outright",
    "D": "derived: follows from other claims in this bundle, and only if they hold",
    "X": "candidate: computed but not proved, carries no weight",
}

# Evidence kind -> tier. Adding a row here is a deliberate act: it decides
# what the project is willing to call proved.
EVIDENCE_TIERS = {
    # A number was produced by a program we asked. That is all it means.
    "candidate.sea": "X",
    "candidate.pseudoprime": "X",
    # An Atkin-Morain chain, re-checked step by step by the verifier.
    "proof.ecpp": "A",
    # The exact order of an element, established from a proved factorisation
    # of the group order. Not a bound: the number itself.
    "proof.multiplicative-order": "A",
    # The fundamental discriminant of the CM field, with the factorisation
    # that shows it really is fundamental.
    "proof.cm-discriminant": "A",
    # The published derivation, rerun. Shows b follows from the seed; says
    # nothing about where the seed came from.
    "check.seed-derivation": "A",
    # Given p and n, the bound is re-checked with integer arithmetic.
    "check.hasse": "A",
    # A point of prime order n, with n larger than the Hasse window, which
    # leaves the group order no room to be anything else.
    "check.order-unique": "A",
    # #E + #E' = 2p + 2. Sound only if the order claim is sound.
    "derive.twist-sum": "D",
}

CLAIM_TYPES = {
    "field.characteristic",
    "curve.cardinality",
    "curve.order.prime",
    "curve.order",
    "curve.embedding",
    "curve.cm",
    "param.rigidity",
    "curve.hasse",
    "twist.cardinality",
}


class BundleError(ValueError):
    """The bundle is malformed, inconsistent, or claims something it may not."""


@dataclass(frozen=True)
class Claim:
    """A single assertion plus a pointer to what backs it."""

    claim: str
    asserts: dict[str, Any]
    evidence_type: str
    evidence_ref: str | None = None
    depends_on: tuple[str, ...] = ()

    @property
    def tier(self) -> str:
        return EVIDENCE_TIERS[self.evidence_type]

    def to_obj(self) -> dict[str, Any]:
        obj: dict[str, Any] = {
            "claim": self.claim,
            "asserts": dict(self.asserts),
            "evidence": {"type": self.evidence_type},
        }
        if self.evidence_ref is not None:
            obj["evidence"]["ref"] = self.evidence_ref
        if self.depends_on:
            obj["depends_on"] = list(self.depends_on)
        return obj

    @classmethod
    def from_obj(cls, obj: Any) -> "Claim":
        if not isinstance(obj, dict):
            raise BundleError("claim must be an object")
        for key in obj:
            if key not in {"claim", "asserts", "evidence", "depends_on"}:
                raise BundleError(f"unknown field in claim: {key}")
        evidence = obj.get("evidence")
        if not isinstance(evidence, dict) or "type" not in evidence:
            raise BundleError("claim is missing its evidence block")
        for key in evidence:
            if key not in {"type", "ref"}:
                raise BundleError(f"unknown field in evidence block: {key}")
        asserts = obj.get("asserts")
        if not isinstance(asserts, dict):
            raise BundleError("claim is missing its asserts block")
        depends = obj.get("depends_on", [])
        if not isinstance(depends, list) or not all(isinstance(d, str) for d in depends):
            raise BundleError("depends_on must be a list of claim names")
        return cls(
            claim=obj.get("claim"),
            asserts=asserts,
            evidence_type=evidence["type"],
            evidence_ref=evidence.get("ref"),
            depends_on=tuple(depends),
        )


@dataclass
class Bundle:
    """A subject, the claims made about it, and the evidence pool."""

    subject: dict[str, Any]
    claims: list[Claim] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    # -- evidence pool ----------------------------------------------

    def add_evidence(self, payload: dict[str, Any]) -> str:
        """Store evidence and return its content address."""
        ref = digest(payload)
        existing = self.evidence.get(ref)
        if existing is not None and existing != payload:
            raise BundleError("hash collision in the evidence pool")
        self.evidence[ref] = payload
        return ref

    def add_claim(
        self,
        claim: str,
        asserts: dict[str, Any],
        evidence_type: str,
        payload: dict[str, Any] | None = None,
        depends_on: tuple[str, ...] = (),
    ) -> Claim:
        if evidence_type not in EVIDENCE_TIERS:
            raise BundleError(f"unknown evidence type: {evidence_type}")
        ref = None
        if payload is not None:
            body = dict(payload)
            body["type"] = evidence_type
            ref = self.add_evidence(body)
        record = Claim(claim, dict(asserts), evidence_type, ref, tuple(depends_on))
        self.claims.append(record)
        return record

    def by_name(self, name: str) -> Claim | None:
        for record in self.claims:
            if record.claim == name:
                return record
        return None

    # -- serialisation ----------------------------------------------

    def to_obj(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "version": VERSION,
            "subject": self.subject,
            "claims": [c.to_obj() for c in self.claims],
            "evidence": self.evidence,
        }

    @classmethod
    def from_obj(cls, obj: Any) -> "Bundle":
        if not isinstance(obj, dict):
            raise BundleError("bundle must be an object")
        if obj.get("format") != FORMAT:
            raise BundleError("not a ccert bundle")
        if obj.get("version") != VERSION:
            raise BundleError(f"unsupported version: {obj.get('version')!r}")
        for key in obj:
            if key not in {"format", "version", "subject", "claims", "evidence"}:
                raise BundleError(f"unknown top-level field: {key}")
        subject = obj.get("subject")
        if not isinstance(subject, dict):
            raise BundleError("bundle is missing its subject")
        raw_claims = obj.get("claims")
        if not isinstance(raw_claims, list):
            raise BundleError("bundle is missing its claims")
        evidence = obj.get("evidence", {})
        if not isinstance(evidence, dict):
            raise BundleError("evidence pool must be an object")
        return cls(
            subject=subject,
            claims=[Claim.from_obj(c) for c in raw_claims],
            evidence=evidence,
        )

    def encode(self) -> bytes:
        return canonical.encode(self.to_obj())

    def digest(self) -> str:
        return canonical.digest_bytes(self.encode())

    # -- validation -------------------------------------------------

    def validate(self) -> None:
        """Refuse anything malformed. Called before writing and after reading.

        This is not the verifier. It checks that the document is
        well-formed and internally consistent; it does not re-derive a
        single mathematical fact. That is the Rust binary's job, and
        keeping the two separate is what makes the second one meaningful.
        """
        canonical.check_shape(self.to_obj())

        seen: set[str] = set()
        for record in self.claims:
            if record.claim not in CLAIM_TYPES:
                raise BundleError(f"unknown claim type: {record.claim!r}")
            if record.claim in seen:
                raise BundleError(f"claim stated twice: {record.claim}")
            seen.add(record.claim)

            if record.evidence_type not in EVIDENCE_TIERS:
                raise BundleError(f"unknown evidence type: {record.evidence_type!r}")

            if record.evidence_ref is not None:
                if not canonical.is_digest(record.evidence_ref):
                    raise BundleError("evidence reference is not a content address")
                payload = self.evidence.get(record.evidence_ref)
                if payload is None:
                    raise BundleError(
                        f"claim {record.claim} points at missing evidence"
                    )
                if payload.get("type") != record.evidence_type:
                    raise BundleError(
                        f"claim {record.claim} and its evidence disagree on type"
                    )

        tiers = {record.claim: record.tier for record in self.claims}
        for record in self.claims:
            for name in record.depends_on:
                if name not in seen:
                    raise BundleError(f"claim depends on something absent: {name}")
                # Nothing may rest on something weaker than itself.
                too_weak = (record.tier == "A" and tiers[name] != "A") or (
                    record.tier == "D" and tiers[name] == "X"
                )
                if too_weak:
                    raise BundleError(
                        f"{record.claim} ({record.tier}) depends on {name} "
                        f"({tiers[name]}), which is weaker"
                    )

        for ref, payload in self.evidence.items():
            if not canonical.is_digest(ref):
                raise BundleError(f"evidence key is not a content address: {ref!r}")
            if digest(payload) != ref:
                raise BundleError(
                    "evidence does not hash to its key; the pool has been altered"
                )

        used = {r.evidence_ref for r in self.claims if r.evidence_ref}
        orphans = set(self.evidence) - used
        if orphans:
            raise BundleError(f"{len(orphans)} evidence entries are referenced by nothing")

    # -- reporting ---------------------------------------------------

    def tier_counts(self) -> dict[str, int]:
        counts = {tier: 0 for tier in TIER_MEANING}
        for record in self.claims:
            counts[record.tier] += 1
        return counts

    def proved_only(self) -> list[Claim]:
        """Claims that stand on their own. Usually a short list, honestly."""
        return [record for record in self.claims if record.tier == "A"]
