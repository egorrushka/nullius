"""Pieces both producers assemble the same way.

There are two producers because their inputs differ: a prime-field curve
needs `a`, `b` and `p`, a pairing-friendly one needs a twist and an
extension as well. What they do with the results is largely identical —
the same twist claim, the same CM claim, the same embedding claim, the
same canonical factor entries — and until this module existed they did it
twice, in two files, edited separately.

That arrangement produced three of the bugs found in review, all of one
shape: a value read correctly in one place and not the other, or a fix
applied to one copy and forgotten in the second. Two copies of a rule are
two rules that agree until someone edits one.

Nothing here decides anything. It formats, sorts and assembles; every
number it handles was computed and checked by the caller. The point is
that the *formatting* is one implementation, because formatting is what
the byte-for-byte guarantee rests on.
"""

from __future__ import annotations

from typing import Any

from core.bundle import canonical

__all__ = [
    "SMALL_PRIME_LIMIT_EXP",
    "SMALL_PRIME_LIMIT",
    "certificate_payload",
    "chains_for",
    "factor_entries",
    "largest_prime_factor",
    "cardinality_deps",
]

# The bound below which a verifier settles primality itself, so a chain
# there would be bulk with no content. Written once here and read out of
# the Rust source by a test, which is the only thing keeping the two
# languages in step.
SMALL_PRIME_LIMIT_EXP = 24
SMALL_PRIME_LIMIT = 10**SMALL_PRIME_LIMIT_EXP


def certificate_payload(subject: int, steps: list[dict[str, int]]) -> dict[str, Any]:
    """An Atkin-Morain chain in canonical form."""
    return {
        "subject": canonical.as_str(subject),
        "steps": [
            {key: canonical.as_str(value) for key, value in step.items()}
            for step in steps
        ],
    }


def chains_for(
    factors: list[tuple[int, int]], backend, progress
) -> dict[int, list[dict[str, int]]]:
    """Chains for the factors the verifier cannot settle on its own."""
    chains: dict[int, list[dict[str, int]]] = {}
    for prime, _exponent in factors:
        if prime >= SMALL_PRIME_LIMIT:
            progress(f"proving a {prime.bit_length()}-bit factor prime")
            chains[prime] = backend.primality_certificate(prime)
    return chains


def factor_entries(
    factors: list[tuple[int, int]], chains: dict[int, list[dict[str, int]]]
) -> list[dict[str, Any]]:
    """Factors in canonical form, sorted so two runs agree byte for byte.

    The sort is not decoration. PARI happens to return factors in
    ascending order, so relying on that produced the right bytes for
    years — but relying on it is exactly the kind of accidental agreement
    that breaks when a backend changes, and the whole format rests on
    two builds producing one file.
    """
    entries: list[dict[str, Any]] = []
    for prime, exponent in sorted(factors):
        entry: dict[str, Any] = {
            "prime": canonical.as_str(prime),
            "exponent": canonical.as_str(exponent),
        }
        chain = chains.get(prime)
        if chain is not None:
            entry["steps"] = certificate_payload(prime, chain)["steps"]
        entries.append(entry)
    return entries


def prime_entries(factors: list[tuple[int, int]], backend, progress) -> list[dict[str, Any]]:
    """Factors with their chains, in one call. The common case."""
    return factor_entries(factors, chains_for(factors, backend, progress))


def largest_prime_factor(factors: list[tuple[int, int]]) -> int:
    """The largest prime in a factorisation, or 1 for the empty one.

    Asserted rather than left in the evidence because a policy reads only
    what a claim asserts. Subgroup security asks how large the biggest
    prime factor of a cofactor is, and a fact a policy needs has to be
    stated where a policy can see it. The verifier recomputes it from the
    factorisation, so asserting it adds nothing a reader must trust.
    """
    return max((prime for prime, _ in factors), default=1)


def cardinality_deps(cofactor: int) -> tuple[str, ...]:
    """What a claim that reads the number of points depends on.

    `curve.cardinality` exists only when the cofactor is not one; below
    that the same number lives in `curve.order`. The verifier requires
    whichever it actually reads to be declared, so the declaration has to
    follow the bundle's shape rather than the claim's name.
    """
    if cofactor == 1:
        return ("curve.order",)
    return ("curve.cardinality", "curve.order")
