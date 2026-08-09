# Bundle format v0

A `.ccert` bundle is a set of claims about one subject, where every claim
points at the evidence needed to re-check it.

## Design rules

1. **Facts and verdicts never mix.** A bundle states what is true. Whether
   that is "safe" is decided by a policy, outside the bundle.
   Tier C never appears inside a bundle.
2. **Unknown fields are rejected loudly.** A verifier that skips what it
   does not understand is worse than no verifier. This applies to claim
   types, evidence types and stray object members alike.
3. **Canonical bytes.** One bundle, one serialisation, one hash.
4. **Tier is derived from evidence, never asserted by the producer.**

## Encoding

* UTF-8, no byte-order mark. The file ends with a single newline, which is
  not part of the hashed encoding.
* Object keys sorted by code point; no whitespace between tokens.
* **No JSON numbers anywhere.** Every quantity is a decimal string with
  exactly one spelling: no leading zeros, no plus sign, no `-0`, no
  exponent. Two different strings must never mean the same number.
* Allowed types: object, array, string, `true`, `false`, `null`.
* Keys match `[A-Za-z0-9._:-]+`, so escaping cannot disturb the sort order.
* Content addresses are `sha256:` followed by 64 lowercase hex digits.

The digest of a bundle is the SHA-256 of its canonical encoding.

## Structure

```
format    "ccert"
version   "0"
subject   what the claims are about
claims    array of claim records
evidence  flat pool, keyed by the hash of each entry
```

A claim record carries `claim` (its type), `asserts` (what is being said),
`evidence` (`type` and an optional `ref` into the pool), and an optional
`depends_on` listing other claims in the same bundle that it rests on.

The evidence pool is **flat**. Evidence does not nest inside claims, and a
claim reaches it by content address. A verifier therefore walks a loop
rather than a recursion, which keeps its size budget realistic. Every key
in the pool must equal the digest of its own value, and every entry must
be referenced by some claim.

## Tiers

| Tier | Meaning                                                       |
|------|---------------------------------------------------------------|
| A    | Proved: the evidence establishes the claim outright            |
| D    | Derived: follows from other claims here, and only if they hold |
| X    | Candidate: computed but not proved, carries no weight          |

Tier is a function of the evidence type, resolved through a table the
verifier also holds. A producer cannot promote its own output.

| Evidence type           | Tier | What it actually is                       |
|-------------------------|------|-------------------------------------------|
| `candidate.pseudoprime` | X    | a screening test said probably prime      |
| `candidate.sea`         | X    | a program returned a number               |
| `check.hasse`           | A    | bound re-derived from p and n by integers |
| `derive.twist-sum`      | D    | `#E + #E' = 2p + 2`                       |

## What is deliberately absent

**Timings.** A wall-clock measurement would make the same certificate hash
differently on a fast machine and a slow one, destroying the property that
two independent runs produce identical bytes. Timings belong in a run log
beside the file.

**Signatures.** Deferred past v0, and then only as a detached envelope. A
certificate is worth something because it can be checked, not because of
who signed it; adding a signature now would suggest the opposite.

Provenance, on the other hand, *is* hashed. For an unproved claim the
identity of the producer is part of what is being said, so a candidate from
PARI 2.15 and one from 2.17 are different objects. Tier A evidence carries
no provenance and is therefore identical everywhere.

## Open questions

- Do policies name claim types directly, or a stable alias, so that adding
  `curve.embedding.v2` does not silently break every published policy?
- Should a bundle be allowed to state a claim it could not compute, marked
  as attempted-and-failed, or is absence enough?
