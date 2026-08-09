# Nullius

*Nullius in verba* — take nobody's word for it.

Claims about elliptic curves normally arrive as tables. This curve has
prime order, that one has a large discriminant, this one's parameters came
from a seed. The numbers are usually right, and there is usually no way to
tell from the table itself.

Nullius produces certificates instead. Every claim carries the evidence
for it, and a small separate program re-establishes each claim from the
file alone. Producing the evidence for one curve takes half a minute of
point counting, factoring and primality proving. Checking it takes a
quarter of a second, on a machine that did none of that work.

```
$ ccert-verify corpus/secp256k1.ccert

  [   proved]  field.characteristic    Atkin-Morain chain of 8 step(s) checked
  [   proved]  curve.order.prime       Atkin-Morain chain of 10 step(s) checked
  [   proved]  curve.order             witness of order n; no other multiple fits the window
  [   proved]  curve.hasse             bounds recomputed from p
  [   proved]  curve.embedding         exact order, 254 bits, comparable to n
  [   proved]  curve.cm                |D| is 2 bits, fundamental
  [  derived]  twist.cardinality       identity re-derived; sound only if the cardinality is

  6 proved, 1 derived, 0 not proved
```

## Facts are not verdicts

A certificate says what is true. Whether a curve is a good choice is a
separate question, and different people answer it differently from the
same numbers.

secp256k1 has CM discriminant −3. Under the SafeCurves criteria that is a
failure: the discriminant is supposed to be large. Under a policy written
for implementers who want the GLV endomorphism it is a requirement, since
the speedup exists precisely because the discriminant is small.

So verdicts live in policies, which are data files listing criteria and
citing where each comes from, applied to a certificate from outside. One
certificate, several policies, several answers, and no certificate
rewritten.

Policies never compute. Every comparison is against a number already
proved. A criterion whose evidence is missing comes back undecided, and an
undecided criterion prevents a pass — silence is not approval.

## Three tiers, and a producer cannot promote itself

| Tier | Meaning |
|------|---------|
| proved | The evidence establishes the claim outright |
| derived | Follows from other claims here, and only if those hold |
| not proved | A program reported it. That is all it means |

The tier of a claim follows from the kind of evidence attached, through a
table the verifier holds too. And nothing may rest on something weaker
than itself: a claim called proved while depending on an unproved one is
rejected as a malformed document.

## What is proved today

For each curve in the corpus: p is prime and n is prime, both by
Atkin–Morain certificates re-checked step by step; the group has exactly n
points, from a witness point of order n and the fact that n exceeds the
Hasse window, so no other multiple of n fits inside it; the exact
embedding degree, established from a proved factorisation of n − 1 rather
than bounded by search; the CM field discriminant, with the factorisation
that shows it is fundamental; and, where the standard publishes a seed,
that the curve parameters follow from it.

Curves in the corpus: secp256k1, NIST P-256.

## Getting started

Reading requires nothing. Download a release, open
`curve-certificates.html` in any browser — the corpus is inlined, there is
no server and no internet — and run `check-all.bat` to have the verifier
re-check every certificate beside it.

Building certificates requires PARI/GP with the `seadata` package, Python
3.10, and Rust. Then:

```
tools\build_verifier.bat     build the verifier
tools\corpus.bat             build and verify every known curve
tools\policy.bat --list      see the installed policies
tools\web.bat                open the dossier viewer
tools\test.bat               run the suite
```

`python tools\env_check.py` says which of those are missing.

## How it is put together

| Path | What lives there |
|------|------------------|
| `spec/` | The bundle format, and the test vectors that pin it |
| `verifier/` | The independent verifier, in Rust |
| `core/` | The evidence producer, in Python over PARI/GP |
| `core/policy/` | The policy engine and the shipped policies |
| `web/` | The viewer: one page, no server |
| `tools/` | Everything runnable |

The producer is Python and the verifier is Rust, deliberately. Two
implementations written from one specification disagree in ways a single
implementation cannot, and that disagreement is the point. The policy
engine exists twice for the same reason — once in Python, once in
JavaScript for the viewer — and a test compares their verdicts.

Heavy computation happens behind a process boundary: PARI runs as a
subprocess whose output is parsed strictly and never believed. What it
returns is a candidate, and the certificate carries the argument that
makes it a fact.

Certificates are canonical: two machines building the same curve produce
identical bytes, which is what makes addressing them by hash meaningful.
Continuous integration rebuilds the corpus on every commit and compares it
byte for byte with what is published.

## What this does not do

It does not prove curves safe. It proves specific statements and lets
policies argue about them.

It does not yet cover twist security, and the shipped SafeCurves policy
shows that gap honestly rather than passing over it.

It cannot prove the absence of a seed. secp256k1 has no published
derivation, and no certificate can establish that none exists — that is a
claim about the literature, not about numbers. The bundle stays silent and
the criterion stays undecided.

The seed check shows that parameters follow from a seed. Where the seed
itself came from is a separate question, and a seed can be searched for.

## Licence

Apache-2.0. PARI/GP is invoked as a separate process, not linked, so its
GPL does not reach this code; see `NOTICE` for what changes if you
distribute PARI binaries alongside a build.
