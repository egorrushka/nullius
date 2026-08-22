# Design notes

## Why a certificate and not just a table

A table of curve properties requires trusting whoever computed it.
A certificate moves the trust into a small program the reader can
audit. The asymmetry is the whole point: producing evidence is
expensive, checking it is cheap.

## Why the verifier is a separate language

Producer and verifier sharing an implementation means a bug can cancel
itself out. Producer is Python over PARI/GP; verifier is Rust with a
pure-Rust bignum. A disagreement between them is a signal, not noise.

## Why heavy work sits behind a process boundary

Same reason as the kangaroo host: kernels are fast, replaceable and
untrusted. `gp.exe` is a subprocess whose output is parsed and
re-checked, never believed.

## Why workers need not be trusted

Every farm result carries evidence. The coordinator checks it and drops
what fails. No replication, no voting, no reputation system.

## Open risk

A wrong certificate is worse than no certificate. Differential testing
against known values for well-studied curves belongs in CI from day one,
before any new curve is certified.

## Reproducibility envelope

Content addressing only means something if two independent builds produce
the same bytes. That property is not free, and it is not entirely ours:
part of every certificate is decided by PARI.

What the bytes depend on:

- **The producer's own choices.** Which point the witness search picks,
  the order factors are written in, the shape of every payload. All of
  this is deterministic by construction and ours to keep that way.
- **The Atkin-Morain chains PARI returns.** These go into the bundle
  verbatim, and nothing documents that `primecert` is stable across PARI
  versions. Two versions have been checked and agree — 2.15.4 on Linux
  and 2.17.4 on Windows — but that is an observation, not a guarantee.
- **Nothing else.** No timings, no paths, no locale, no machine word size.

The rule that follows: a PARI version enters the supported set only after
the full corpus has been rebuilt with it and compared byte for byte
against the published vectors.

CI runs the corpus on two runners carrying different PARI versions, each
comparing against the published vector. Comparing against the vector
rather than against the other job is deliberate and sufficient: the
vector is fixed in the repository, so a drift in either version fails
that job, and a drift that moved both alike fails both. There is nothing
a cross-job comparison would catch that this does not.

**Versions checked so far.** PARI/GP 2.15.4 on Linux and 2.17.4 on
Windows, on the prime-field and BLS12/BN curves. The degree-4 curves —
BLS24-315 and BLS24-509 — were produced under 2.15.4 only, and their
cross-version confirmation is pending rather than established. That
distinction is worth keeping: "reproduces across two versions" and "was
built once and nobody has contradicted it" are different claims, and only
the first is evidence.

The same check happens in development, informally but continuously. The
corpus is rebuilt on Linux under one PARI and on Windows under another,
and the digests are compared by hand each time. Two platforms and two
versions agreeing on every byte is a stronger signal than either CI job,
and it is how the first cross-version confirmation was obtained.

If a future version does change the chains, the certificates stay valid —
a chain is checked on its own merits, not against a reference — but their
digests move, and everything addressing them by hash breaks. That is a
release event, not a bug to be patched quietly.

The long-term answer is a deterministic chain generator of our own, which
would remove the dependency entirely. It is expensive and not scheduled;
noting it here so the decision is visible rather than implied.
