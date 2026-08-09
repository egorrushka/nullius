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
