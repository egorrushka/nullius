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

### The verifier binary

The paragraphs above are about the certificates. The verifier itself is a
compiled binary, and its reproducibility is a separate question with a
separate answer.

A release build of `ccert-verify.exe` is deterministic on Windows: two
builds from the same sources, on the pinned toolchain (Rust 1.95.0, set in
`rust-toolchain.toml`), produce the identical binary. Two sources of
nondeterminism were found and pinned — `-C codegen-units=1` for a stable
code-generation order, and the MSVC linker's `/Brepro` to zero the
timestamp it otherwise writes into the executable. The flags are set in
`tools/build_verifier.bat`, through the environment, deliberately: the same
flags placed in `.cargo/config.toml` did not reproduce, because cargo
merges a target's `rustflags` with the profile differently than a plain
`RUSTFLAGS` does — the environment channel is the one that holds, and it is
the channel the build script uses. Windows-only, so the Linux CI runners,
which link differently and do not know `/Brepro`, are untouched.

With those, the expected SHA-256 of the binary is:

```text
da7a789ba5cae4a0010d6763d4dc3a28fc6387b0b086a31cccdb35bca3beda42
```

The honest boundary. This is reproduction *on our build*: the same
toolchain, the same machine, the same path the tree sits at — the build
path is compiled into the binary, so a checkout at a different location
hashes differently even with everything else identical. It is enough to
catch a binary that changed when nothing should have, which is what a
release check needs. Path-independent, cross-machine reproduction — anyone
on 1.95.0 arriving at this same hash — is a stronger claim, would need the
build path remapped away and then confirmed across machines, and is not
made here.

Authenticity does not rest on this in any case. A downloaded release is
pinned by its signed `DIGESTS.txt` (see the project README), which attests
the exact bytes shipped, and the source stamp ties the browser module to
the verifier's sources. A byte-for-byte rebuild is a check the author can
run, not a chain of trust the reader depends on.

## Where verification time goes

Checking a prime-field certificate is well under a second; the pairing
curves cost more, and BLS24-509 is the extreme — about nine and a half
seconds. That number is worth breaking down rather than hiding, because it
says plainly what is expensive and why it is not being chased.

Measured on one run of BLS24-509:

```text
derive.order-elimination  g2.cardinality       5.1 s   ~54%
proof.point-order         curve.cardinality    1.9 s   ~20%
proof.ecpp                field.characteristic 1.2 s   ~12%
proof.ecpp                curve.order.prime    0.7 s    ~7%
derive.twist-sum          twist.cardinality    0.2 s    ~2%
everything else                              < 2 ms    ~0%
```

More than half is the order-elimination over `F_p^4`: multiplying points
through the tower field `fq4` builds on `fq2` builds on `fq`, and every
one of those multiplications is affine, with a modular reduction written
as `%` rather than Montgomery form. That is a deliberate choice the
arithmetic modules state in their own docstrings — a verifier is read
before it is trusted, and clarity there is worth more than speed.

So the cost is understood and accepted, not unexamined. Nine seconds to
re-check what took minutes to produce is the asymmetry working as
intended, on a document nobody re-checks in a loop. Faster tower
arithmetic — Montgomery reduction, fewer inversions — is possible, but it
would rewrite the part of the trusted base a reader most needs to follow,
to shave a wait that is already far below the build it verifies. It is not
scheduled, and this paragraph is here so that is a decision on the record
rather than an omission.
