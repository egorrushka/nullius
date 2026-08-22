# Roadmap

Status is marked against what is in the tree, not against what was
intended. A phase is done only when something a reader can run
demonstrates it.

- **Phase 0 — done.** Format drafted, verifier covers fifteen evidence
  kinds, and the negative corpus stands at 44 vectors the verifier must
  reject, each checked to be refused for the reason it claims.
- **Phase 1 — done.** Full tier-A dossiers exist for eight curves, and the
  accepted values for secp256k1, P-256 and Curve25519 reproduce.
- **Phase 2 — done.** The corpus runs as a batch and ships as a
  single-file browser page that re-checks each certificate rather than
  displaying it; the page's verifier is tied to the tree's sources by a
  stamp the release refuses to assemble without.
- **Phase 3 — partial.** `param.rigidity` re-derives a curve's `b` from
  its seed and P-256 carries it. The degrees-of-freedom metric is not
  built.
- **Phase 4 — not started.** Distributed farm with untrusted workers.
- **Phase 5 — partial.** The web frontend exists (Phase 2); the
  append-only registry does not.

## The degree-3 and degree-4 ceiling, and how it was cleared

This section used to describe a wall. It is kept as a record of the wall
and how it fell, because a roadmap that silently drops a blocker leaves
the next person unable to tell a solved problem from a forgotten one.

**The wall.** Curves whose second group lives over `F_p^4` — BLS24, and
with it the 192-bit level — were not reachable by a witness argument, and
the obstacle was arithmetic rather than effort. `proof.point-order` needs
the factorisation of a group order to establish a witness's exact order.
For BLS24-315 the G2 cofactor is 1005 bits and its unfactored part is 983
bits after trial division; the record for factoring general numbers of
that shape is 829 bits, at thousands of core-years. Building tower field
arithmetic first would have arrived at this wall with the work spent.

**How it fell.** Invert the argument. A group order annihilates every
point, so rather than prove one point's exact order, use points to
*eliminate* candidate orders. `derive.twist-class` already enumerates the
six orders a sextic twist can have, from the trace alone by the Weil
recurrence and with no factorisation. Multiply a point by each; discard
every candidate that does not send it to the identity; the true order is
never discarded, so if one survives it is the order — provably, by
Lagrange and uniqueness. This is `derive.order-elimination`, and it needs
no factorisation, works at any degree, and produces smaller certificates
than the witness argument it replaces for the second group.

**What it cost to do safely.** The inversion has a sharp edge, found in
review: a group order annihilates every point *on every curve*, so an
elimination run on the wrong curve settles a real number that is not the
second group's order. The curve in the evidence therefore had to be tied
to the subject — established, not assumed — by checking `a' = 0` on it and
`a = 0` on the subject over a field with `q = 1 mod 3`, which makes it one
of the six sextic twists, and then a census on `r` to say which of the
six carries the second group. A second door into the same room,
`proof.point-order` accepting a G2 order at degree 2 with no binding at
all, was closed by confining that evidence kind to the base field. The
worked answers to the review's open questions are in
`docs/OPEN_QUESTION_high_degree_extensions.md`, now an answered document
rather than an open one.

**Where it stands.** BLS24-315 and BLS24-509 are certified, verify
cleanly under both implementations, and reach the 192-bit level on every
criterion except the embedding-field-size threshold under the
conservative worst-case model — which is a property of that model and the
curve, stated as such, not a limit of the format. The one thing still
absent is cross-version reproducibility for the two degree-4 curves; see
the reproducibility envelope in `docs/DESIGN.md`.
