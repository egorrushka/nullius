# Security model

This document states what you trust when you accept a Nullius certificate,
and what you do not. It is not the design rationale — that is
`docs/DESIGN.md` — and it is not a summary of the format — that is
`spec/ccert-v0.md`. It is the trust boundary, drawn once and precisely: the
small thing you must believe, the large things you need not, the guarantees
that follow, and the things the verifier deliberately does not prove. Each
guarantee and each non-goal names the mechanism that holds it and, where one
exists, the negative vector that fails if it ever stops holding. A guarantee
you cannot see fail is a guarantee you cannot check, and this project exists
to be checked.

## What you trust — the TCB

Two things, and nothing else:

- **The Rust verifier** (`verifier/src/`). It re-establishes every claim
  from the certificate alone, with its own integer and field arithmetic. It
  calls no oracle, reads no clock, and reaches no network. It is kept small
  enough to read, because the thing you must trust to trust the result is the
  thing you should be able to audit in an afternoon.
- **The format semantics** (`spec/ccert-v0.md`). What the bytes mean — which
  claim types exist, what evidence establishes what, how a claim's tier is
  resolved, what canonical form is. The verifier enforces these semantics;
  the spec is the statement of them.

Nothing else is in the trusted base. Not PARI, not the producer, not the
certificate as delivered, not the machine that wrote it. If the verifier and
the spec are correct, a certificate that verifies is sound regardless of how
it was made.

## What you do not trust — and why it does not matter

Everything that produces a certificate is untrusted, because everything it
produces is re-checked:

- **PARI/GP.** The producer's number theory runs on PARI. The verifier
  believes none of it: ECPP primality chains are re-walked step by step,
  factorisations re-multiplied, orders re-derived. PARI is a convenience for
  the producer, never an authority for the verifier.
- **The Python producer.** It is a second, independent implementation of the
  same format, and disagreement between the two is a signal rather than
  noise. Where a rule lives in both — the tier table, the required
  dependencies, the `asserts` keys, the claim scope — the Rust copy is
  authoritative and a mirror test compares the two *arm for arm*. That
  qualifier is load-bearing: an earlier mirror test asked only whether each
  dependency name appeared *somewhere* in the Rust table, and `curve.order`
  was missing from the one arm that needed it while present in four others,
  so the test passed over a real gap. It now compares matching arms, which is
  why the mirror can be trusted rather than merely consulted.
- **The certificate bytes.** The file is content-addressed: its name is the
  SHA-256 of its canonical bytes, and the verifier hashes the raw bytes it
  was handed rather than a re-encoding of them. A non-canonical document is
  refused, not repaired.
- **Every external input, including the subject.** The curve the whole bundle
  is named after is re-checked like anything else — prime field, reduced
  coefficients, non-singular — because it is the one omission that would have
  been invisible: every evidence handler checks the curve *it* was handed,
  and until this check nothing checked the one they all refer to.

Trust rests on the verifier, not on the producer. That inversion is the whole
architecture.

## How to read the guarantees below

Three things frame every guarantee, and getting them wrong misreads all four:

- **A guarantee is about refusal, not about truth.** Each says the verifier
  will not *accept* a certain kind of false certificate — not that some
  statement about the world is true. You can hand it a certificate that
  attempts the thing and watch it be refused; the named vector does exactly
  that. This is what makes the guarantees falsifiable rather than reassuring.
- **Soundness is guaranteed; liveness is not.** A certificate the verifier
  cannot check is refused, never accepted with a guess. "Not proved" is the
  verifier declining to assert, and it is not "false." The elimination
  argument below is the clean case: faced with two surviving candidates it
  refuses rather than pick, so it can fail to produce a verdict but cannot
  produce a wrong one.
- **Rust is the truth; Python mirrors it.** Stated above, repeated because the
  guarantees lean on it: every table that decides an outcome exists
  authoritatively in the verifier, and the producer's copy is checked against
  it, not the other way round.

## The guarantees — what a malicious certificate provably cannot do

### 1. Proved means proved, all the way down

A claim marked proved does not rest, at any depth, on anything the verifier
has not itself established. One invariant, held by three mechanisms:

- **Tier follows the evidence, not the producer's word.** A claim's tier —
  proved, derived, or candidate — is resolved from its evidence kind through a
  table the verifier holds (`tier_of` in `verifier/src/verify.rs`), mirrored
  by `EVIDENCE_TIERS` in `core/bundle/model.py`. The claim name does not
  encode the tier and a reader must not read it as if it did: three kinds
  begin `derive.`, two of them tier A and one tier D. A bundle cannot label
  its own output proved.
- **A dependency that is read must be declared.** A handler that reads another
  claim rests on it whether or not an edge says so, so the edges the handlers
  actually need are required — `required_deps` in the verifier, `REQUIRED_DEPS`
  in the producer — and a bundle that omits one is refused before any
  arithmetic runs, with the message *rests on … and must declare it*. Absence
  of a declaration was exactly how a handler once read another claim with
  nothing checking what it read.
- **A declared dependency must be at least as strong as the claim on it.** A
  proved claim leaning on a candidate is a false certificate with extra steps;
  a derived one leaning on a candidate quietly inherits its emptiness. The
  gate refuses both, with the message *… is proved but depends on … which is
  only candidate*.

Together these close the certificate under support: the set of proved claims
has an entirely proved transitive closure.

*Fails visibly if it ever stops holding:* `undeclared-dependency` — a
cofactor split that does not declare what it rests on, refused with "must
declare" — and `unproved-characteristic` — a proved cardinality resting on a
characteristic backed only by a pseudoprimality candidate, refused with
"candidate." The sibling `candidate-source` shows the same gate catching a
subtler composition: an exact, honest cofactor split of a number nobody
proved.

### 2. One curve's evidence cannot be passed off as another curve's subject

The order of the second group — the one carrying G2 over an extension — is
settled only by `derive.order-elimination`, and that evidence kind may support
only `g2.cardinality` (`CLAIM_SCOPE` in the producer, enforced in the handler;
the degree-2 route through `proof.point-order`, which proved a G2 order while
binding its curve to nothing, was removed). The argument is sound only when
the curve it runs on really is a sextic twist of the subject, and that premise
is a property of the curve handed to it, not of the argument — so it is
checked, in `verifier/src/elimination.rs`:

- the subject has `a = 0`, so it has sextic twists at all;
- the evidence curve has `a' = 0` and is non-singular, so `b' ≠ 0`, which over
  a field with `q ≡ 1 mod 3` makes it one of the six sextic twists of the
  subject — one comparison against zero, no isogeny, no appeal to a standard;
- a census on the proved subgroup order `r`, run before any point is read,
  fixes candidate index 0 as the subject's own order over the extension and
  requires exactly one other candidate divisible by `r`, which is then the
  twist carrying G2.

An elimination that settles on index 0 — the subject's own curve over the
extension — is refused, *even when every arithmetic step is honest*: honest
points, one survivor, inside the Hasse window, and still the wrong group. This
is the forgery a reviewer built, and the reason liveness is not promised: more
than one survivor, or the wrong survivor, is a refusal, not a choice.

*Fails visibly if it ever stops holding:* `elimination-on-the-base-curve` —
the reviewer's mutation, refused with "own order over the extension." It is
the vector whose every stated condition is met and which is wrong only about
which curve it describes.

### 3. No field reaches a policy or a human reader unchecked

Every level of the document has a closed set of keys — the bundle's top level,
the subject, each claim, the evidence block, the evidence payload, and the
objects nested inside a payload. The rule is one method, `Node::closed_keys`
in `verifier/src/json.rs`, applied at every level rather than re-implemented
per caller, because a rule that lives next to one caller is a rule the next
caller forgets. The load-bearing level is `asserts`: it is the object a policy
reads directly and a person diffs, so a field there with nothing behind it
reaches both a machine verdict and a human reader. Its keys are closed per
claim type by `asserts_keys` in the verifier, mirrored by `ASSERTS_KEYS` in
the producer.

*Fails visibly if it ever stops holding:* `asserts-with-an-unread-field` — a
`"security_level": "192-bit"` placed inside `asserts`, read by nobody and
aimed at the reader who would believe it, refused with
``unknown field `security_level` ``. This was the one level the closed key
sets did not originally cover; a reviewer found it open and it was closed on
the side where truth lives.

### 4. Two readers cannot disagree about what the bytes say

The certificate is content-addressed, so one document must have one
serialisation or the addressing means nothing. The reader accepts only
canonical form and refuses anything a second implementation might read
differently: unsorted or duplicate object keys, whitespace between tokens,
JSON numbers (quantities are decimal strings), a byte-order mark, non-minimal
escapes, and trailing bytes after the document. There is deliberately **no
re-encoding mode** — a non-canonical file is refused, not normalised — so no
oracle quietly maps two spellings onto one. And because values are hashed from
their original byte spans rather than from a re-serialisation, a disagreement
between the project's own writer and reader cannot hide. The rules are in
`verifier/src/json.rs`; the normative statement is `spec/ccert-v0.md`, under
"Design rules" and "Encoding."

*Fails visibly if it ever stops holding:* `reordered-keys` — valid JSON whose
top-level keys are not sorted, refused with "out of order" — with
`trailing-bytes` and `whitespace` covering framing and exactness.

The rules are enumerated normatively in `canonical-encoding.md`, each with its refusal substring and vector.

## Reproducibility is not a security property here

Two runs of the producer on different PARI versions can emit byte-different
certificates for the same curve, because ECPP primality chains are not unique
and different versions choose different valid ones. This is not a hole, and no
guarantee above rests on it. The verifier re-checks each certificate from its
own bytes and never depends on which chain was chosen, so a certificate
*verifies from the file alone on any version*; content addressing then names
exactly the bytes that were verified. Byte-identical reproduction across
versions is a property of the *build*, pursued separately in v0.3.0's
reproducible-and-signed-builds work (`SPEC_v0.3.0.md`, item 4), and its
absence costs nothing to the soundness stated here.

## Non-goals — what the verifier does not prove

A serious reader checks the non-goals first, to see whether the guarantees
have been quietly overstated. They have not, and here is the boundary, drawn
as sharply as the guarantees. The verifier proves specific facts about a
curve's parameters. It does not:

### Certify that a curve is "safe"

"Safe" is a judgement, not a fact, and judgements are contested: secp256k1
fails SafeCurves on its small CM discriminant and is *required* by the GLV
endomorphism that same discriminant enables. The verifier therefore emits a
tier per claim — proved, derived, or not proved — and never a verdict. There
is no `safe` field in the format and no green/red output; the tier vocabulary
has no room for one (`spec/ccert-v0.md`, "What is deliberately absent"). Any
suitability verdict lives in a policy — data under `core/policy/policies/`
that a reader chooses and applies — not in the verifier, so that the tool
proving the facts is never also the one judging them.

### Prove that an implementation is free of side channels

The certificate is about the mathematics of the parameters. It never sees an
implementation, and it says nothing about constant-time execution, fault
resistance, or any property of code that uses the curve. That is a separate
discipline; a certificate full of proved claims is not a statement about the
software next to it. (A constant-time code generator is named out of scope in
`SPEC_v0.3.0.md` for the same reason: a different product with a different
liability.)

### Prove that no cryptanalytic attack exists

The claims are a fixed, enumerated set — primality, cardinality, subgroup
order, embedding degree, CM discriminant, twist orders, family and model
(`KNOWN_CLAIMS` in the verifier) — and the verifier establishes exactly those
and nothing beyond them. "This curve is unbroken" is not among the claims and
cannot be. A certificate is a record of specific proved properties, not a
warranty against the unknown.

### Prove that a curve fits an operational policy

Which properties a deployment demands — a minimum embedding degree, a
two-adicity target, a discriminant floor — is a policy question, and the
answer is a policy's verdict, not the verifier's. The verifier hands a policy
engine (`core/policy/`) a set of proved facts; whether those facts clear a
given bar is decided there. A claim the verifier did not prove is "not
proved," which a policy may weigh as it likes; the verifier itself never reads
it as pass or fail.

The discipline throughout is that the verifier under-claims: everything it
does not prove, it declines to assert, and this section is where those
declinations are named, so that a reader can confirm the tool has not claimed,
anywhere, more than it proves.
