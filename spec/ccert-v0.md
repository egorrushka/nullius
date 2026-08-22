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

**The prefix does not encode the tier, and a reader must not read it as
though it did.** Three kinds begin `derive.`; two of them are tier A and
one is tier D. The prefix says what the evidence *does* — derive a value
from other claims rather than exhibit a witness for it — and that is a
different question from how much the result is worth. `derive.twist-sum`
re-derives an identity and inherits whatever its inputs are worth, so it
is D. `derive.twist-class` and `derive.order-elimination` derive a value
too, but by arithmetic that settles it outright, so they are A.

The names could be made to line up by renaming one kind. They are not,
deliberately: renaming an evidence type changes the bytes of every
certificate that carries it, and tidier names are not a reason to move
published digests. The table above is where the tier is answered, and it
is the only place — which is the rule that made the prefix ambiguous
survivable in the first place.

| Evidence type                | Tier | What it actually is                          |
|------------------------------|------|----------------------------------------------|
| `candidate.pseudoprime`      | X    | a screening test said probably prime         |
| `candidate.sea`              | X    | a program returned a number                  |
| `proof.ecpp`                 | A    | an Atkin-Morain chain, re-checked step by step |
| `proof.multiplicative-order` | A    | the exact order of an element, from a proved factorisation |
| `proof.cm-discriminant`      | A    | the CM discriminant, with the factorisation showing it fundamental |
| `proof.point-order`          | A    | a point whose exact order leaves the Hasse window one candidate |
| `check.seed-derivation`      | A    | the published derivation, rerun               |
| `check.hasse`                | A    | bound re-derived from p and n by integers    |
| `check.order-unique`         | A    | a point of prime order n, with n above the Hasse window |
| `check.cofactor`             | A    | a group order split into a proved prime and a factored cofactor |
| `check.family`               | A    | a curve regenerated from one parameter by its family's polynomials |
| `check.curve-model`          | A    | Weierstrass coefficients recomputed from a Montgomery or Edwards equation |
| `derive.order-elimination`   | A    | a group order left standing when points rule out every other candidate |
| `derive.twist-class`         | A    | an order shown to be one of the six a sextic twist can have |
| `derive.twist-sum`           | D    | `#E + #E' = 2p + 2`                          |

## Fields beyond the prime case

A subject over a prime field remains the common case, but a
pairing-friendly curve needs a second group over `F_p[u]/(u^2 - beta)` or
over a tower above it. That group's order is settled by
`derive.order-elimination`, which is the only evidence kind that works
over an extension; `proof.point-order` is confined to the base field and
to the subject's own curve. Two rules keep the degrees from becoming two
formats.

**Degree is stated, never inferred.** Evidence carries `field.degree` as
`"1"`, `"2"` or `"4"`. At degree 2 it also carries `beta`, and a verifier must
refuse a `beta` that is a quadratic residue: the quotient would then have
zero divisors and every conclusion drawn from it is void. At degree 1
`beta` must be absent, not zero.

**Field elements are coefficient lists**, low order first, of length
exactly equal to the degree. `["4","4"]` is `4 + 4u`; `["7"]` is `7`. A
list of the wrong length is an error rather than something to pad or
truncate, because a padded list would silently describe a different point.

The Hasse window follows the degree. Over `F_p^2` the field has `p^2`
elements and the square root of that is `p` exactly, so the bound
`q + 1 -+ 2p` is tight; the same holds at degree 4, where `sqrt(p^4)` is
`p^2`. Over `F_p` it is not, and the integer square root must be widened
by one on each side. Widening is the safe direction: a
window one wider can only fail to pin an order, never pin a wrong one.

## Why two ways to prove a group order over the base field

`check.order-unique` exhibits a point of prime order `n` and observes that
the window admits no other multiple of `n`. It is small and it is enough
whenever the cofactor is one.

It cannot reach a group whose cofactor is large. Curve25519's cofactor is
8 and BLS12-381's is 126 bits: many multiples of the subgroup order fit
the window, so a point of order `r` pins nothing at all.

`proof.point-order` answers this not with a weaker claim but with a bigger
witness. It carries a point whose **exact** order exceeds the window,
together with the factorisation that establishes that order, and the
window then admits exactly one multiple. The argument is the same shape;
only the witness is larger.

Both are confined to `curve.cardinality`, over the base field, on the
subject's own curve — the evidence names `a` and `b`, and a verifier
refuses them if they are not the subject's. Group orders over an
extension are settled only by `derive.order-elimination`, described
below. There was a second route once: `proof.point-order` accepted
`g2.cardinality` over `F_p^2` and tied the curve in its evidence to
nothing, saying so in its note. A note is not a check, and once
elimination began binding its own curve to the subject that route was
simply the way round the binding. It is gone rather than annotated.

A verifier re-establishes it in five steps, in this order:

1. the field is a field, and its characteristic is the one the subject names;
2. the curve is non-singular and the witness lies on it;
3. every factor is prime, by chain or by the deterministic base set, and
   the factors multiply to the order claimed for the witness;
4. that order takes the witness to the identity, and no proper divisor of
   it does, so the order is exact rather than a multiple;
5. the window admits exactly one multiple of that order, and it is the
   number the claim asserts.

Step 5 is where the argument closes and where a small witness fails.
**A witness that does not pin the order must be refused loudly.** Choosing
the nearest admissible multiple would produce output indistinguishable
from a real proof and mean nothing.

`check.cofactor` then splits a proved group order into a subgroup order
and a cofactor. It is exact integer arithmetic the verifier redoes, which
is why it sits at tier A alongside `check.hasse`. Three things are
required: the two numbers multiply to the group order; the subgroup order
is one already proved prime elsewhere in the same bundle; and the cofactor
arrives with a factorisation that multiplies back and whose factors are
themselves proved prime. The last is not decoration. A subgroup-security
policy reads the largest prime factor of the cofactor, and an unchecked
split would be an assertion wearing the clothes of proof.

## Claim types

| Claim                  | Asserts                        | Usual evidence               |
|------------------------|--------------------------------|------------------------------|
| `field.characteristic` | `p` is prime                   | `proof.ecpp`                 |
| `curve.cardinality`    | the curve has `n` points       | `proof.point-order`          |
| `curve.order.prime`    | the subgroup order is prime    | `proof.ecpp`                 |
| `curve.order`          | subgroup order and cofactor    | `check.order-unique`, `check.cofactor` |
| `curve.hasse`          | `n` lies in the Hasse window   | `check.hasse`                |
| `curve.embedding`      | the embedding degree           | `proof.multiplicative-order` |
| `curve.cm`             | the CM discriminant            | `proof.cm-discriminant`      |
| `param.rigidity`       | parameters follow from a seed  | `check.seed-derivation`      |
| `twist.cardinality`    | the order of the quadratic twist | `derive.twist-sum`         |
| `g2.cardinality`       | the order of the twist carrying G2 | `derive.order-elimination` |
| `g2.order`             | its subgroup order and cofactor | `check.cofactor`            |
| `curve.family`         | the family and its parameter   | `check.family`               |
| `curve.model`          | the model a curve is published in | `check.curve-model`       |
| `g2.twist`             | the twist relation, its class and the degree indexed | `derive.twist-class` |

Two assertions are optional and re-established when present rather than
taken: `curve.embedding` may carry `two_adicity`, the exponent of two in
`n - 1`, recomputed from the factorisation the order argument already
proves complete; and `curve.order` carries `largest_prime_factor` of its
cofactor, recomputed from the factorisation beside it. Both exist because
a policy reads what a claim asserts and nothing else, so a fact a policy
needs has to be stated where a policy can see it.

One correction worth recording, since it is the kind that hides for
years. Several handlers read `curve.order` where they meant the number of
points on the curve. On a curve with cofactor one those are the same
number; on a pairing-friendly curve the cofactor is 126 bits wide, and a
CM trace computed from the subgroup order is a trace for no curve at all.
Handlers now read `curve.cardinality` when a bundle states it, and a
`curve.cardinality` that is present but not proved is a refusal rather
than a reason to fall back.

A claim names its evidence by type, and the tier follows from that type
alone. The pairing above is what producers currently emit, not a
constraint: any evidence type that establishes the claim may be used, and
the tier follows the evidence rather than the claim.

## Curves published in another model

Curve25519 is a Montgomery curve and Ed25519 a twisted Edwards one. Every
other claim in this format is about a short Weierstrass equation, and
converting quietly would produce a document whose subject is a curve
nobody uses under a name everybody recognises.

So the subject keeps its Weierstrass coefficients, and `curve.model`
carries the equation people actually cite along with the parameters that
generate those coefficients. A verifier recomputes the first from the
second:

    Montgomery       B y^2 = x^3 + A x^2 + x
                     a = (3 - A^2) / (3B^2), b = (2A^3 - 9A) / (27B^3)

    twisted Edwards  a x^2 + y^2 = 1 + d x^2 y^2
                     A = 2(a + d)/(a - d), B = 4/(a - d), then as above

**What this establishes** is that those coefficients follow from those
parameters, by exact arithmetic in the field.

**What it does not** is the birational equivalence itself. That the map
takes points of one curve to points of the other is a theorem about the
shapes, not a fact about these numbers, and this format carries no proofs
of theorems — a reader takes it from the literature the way they take the
Hasse bound. The distinction matters because the two groups are
isomorphic only up to a handful of exceptional points, and cofactors are
exactly where that shows. The verifier says as much in its own output.

The list of models is closed, for the same reason the family list is: a
model nobody can convert is not a claim. A degenerate parameter is a
refusal rather than an awkward case: `A^2 = 4` means the cubic has a
repeated root and there is no curve, and `a = d` means the same for an
Edwards curve.

Ed25519's Montgomery form has `B = 4/(a - d)` rather than 1, so it yields
different Weierstrass coefficients from Curve25519 for an isomorphic
curve. The ratio is a square, so the orders agree; both are certified
separately rather than one standing in for the other.

## Settling a group order over an extension

A witness argument would exhibit a point whose **exact** order exceeds the
Hasse window. Proving an exact order needs the group order's
factorisation, and that is a ceiling rather than an inconvenience:
BLS24-315's second group has a 1005-bit cofactor whose unfactored part is
983 bits, beyond anyone. The whole 192-bit level sits behind it, which is
why no witness argument is admitted over an extension at all.

`derive.order-elimination` turns the argument around. A group order
annihilates every point, so points cannot show which candidate is right
but can rule out those that are wrong. The sextic twist enumeration
already yields six candidates from the trace alone, with no factorisation.
Multiply a point by each and discard those that miss the identity; the
true order is never discarded. If exactly one survives, it is the order —
provably, since the truth is among the survivors and uniqueness closes it.

Five conditions, none of them decoration:

- **Every point in the evidence must eliminate at least one candidate.**
  Padding in an argument is where a reader stops reading, and a step that
  decides nothing is padding.

  This is a rule about the record, not about the search that produced it,
  and the two must not be confused. A producer walks abscissas in a fixed
  order and cannot know in advance which will decide anything; over `F_19`
  the curve `y^2 = x^3 + 17` yields points at abscissas 2 and 3 that rule
  nothing out before a later one closes the argument. A producer that
  stopped at the first would report no certificate for a curve that has
  one, and the evidence it would have written is identical either way. So
  a producer skips such points during the search and replays the ones it
  kept, exactly as a verifier will, before writing anything down.
- **The six must be pairwise distinct.** If two coincide, "exactly one
  survived" counts a set that was never six.
- **More than one survivor is a refusal**, not a choice, in the same way a
  Hasse window admitting two multiples is a refusal. Output
  indistinguishable from a proof is worse than no output.
- **Extra points come in a fixed order**, because two builds must write
  the same bytes.
- **The producer multiplies the points itself**, so there is nothing taken
  on trust.

The evidence carries only the points that were actually needed. On all
four pairing curves in this corpus the first decides, and the
certificates are a quarter smaller than the witness argument made them.

Weil's recurrence `t_n = t·t_{n-1} - p·t_{n-2}` gives the trace over any
extension from the trace over `F_p` by exact integer arithmetic, which is
how the candidates are reached at degrees the witness argument cannot
serve. At degree 2 it collapses to `t^2 - 2p`, so the curves that already
worked are unaffected by the generalisation.

### What binds the curve to the subject

The conclusion `#E' = the survivor` follows from Lagrange, which needs no
checking, and from *the true order is among the six*, which needs a great
deal. The second premise is a property of the curve handed to the
argument, not of the argument. It is established, not assumed:

- the **subject** has `a = 0`, so it has sextic twists at all;
- `q = 1 mod 3`, so it has six of them rather than two;
- the **curve in the evidence** has `a' = 0` and is non-singular, so
  `b' != 0`. Over such a `q` every `y^2 = x^3 + b'` with `b' != 0` is one
  of the six sextic twists of `y^2 = x^3 + b`. That is the whole binding:
  no isogeny, no appeal to a standard, one comparison against zero.

**Two candidates can be divisible by the subgroup order, and only one is
the second group.** `r` divides `#E(F_p)`, which divides `#E(F_p^n)`, so
the subject's own curve over the extension is candidate 0 and `r` divides
it. It is not G2 — the pairing needs the eigenvalue-`p` subgroup, which
lives on the twist. A producer filtering on divisibility alone would
certify the wrong group with every step of the argument intact.

So a verifier takes a census. Exactly two candidates may be divisible by
`r`; index 0 must be one of them; and the survivor must be the other. The
six being pairwise distinct makes an order determine a twist class, so a
survivor equal to that candidate is the order of the twist carrying G2,
and the curve in the evidence is that twist up to `F_q`-isomorphism. Any
other census is a refusal: it means the enumeration did not single out one
group, and this format does not pick.

`g2.twist` reports which of the six the survivor is, at whichever degree
the claim names. It rests on this argument and says so: a verifier
refuses to classify an order that was not settled by the elimination,
because the class only means what it says when the curve underneath it is
tied to the subject.

The prose here once said instead that the elimination is run on the
twist, so the survivor is the twist's order by construction. That is true of an honest
producer and says nothing to a reader. A run on the subject's own curve
over `F_p^2`, with two points found by the same abscissa scan, met every
stated condition and settled candidate 0; `spec/vectors/invalid/`
carries it.

## Fields of degree four

`F_p^4` is written as a tower, `F_p^2[v]/(v^2 - xi)` over
`F_p^2 = F_p[u]/(u^2 - beta)`, and the evidence carries both parameters.
A payload that omits `xi` describes a field nobody can rebuild, and every
coefficient in it then means something else.

`xi` must be a non-residue **in `F_p^2`**, which is stricter than being
one in `F_p`; the criterion is `xi^((p^2-1)/2) != 1`. An element is
written as four integers in the order `(c0.c0, c0.c1, c1.c0, c1.c1)`, and
a second implementation has to agree with that flattening or read every
certificate wrongly while verifying happily.

The Hasse window is exact here as at degree 2: `sqrt(p^4)` is `p^2` on the
nose, so the bound `q + 1 -+ 2p^2` is tight with nothing widened. It is
also about `2^631` wide for a 315-bit characteristic, against a 253-bit
subgroup order — which is precisely why the witness argument is
unavailable at this degree and elimination is not.

One property is worth recording because it is a trap rather than a
subtlety: **every element of `F_p` is a square in `F_p^4`**. For `a` in
`F_p*`, `a^((p^4-1)/2) = (a^(p-1))^((p^3+p^2+p+1)/2)`, the exponent is a
whole number because four odd terms sum to an even one, and `a^(p-1)` is
one. Anything needing a non-residue must look in the field itself; a
search over the integers does not fail, it runs out.

## The twist relation

For a curve with `j = 0` the orders of its six sextic twists over `F_p^2`
are determined by the trace and by the `v` from `4q = t2^2 + 3v^2`. A
verifier enumerates all six and checks that the proved `g2.cardinality`
is among them, at the index the evidence names.

The enumeration order is part of the format, because the index is:

    0: q + 1 - t2        3: q + 1 + (t2 + 3v)/2
    1: q + 1 + t2        4: q + 1 - (t2 - 3v)/2
    2: q + 1 - (t2 + 3v)/2   5: q + 1 + (t2 - 3v)/2

`v` is determined only up to sign and the set of six does not depend on
the choice, but the indices do, so `v` is taken positive.

Every division and root involved is exact and checked. A floored square
root or a silent halving would build all six candidates on the wrong `v`,
and six wrong numbers still look like an argument.

## Generated curves

BLS12 and BN curves are not chosen but produced: one integer `u`
determines the characteristic, the subgroup order and the trace through
polynomials the family fixes. `check.family` states that parameter and a
verifier recomputes all three, comparing against claims already proved.

This is what `check.seed-derivation` is for a prime-field curve, and
pairing curves had no equivalent. Without it, "why these numbers and not
others" is answerable only by pointing at a standard; with it, the answer
is arithmetic — the numbers are what the family produces at this `u`, and
no freedom was left in which to hide anything.

The list of families is closed. A verifier that skipped families it did
not recognise would let a bundle assert membership in anything, so an
unknown name is a refusal.

Two details that are easy to get wrong, and are therefore stated. The
parameter may be negative — BLS12-381's is — so everything is signed
arithmetic, and the trace is compared as `p + 1 - #E` rather than by
subtracting unsigned values. And the BLS12 division by three must be
exact: a floor division there produces a number for a `u` that generates
nothing, and that number looks exactly like a characteristic.

## Vectors

`spec/vectors/valid/` holds certificates a verifier must accept, and
`spec/vectors/invalid/` holds ones it must refuse. The second directory is
the more useful of the two for anyone writing an implementation: accepting
a well-formed file is easy, and a verifier is worth something for what it
turns away.

Each invalid vector ships with the substring its refusal must contain. A
refusal that arrives from somewhere else — a malformed-input check firing
before the argument under test is reached — counts as a failure, because
it leaves that argument untested while looking like a pass.

## Machine output

Both programs take `--json` and write a verdict a caller can act on
without parsing prose. The shape is fixed and versioned separately from
the bundle format, since one may change without the other.

The verifier writes `{bundle, digest, subject, outcomes[{claim, tier,
note}], proved, derived, unproved, result}` on acceptance, and `{bundle,
reason, result}` on refusal. A refusal carries its reason because an exit
code alone tells an automated caller nothing about which claim went
wrong.

The policy engine writes `{bundle_digest, policy{name, source},
outcomes[{id, status, detail, model?}], result}`. The digest is not
optional: a verdict is about a particular set of bytes, and one quoted
without them is an opinion about a curve rather than a statement about a
document. `model` appears on exactly those criteria whose threshold came
from an estimate, so a consumer can tell which lines may move without any
fact moving.

`--corpus DIR --json` gives the whole matrix in one pass: every bundle
against every policy, each with the bundle's digest. Without it a caller
runs the engine once per pair, which for eight curves and seven policies
is fifty-six invocations to learn what one already knows.

Both writers sort their keys and emit no floating point, so the output is
reproducible byte for byte and a consumer may pin a hash of it.

The subject states `optional_steps`: a sorted list of the optional work
that was **done**, not skipped. Two producers who chose differently write
honestly different certificates, and a reader can tell "the twist was not
factored" from "there is no twist claim for another reason" instead of
inferring it from an absence. The dependency of the bytes on the
producer's choice does not disappear; it becomes visible, which is the
point.

Two steps in the producer are optional, and their absence is honest
rather than silent. `--skip-twist` omits the quadratic twist claim, whose
cost is factoring a number around 2p. `--skip-cm` omits the CM
discriminant, whose cost is factoring a number as large as the
discriminant — for Curve25519 that runs to minutes, and it is the one
step whose cost is not bounded by the size of the curve. In both cases
the claim is absent rather than weakened, so a policy asking about it
returns undecided, which blocks a pass. A timeout must not quietly become
consent.

`--explain` prints, for each claim, the tree of what it rests on down to
the leaves. The edges come from the verification rather than from a second
reading of the file, so the tree describes the argument that was actually
checked.

It exists to make one property visible. A proved claim may not rest on
anything below proved, and a derived one may not rest on a bare candidate,
so **a tier is a statement about everything beneath a claim rather than a
label on the claim alone**. Read a tree to its leaves and the tier at the
top is the weakest thing in it. The verifier computes that floor and would
say so if it ever disagreed with the tier above — a line that cannot
appear on a bundle it accepted, which is the point of computing it.

Two flags govern how demanding the verifier is. `--require-proved` fails
when any claim is a bare candidate. `--strict` fails when any claim is
below proved at all, derived included. Both readings are defensible: a
derived claim stands on proof, because the verifier has already refused
any bundle where one rests on something unproved — and a caller entitled
to demand that everything stand on its own should not have to argue the
point.

## Canonical form, and why there is no re-encoding mode

A document has one spelling, and the reader is what enforces it. The
parser refuses whitespace, unsorted keys, duplicate keys, numbers,
non-minimal escapes, a byte order mark and trailing bytes. Every one of
those is a document two implementations might have read differently,
which is the situation content addressing exists to prevent.

**There is deliberately no `--canonical-check` that re-encodes and
compares.** It would be weaker, not stronger. Re-encoding needs a writer
inside the verifier, and the reader is built so that a value is hashed
from the bytes it was parsed from rather than from anything re-serialised
— precisely so that a disagreement between a writer and a reader cannot
hide. Adding a writer to check canonicality would introduce the one
disagreement the design removes.

**Every level of the document has a closed set of keys.** The bundle, a
claim, its evidence reference, the subject and its field, each evidence
payload, and the objects nested inside a payload: a chain step, a factor
entry, a point, a curve, a field. An unknown key is a refusal.

Three reasons, in increasing weight. A field that decides nothing is
padding in an argument, which this format refuses everywhere else. A
field nothing checks is a sentence addressed to a human reader with no
verifier behind it, and certificates are read and diffed by people. And a
key accepted today and read tomorrow changes the meaning of documents
that already verified — silently, because the bytes never moved, which is
the one failure content addressing cannot catch.

## What is deliberately absent

**Timings.** A wall-clock measurement would make the same certificate hash
differently on a fast machine and a slow one, destroying the property that
two independent runs produce identical bytes. Timings belong in a run log
beside the file.

**The twist relation is no longer among the absences, and neither is its
label.** Both were, and this entry said so twice over. The relation went
first: `derive.order-elimination` establishes that the curve in the G2
evidence is the sextic twist carrying the subgroup, by checking `a' = 0`
on that curve and `a = 0` on the subject with `q = 1 mod 3` — which makes
it one of the six — and then by the census on `r` that says which one.
The label followed: `g2.twist` asserts the degree beside the class, so an
index names the set it indexes and a degree-4 bundle can carry the claim
instead of omitting it.

The entry is kept, emptied, because a reader who learned either limit
should be able to find out that it moved rather than wonder whether the
document merely stopped mentioning it.

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
- Answered for now: a criterion whose verdict rests on something outside
  the bundle carries a `model` block naming it, and the engine prints that
  name beside the verdict. Index-calculus cost in `F_p^12` is the first
  such case. Whether a policy should be *refused* when a threshold has no
  model behind it is still open, since the engine cannot tell which
  thresholds are estimates and which are theorems.
- Should the twist relation become a claim, and what evidence would
  establish it without the verifier having to compute an isogeny?
