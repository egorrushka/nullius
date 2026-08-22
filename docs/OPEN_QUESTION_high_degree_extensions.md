# Group orders over high-degree extensions — the question, answered

Written after the first review round as an open question with a proposed
fix its author had not had reviewed. It is kept, and answered inline,
because the fix was built and the reasoning that made it safe is worth
having next to the reasoning that motivated it. Where the original asked
something, the answer follows it rather than replacing it.

## The blocker it opened with

Fields of degree 4 are what BLS24 needs, and with them the 192-bit level.
The infrastructure — a tower `F_p^4 = F_p^2[v]/(v^2 - xi)`, mirrored in
Rust, the evidence extended to more degrees — was a known quantity. The
blocker was not the infrastructure.

`proof.point-order` proves a group order by exhibiting a point whose
*exact* order exceeds the Hasse window, and proving an exact order needs
the group order's factorisation. For BLS24-315:

| quantity | size |
| --- | --- |
| `p` | 315 bits |
| `r` | 253 bits |
| `#E'` over `F_p^4` | 1258 bits |
| Hasse window over `F_p^4` | about `2^631` |
| G2 cofactor | 1005 bits |
| **cofactor after removing small factors** | **983 bits, composite** |

Factoring a 983-bit general composite is out of reach: the record for
numbers of that shape is 829 bits, at thousands of core-years. The
subgroup order `r` at 253 bits is far below the 631-bit window, so it
pins nothing on its own. The ceiling was arithmetic, not engineering.

## The way past it, now built

Invert the argument. A group order annihilates every point, so instead of
proving one point's exact order, use points to *eliminate* candidates:

1. `derive.twist-class` enumerates the six orders a sextic twist can have,
   from the trace alone by the Weil recurrence and by exact arithmetic.
   No factorisation.
2. Take a point on the curve. Multiply it by each of the six. Any
   candidate that does not send it to the identity cannot be the order.
3. If exactly one survives, that is the order — provably: the true order
   is among the survivors by Lagrange, and uniqueness closes it.

This is `derive.order-elimination`. It needs no factorisation, works at
any degree, needs no witness search, and makes smaller certificates. The
ceiling is gone.

## The questions it raised, answered

**1. Is the elimination argument sound as stated?** Yes, and with one
condition the original glossed. It rests on Lagrange plus the claim that
the true order is among the six enumerated, and the second holds *only
when the curve really is a sextic twist of the subject*. That is not a
property of the argument; it is a property of the curve handed to it. A
group order annihilates every point on *every* curve, so an elimination
run on the wrong curve settles a real number that is simply not the
second group's order. Nothing is smuggled in by "exactly one survives" —
what had to be added is a check that the curve is the right one:
`a' = 0` on it and `a = 0` on the subject over a field with `q = 1 mod 3`
make it one of the six twists, and a census on `r` says which of the six
carries the subgroup. Both are in the verifier. Without them the argument
is a true statement with a false conclusion, and a reviewer demonstrated
exactly that — a run on the subject's own curve over `F_p^2`, two
honestly found points, one survivor, and it was the wrong group.

**2. What if more than one survives — is there a curve where no point
ever decides?** This is the question the original said deserved a worked
answer rather than a reassurance, so here is the worked answer. A
candidate `d ≠ c` survives a point `P` exactly when `ord(P) | d`. No point
distinguishes `c` from another candidate `d` when the group's exponent
divides `gcd(c, d)`, and since `gcd(c, d) | c − d` and all six lie in the
Hasse window, `|c − d| ≤ 4√q`. So an undecidable curve needs an exponent
of at most `4√q` while its order is about `q` — a group close to
`Z/m × Z/m` with `m ≈ √q`, i.e. nearly full two-dimensional torsion. The
clean representative is a supersingular curve over an even-degree
extension, `#E = (√q ± 1)^2` with exponent `√q ± 1` — and that class is
**already refused** upstream, at the `v = 0` check in the enumeration
(`t2 = ±2√q` gives `4q − t2^2 = 0`). For an ordinary curve it would take
an anomalously large square factor of the order; possible in principle,
and safe in practice, because the response is a refusal, not a wrong
answer: more than one survivor means the producer declines and the
verifier would too. Liveness can fail here; soundness cannot.

**3. A third evidence kind, or a replacement?** A replacement, in effect,
scoped by group. `derive.order-elimination` settles the *second* group at
every degree, so the degree-2 branch of `proof.point-order` — which
proved a G2 order while tying its curve to nothing — was removed, and that
evidence kind is now confined to the base field and the subject's own
curve. `check.order-unique` and `proof.point-order` remain for the first
group, where a witness's order can be proved and the factorisation it
needs is affordable. So the format did not grow a third overlapping
argument; it moved the G2 case onto the one that has no ceiling. The
prefix `derive.` names what the evidence does, not its tier; the spec now
says so, since `derive.order-elimination` and `derive.twist-class` are
tier A while `derive.twist-sum` is D.

**4. Does the inversion help on the prime field?** No, and the reason is
structural rather than incidental. Over `F_p` the candidate orders are not
six enumerable numbers but the whole Hasse window, so there is nothing to
eliminate against. The first group keeps `check.order-unique` and
`proof.point-order`, which is where the affordable factorisation lives.

**5. Is the Weil recurrence the better route?** It is not an alternative
to the elimination; it is a part of it. `t_n = t·t_{n-1} − p·t_{n-2}`
gives the trace over any extension from the trace over `F_p` by exact
integer arithmetic, and that is exactly how the six candidates are
enumerated — one implementation of it, in `core/claims/twist.py`, mirrored
in the verifier. The recurrence gives the trace; it does not say which
twist G2 sits on; the census on `r` does. The combination the question
guessed might be cleaner than either alone is the thing that was built.

## Status in the tree

Everything in this document is built. The tower field `F_p^4` exists in
both languages, `derive.order-elimination` is a proved-tier evidence kind
with its binding to the subject checked, `g2.twist` names the class at
degree 4 as well as degree 2, and BLS24-315 and BLS24-509 are certified
and verify cleanly. The negative corpus carries the base-curve forgery
from question 1 as a vector, refused for the reason it documents.

What remains open is narrow and recorded where it belongs: cross-version
reproducibility for the two degree-4 curves is pending rather than
established (`docs/DESIGN.md`), and the sextic-twist *class label* is a
degree-2 and degree-4 fact only because those are the extensions the
format reaches. Neither is the ceiling this document was written about.
That ceiling is down.
