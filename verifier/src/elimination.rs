//! A group order settled by eliminating candidates, not by proving one.
//!
//! `proof.point-order` needs the factorisation of a group order to
//! establish a witness's exact order, and that is a ceiling rather than
//! an inconvenience. BLS24-315's second group has a 1005-bit cofactor
//! whose unfactored part is 983 bits; the record for numbers of that
//! shape is 829 bits at thousands of core-years. The whole 192-bit level
//! sits behind it.
//!
//! Turn the argument around. A group order annihilates **every** point,
//! so a point cannot say which candidate is right but can rule out those
//! that are wrong. The sextic twist enumeration gives six candidates from
//! the trace alone, with no factorisation anywhere. Multiply a point by
//! each and discard those that miss the identity; the true order is never
//! discarded, because it annihilates everything. One survivor is a proof.
//!
//! # What the conclusion rests on
//!
//! `#E' = the survivor` follows from Lagrange, which needs no checking,
//! and from *the true order is among the six*, which needs a great deal.
//! The second premise is not a property of the argument. It is a property
//! of the curve handed to it, and this file used to take it on the
//! producer's word: a run on the subject's own curve over `F_p^2`, with
//! two honestly found points and every stated condition met, singled out
//! candidate 0 and verified as the second group's order.
//!
//! So the premise is now established here, from the document:
//!
//! - the **subject** has `a = 0`, so it has sextic twists at all;
//! - `q = 1 mod 3`, so it has six of them rather than two — checked
//!   inside [`sextic_candidates`];
//! - the **curve in the evidence** has `a' = 0` and is non-singular, so
//!   `b' != 0`. Over such a `q` every `y^2 = x^3 + b'` with `b' != 0`
//!   *is* one of the six sextic twists of `y^2 = x^3 + b`. That is the
//!   entire binding: no isogeny, no appeal to a standard, one comparison
//!   against zero.
//!
//! # Which twist, not merely which order
//!
//! Two of the six can be divisible by `r`. One is the subject's own order
//! over the extension — `r` divides `#E(F_p)` which divides `#E(F_q)` —
//! and it is never the second group, because the pairing needs the
//! eigenvalue-`p` subgroup and that lives on the twist. A producer
//! filtering on divisibility alone would certify the wrong group with
//! every step intact.
//!
//! The census closes it. If exactly two candidates are divisible by `r`,
//! and index 0 is one of them, then the other is the only remaining class
//! that can carry an `r`-torsion subgroup; the six being pairwise
//! distinct makes the order determine the class. A survivor equal to that
//! candidate is therefore the order of the twist carrying G2, and the
//! curve in the evidence is that twist up to `F_q`-isomorphism. Any other
//! census is a refusal: it means the enumeration did not single out one
//! group, and this format does not pick.
//!
//! # Four further conditions, none of them decoration
//!
//! - The six must be **pairwise distinct**, or "exactly one survived"
//!   counts a set that was never six.
//! - More than one survivor is a **refusal**, never a choice. Picking
//!   would produce output indistinguishable from a proof.
//! - Points are consumed in the order the evidence lists them, and each
//!   must eliminate something — a point that decides nothing is padding.
//! - The trace comes from a **proved** cardinality over the base field,
//!   and `r` from a **proved** prime subgroup order.

use num_bigint::{BigInt, BigUint};
use num_traits::Zero;

use crate::claims::{decimal, find_proved_assert};
use crate::curve::{Curve, Field, Pt};
use crate::fq::Fq;
use crate::fq4::Fq4;
use crate::json::Node;
use crate::twist_class::sextic_candidates;

/// One coefficient list from a payload, as an element of the field.
///
/// Generic over the field so that degree 2 and degree 4 read their
/// payloads through the same code. A separate reader per degree is
/// exactly the arrangement that produced this project's recurring bug:
/// a rule applied in one branch and forgotten in its twin.
///
/// The length is checked against the field's own degree rather than
/// padded, because a padded list silently describes a different point.
/// Every coefficient is checked to be reduced, because the format has one
/// spelling per number and a reader that reduced silently would accept a
/// document no canonical producer could write.
fn read_element<F: Field>(
    field: &F,
    node: &Node,
    key: &str,
    ctx: &str,
) -> Result<F::Elem, String> {
    let raw = node
        .field(key, ctx)?
        .as_array()
        .ok_or_else(|| format!("{ctx}: {key} must be an array"))?;
    let degree = field.degree() as usize;
    if raw.len() != degree {
        return Err(format!(
            "{ctx}: {key} has {} coefficient(s), the field has degree {degree}",
            raw.len()
        ));
    }
    let mut values = Vec::with_capacity(degree);
    for (position, entry) in raw.iter().enumerate() {
        let text = entry
            .as_str()
            .ok_or_else(|| format!("{ctx}: {key} holds a non-string"))?;
        let value = decimal(text, key)?;
        if &value >= field.characteristic() {
            return Err(format!("{ctx}: {key}[{position}] is not reduced mod p"));
        }
        values.push(value);
    }
    field.element_from(&values).map_err(|e| format!("{ctx}: {e}"))
}

pub fn check_order_elimination(
    p: &BigUint,
    subject: &Node,
    asserts: &Node,
    payload: &Node,
    claims: &[Node],
    name: &str,
) -> Result<String, String> {
    // Narrow on purpose. This argument enumerates sextic twist orders, so
    // it says nothing about a curve over the base field, and letting it
    // support `curve.cardinality` would attach a G2 argument to a G1
    // claim.
    if name != "g2.cardinality" {
        return Err(format!(
            "{name}: `derive.order-elimination` supports only `g2.cardinality`"
        ));
    }

    // Sextic twists exist only for j = 0. Without this the six candidates
    // are six numbers with no claim to contain the order of anything, and
    // the elimination below would be a true statement about the wrong
    // set. `derive.twist-class` makes the same check; it is repeated here
    // because that claim is optional and absent from every degree-4
    // bundle, so relying on it would leave BLS24 unchecked.
    let subject_a = decimal(subject.str_field("a", name)?, "subject.a")?;
    if !subject_a.is_zero() {
        return Err(format!(
            "{name}: the subject has a != 0, so it has no sextic twists and \
             this argument does not apply to it"
        ));
    }

    let proved_p = decimal(
        find_proved_assert(claims, "field.characteristic", "p")?,
        "field.characteristic.p",
    )?;
    if &proved_p != p {
        return Err(format!("{name}: the proved characteristic is not the subject's"));
    }

    let field_block = payload.field("field", name)?;
    // `beta` and `xi` are optional by degree, not by taste: degree 2
    // needs the first, degree 4 both. Listing them as permitted here and
    // requiring them below keeps the two questions apart — what may
    // appear, and what must.
    field_block.closed_keys(&["p", "degree", "beta", "xi"], "elimination field")?;
    if decimal(field_block.str_field("p", name)?, "field.p")? != *p {
        return Err(format!(
            "{name}: the evidence names a different characteristic than the subject"
        ));
    }
    let degree_raw = decimal(field_block.str_field("degree", name)?, "field.degree")?;
    let degree = u32::try_from(degree_raw).map_err(|_| format!("{name}: absurd degree"))?;
    let beta = match field_block.get("beta") {
        Some(node) => Some(decimal(
            node.as_str().ok_or_else(|| format!("{name}: beta must be a string"))?,
            "field.beta",
        )?),
        None => None,
    };
    // One dispatch on degree, and everything after it is degree-blind.
    // The elimination argument does not depend on how a field multiplies,
    // only on the group law over it, so it is written once.
    match degree {
        2 => {
            let field = Fq::new(p.clone(), degree, beta).map_err(|e| format!("{name}: {e}"))?;
            run(&field, asserts, payload, claims, name)
        }
        4 => {
            // The tower needs a second parameter: F_p^4 is
            // F_p^2[v]/(v^2 - xi), and xi is an element of F_p^2 rather
            // than an integer. A payload that omits it is describing a
            // field nobody can rebuild.
            let beta = beta.ok_or_else(|| format!("{name}: degree 4 needs a beta"))?;
            let xi_raw = field_block
                .field("xi", name)?
                .as_array()
                .ok_or_else(|| format!("{name}: xi must be an array"))?;
            if xi_raw.len() != 2 {
                return Err(format!("{name}: xi has two coefficients over F_p^2"));
            }
            let mut xi = Vec::with_capacity(2);
            for entry in xi_raw {
                let text = entry
                    .as_str()
                    .ok_or_else(|| format!("{name}: xi holds a non-string"))?;
                let value = decimal(text, "field.xi")?;
                if &value >= p {
                    return Err(format!("{name}: xi is not reduced mod p"));
                }
                xi.push(value);
            }
            let field = Fq4::new(p.clone(), beta, (xi[0].clone(), xi[1].clone()))
                .map_err(|e| format!("{name}: {e}"))?;
            run(&field, asserts, payload, claims, name)
        }
        other => Err(format!(
            "{name}: the twist enumeration covers degrees 2 and 4, not {other}"
        )),
    }
}

/// The argument itself, over whatever field it was handed.
fn run<F: Field>(
    field: &F,
    asserts: &Node,
    payload: &Node,
    claims: &[Node],
    name: &str,
) -> Result<String, String> {
    let p = field.characteristic().clone();
    let curve_block = payload.field("curve", name)?;
    curve_block.closed_keys(&["a", "b"], "elimination curve")?;

    // The binding, and it is one comparison against zero. With the
    // subject at a = 0 and q = 1 mod 3, every non-singular y^2 = x^3 + b'
    // over this field is a sextic twist of the subject — which is exactly
    // what puts its order among the six. A curve with a' != 0 is not, and
    // for it the elimination would narrow a set that need not contain the
    // answer, so it is refused before any arithmetic runs.
    let curve_a = read_element(field, curve_block, "a", name)?;
    if !field.is_zero(&curve_a) {
        return Err(format!(
            "{name}: the curve in the evidence has a != 0, so it is not a sextic \
             twist of the subject and its order need not be among the candidates"
        ));
    }
    // `Curve::new` refuses 4a^3 + 27b^2 = 0, which with a' = 0 is exactly
    // b' = 0. So b' != 0 is established rather than assumed, and the pair
    // (a' = 0, non-singular) is the whole precondition.
    let curve = Curve::new(
        field,
        curve_a,
        read_element(field, curve_block, "b", name)?,
    )
    .map_err(|e| format!("{name}: {e}"))?;

    // The candidates come from the base-field cardinality, which has to
    // be proved: the whole enumeration is a function of that number, and
    // an unproved one would make six unproved candidates.
    let cardinality = BigInt::from(decimal(
        find_proved_assert(claims, "curve.cardinality", "n")?,
        "curve.cardinality.n",
    )?);
    let (candidates, _t2, _v) =
        sextic_candidates(&BigInt::from(p.clone()), &cardinality, field.degree())
            .map_err(|e| format!("{name}: {e}"))?;

    // Pairwise distinct, checked rather than assumed. Two equal
    // candidates would make "one survivor" a statement about a set that
    // was never six, and it would also break the step below that lets an
    // order stand for a twist class. The enumeration is cheap enough to
    // check.
    for i in 0..candidates.len() {
        for j in (i + 1)..candidates.len() {
            if candidates[i] == candidates[j] {
                return Err(format!(
                    "{name}: the candidate orders are not pairwise distinct"
                ));
            }
        }
    }

    // The census on r, done before any point is read so that a defective
    // enumeration is refused as an enumeration rather than as a failed
    // elimination.
    let subgroup = decimal(
        find_proved_assert(claims, "curve.order.prime", "n")?,
        "curve.order.prime.n",
    )?;
    if subgroup < BigUint::from(2u32) {
        return Err(format!("{name}: the subgroup order must exceed one"));
    }
    let r = BigInt::from(subgroup);
    let mut divisible: Vec<usize> = Vec::new();
    for (index, value) in candidates.iter().enumerate() {
        if (value % &r).is_zero() {
            divisible.push(index);
        }
    }
    if divisible.len() != 2 {
        return Err(format!(
            "{name}: {} of the six candidates are divisible by r, not two, so \
             the second group is not singled out by this enumeration",
            divisible.len()
        ));
    }
    if divisible[0] != 0 {
        // Index 0 is the subject's own order over the extension, and r
        // divides #E(F_p) which divides it. If that fails, the candidates
        // are not describing this curve and nothing downstream is safe.
        return Err(format!(
            "{name}: r does not divide the subject's own order over the \
             extension, so the candidates do not describe this curve"
        ));
    }

    let mut surviving: Vec<bool> = vec![true; candidates.len()];
    let points = payload
        .field("points", name)?
        .as_array()
        .ok_or_else(|| format!("{name}: points must be an array"))?;
    if points.is_empty() {
        return Err(format!("{name}: no points are offered, so nothing is eliminated"));
    }

    for (position, entry) in points.iter().enumerate() {
        entry.closed_keys(&["x", "y"], "elimination point")?;
        let point = Pt::Affine {
            x: read_element(field, entry, "x", name)?,
            y: read_element(field, entry, "y", name)?,
        };
        if !curve.contains(&point) {
            return Err(format!("{name}: point {position} is not on the curve"));
        }

        let mut eliminated_any = false;
        for (index, alive) in surviving.iter_mut().enumerate() {
            if !*alive {
                continue;
            }
            let order = candidates[index]
                .to_biguint()
                .ok_or_else(|| format!("{name}: a candidate order is negative"))?;
            let reached = curve
                .multiply(&order, &point)
                .map_err(|_| format!("{name}: arithmetic in the field broke down"))?;
            if reached != Pt::Infinity {
                *alive = false;
                eliminated_any = true;
            }
        }
        // A point that rules nothing out is padding, and padding in an
        // argument is where a reader stops reading.
        if !eliminated_any {
            return Err(format!(
                "{name}: point {position} eliminates nothing and should not be here"
            ));
        }
    }

    let alive: Vec<usize> = surviving
        .iter()
        .enumerate()
        .filter(|(_, keep)| **keep)
        .map(|(index, _)| index)
        .collect();

    if alive.is_empty() {
        return Err(format!(
            "{name}: every candidate was eliminated, so the enumeration does not \
             contain the group order"
        ));
    }
    if alive.len() > 1 {
        // Refusal, not a choice. The same rule as the Hasse window: an
        // argument that does not single out an answer must say so.
        return Err(format!(
            "{name}: {} candidates survive; the order is not pinned down and \
             must not be guessed",
            alive.len()
        ));
    }

    // The survivor has to be the twist that carries the second group, and
    // the census above says which one that is. Landing on index 0 means
    // the points came from the subject's own curve over the extension —
    // an argument every step of which is honest and whose conclusion is
    // about the wrong group.
    if alive[0] == 0 {
        return Err(format!(
            "{name}: the elimination settled on the subject's own order over the \
             extension rather than on the twist, so the points did not come from \
             the second group's curve"
        ));
    }
    if alive[0] != divisible[1] {
        return Err(format!(
            "{name}: the surviving candidate is not divisible by r, so it is not \
             the order of a group containing the proved subgroup"
        ));
    }

    // The survivor has to be a number a curve over this field could
    // have. The candidates are built to lie in the window, so this
    // catches an arithmetic slip rather than a forgery — but it is one
    // multiplication against a bound the field computes itself, and it
    // makes the window part of the argument instead of a fact stated
    // elsewhere.
    let (low, high) = field.hasse_window();
    if candidates[alive[0]] < low || candidates[alive[0]] > high {
        return Err(format!(
            "{name}: the surviving candidate lies outside the Hasse window"
        ));
    }

    let settled = candidates[alive[0]]
        .to_biguint()
        .ok_or_else(|| format!("{name}: the settled order is negative"))?;
    let stated = decimal(asserts.str_field("n", name)?, "asserts.n")?;
    if stated != settled {
        return Err(format!("{name}: the surviving candidate is not the order asserted"));
    }

    Ok(format!(
        "order settled by eliminating {} of {} twist candidates with {} point(s), \
         no factorisation needed; the curve is a sextic twist of the subject \
         (a = 0 on both, q = 1 mod 3) and is the one carrying the proved subgroup, \
         not the subject's own curve over the extension",
        candidates.len() - 1,
        candidates.len(),
        points.len()
    ))
}
