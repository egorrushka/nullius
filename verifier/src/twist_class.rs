//! The order of a sextic twist, re-derived from the trace.
//!
//! What this establishes: the number proved as `g2.cardinality` is the
//! order of a sextic twist of the subject curve. Before this claim
//! existed, a bundle proved an order for some curve over `F_p^2` and
//! named the claim after G2, and nothing connected the two — a reader had
//! to take the relation from a standard.
//!
//! What it does not establish, and the note says so out loud: matching an
//! order shows the number belongs to a twist, not that the particular
//! curve in the evidence *is* that twist. Two curves can share an order.
//! The family claim fixes the twist by construction, so between the two
//! the practical question is answered; strict uniqueness is outside this
//! format.
//!
//! Every division and root here is exact and checked. A floored root or a
//! silent halving would build the enumeration on the wrong `v`, and the
//! six candidates would be six wrong numbers that still look like an
//! argument.

use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};

use crate::claims::{decimal, find_proved_assert};
use crate::json::Node;

/// The exact square root, or nothing.
fn exact_sqrt(value: &BigInt) -> Option<BigInt> {
    if value.is_negative() {
        return None;
    }
    let root = value.sqrt();
    if &(&root * &root) == value {
        Some(root)
    } else {
        None
    }
}

/// The six possible orders, in the order the format indexes them.
///
/// Shared with the elimination argument, which needs the same six from
/// the same trace. One enumeration, so the two cannot disagree about
/// what the candidates are.
pub fn sextic_candidates(
    p: &BigInt,
    cardinality: &BigInt,
    degree: u32,
) -> Result<(Vec<BigInt>, BigInt, BigInt), String> {
    if degree < 2 {
        return Err("a twist enumeration needs an extension, not the base field".into());
    }
    let one = BigInt::one();
    let trace = p + &one - cardinality;
    // Weil's recurrence t_n = t*t_(n-1) - p*t_(n-2), which at degree 2 is
    // t^2 - 2p and at degree 4 is what BLS24 needs. One recurrence rather
    // than a formula per degree: the second formula is where the two
    // implementations would start disagreeing.
    let (mut previous, mut current) = (BigInt::from(2u32), trace.clone());
    for _ in 1..degree {
        let next = &trace * &current - p * &previous;
        previous = current;
        current = next;
    }
    let t2 = current;
    let q = p.pow(degree);

    // Six twist classes exist only when q = 1 mod 3. Where q = 2 mod 3 a
    // curve with j = 0 is supersingular over this field and has two, so
    // an enumeration of six would be an enumeration of a set the true
    // order need not belong to — and an elimination argument whose
    // enumeration might not contain the answer proves nothing at all.
    // Checked here rather than at each caller: one enumeration, one
    // precondition, no branch to forget.
    if &q % BigInt::from(3u32) != BigInt::one() {
        return Err(
            "q is not 1 mod 3, so this field has two twist classes rather than \
             six and the enumeration need not contain the order"
                .into(),
        );
    }

    let source = BigInt::from(4u32) * &q - &t2 * &t2;
    if source.is_negative() {
        return Err("t2 lies outside the Hasse bound for F_p^2".into());
    }
    let (v_squared, remainder) = source.div_rem(&BigInt::from(3u32));
    if !remainder.is_zero() {
        return Err("4q - t2^2 is not divisible by 3, so j is not 0".into());
    }
    let v = exact_sqrt(&v_squared)
        .ok_or("4q - t2^2 over 3 is not a perfect square")?;
    if v.is_zero() {
        return Err("v vanishes; the curve is supersingular or degenerate".into());
    }

    let mut out = vec![&q + &one - &t2, &q + &one + &t2];
    for combined in [&t2 + BigInt::from(3u32) * &v, &t2 - BigInt::from(3u32) * &v] {
        if combined.is_odd() {
            return Err("t2 +- 3v is odd, so the twist formulas do not apply".into());
        }
        let half = combined / BigInt::from(2u32);
        out.push(&q + &one - &half);
        out.push(&q + &one + &half);
    }
    Ok((out, t2, v))
}

pub fn check_twist_class(
    p: &BigUint,
    subject: &Node,
    asserts: &Node,
    payload: &Node,
    claims: &[Node],
    name: &str,
) -> Result<String, String> {
    // Sextic twists exist only for j = 0. A curve with a != 0 is refused
    // rather than skipped: producing nothing for the case the argument
    // does not cover would leave the impression it was covered.
    let subject_a = decimal(subject.str_field("a", name)?, "subject.a")?;
    if !subject_a.is_zero() {
        return Err(format!(
            "{name}: the subject has a != 0, so it has no sextic twists"
        ));
    }

    let p_signed = BigInt::from(p.clone());
    let cardinality = BigInt::from(decimal(
        find_proved_assert(claims, "curve.cardinality", "n")?,
        "curve.cardinality.n",
    )?);
    let twist_order = BigInt::from(decimal(
        find_proved_assert(claims, "g2.cardinality", "n")?,
        "g2.cardinality.n",
    )?);

    // The degree is stated by the claim, not assumed by the reader.
    //
    // This used to enumerate at degree 2 unconditionally, because that is
    // where the second group lived for every family the format covered.
    // It is not where BLS24 puts it, and the six classes over F_p^4 are a
    // different set from the six over F_p^2: an index means nothing until
    // the field it indexes into is named. So `degree` is part of what the
    // claim asserts rather than a convention a reader has to know.
    //
    // Naming the wrong degree is caught rather than believed. The
    // enumeration at the wrong degree does not contain the proved order,
    // so the index check below refuses.
    let degree_raw = decimal(asserts.str_field("degree", name)?, "asserts.degree")?;
    let degree = u32::try_from(degree_raw).map_err(|_| format!("{name}: absurd degree"))?;
    if degree != 2 && degree != 4 {
        return Err(format!(
            "{name}: the twist enumeration covers degrees 2 and 4, not {degree}"
        ));
    }
    let (six, t2, v) = sextic_candidates(&p_signed, &cardinality, degree)
        .map_err(|e| format!("{name}: {e}"))?;

    // The order this claim classifies must have been settled by the
    // argument that binds its curve to the subject. Stated as a check
    // rather than left as an argument about which evidence kinds may
    // support `g2.cardinality`: the note below says the curve *is* the
    // twist, and that is only true because the elimination established
    // it. A note resting on a fact nobody checked is how this project's
    // last three bugs read.
    let source = claims
        .iter()
        .find(|c| c.get("claim").and_then(Node::as_str) == Some("g2.cardinality"))
        .ok_or_else(|| format!("{name}: there is no `g2.cardinality` to classify"))?
        .field("evidence", "g2.cardinality")?
        .str_field("type", "g2.cardinality")?;
    if source != "derive.order-elimination" {
        return Err(format!(
            "{name}: the order it classifies rests on `{source}`, which does not \
             tie its curve to the subject"
        ));
    }

    // v and the index come from the evidence and are re-derived here, not
    // taken. They are carried at all so a reader can follow the argument
    // without redoing the search.
    let stated_v = decimal(payload.str_field("v", name)?, "v")?;
    if BigInt::from(stated_v) != v {
        return Err(format!("{name}: the stated v is not the one 4q = t2^2 + 3v^2 gives"));
    }
    let stated_index = decimal(payload.str_field("index", name)?, "index")?;
    let index = u32::try_from(stated_index).map_err(|_| format!("{name}: absurd index"))?;
    if index as usize >= six.len() {
        return Err(format!("{name}: the index is outside the six twist classes"));
    }
    if six[index as usize] != twist_order {
        return Err(format!(
            "{name}: the proved order is not the twist class the evidence names"
        ));
    }

    // The claim's own number, checked against the evidence.
    //
    // It was not. The payload's `index` was re-derived and the asserted
    // `class` beside it was never compared to anything, so a bundle could
    // state one class and prove another — and `class` is the field the
    // pairing policies read, so a verdict would have been computed from a
    // number no one checked. The same shape as every serious bug found
    // here: a value that is right on every curve that exists and rests on
    // nothing.
    let stated_class = decimal(asserts.str_field("class", name)?, "asserts.class")?;
    if stated_class != BigUint::from(index) {
        return Err(format!(
            "{name}: the claim states class {stated_class} and the evidence proves {index}"
        ));
    }

    if asserts.str_field("related", name)? != "sextic-twist" {
        return Err(format!("{name}: the claim does not state a sextic-twist relation"));
    }

    // t2 goes into the note rather than being computed and dropped. A
    // reader following the argument by hand needs it: the six candidates
    // are built from t2 and v, and stating one of them lets the
    // enumeration be reproduced without re-deriving it.
    // The caveat that used to end this note is gone, and its absence is
    // the point. It said the curve in the G2 evidence was not thereby
    // shown to be that twist, which was true while nothing checked it and
    // false the moment `derive.order-elimination` began checking a' = 0
    // and taking the census on r. The check above requires that argument
    // to be the one underneath, so the note can say what holds.
    Ok(format!(
        "the proved order is sextic twist class {index} of the six over F_p^{degree}, \
         from a trace of {} bits; the curve in the G2 evidence is that twist, \
         established by the elimination this claim rests on",
        t2.magnitude().bits()
    ))
}
