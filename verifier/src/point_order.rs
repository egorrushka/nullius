//! The point-order argument, and the cofactor that follows from it.
//!
//! What is being re-established here, in order:
//!
//! 1. the field in the evidence is a field, and its characteristic is the
//!    one the subject names;
//! 2. the curve is non-singular and the witness lies on it;
//! 3. every factor offered is prime, by chain or by the deterministic
//!    base set, and they multiply to the order claimed for the witness;
//! 4. that order annihilates the witness, and no proper divisor of it
//!    does, so the order is exact rather than a multiple;
//! 5. the Hasse window admits exactly one multiple of that order, and it
//!    is the number the claim asserts.
//!
//! Step five is where the argument closes, and it is the step that fails
//! for a witness of insufficient order. A group order is not pinned by a
//! small witness, and the refusal has to be loud: silently choosing the
//! nearest admissible multiple would produce output identical to a real
//! proof and mean nothing at all.
//!
//! **Scope: `curve.cardinality`, over the base field, on the subject's
//! own curve.** It once also supported `g2.cardinality` over `F_p^2`,
//! where it could tie the curve in the evidence to nothing and said so in
//! its note. A note is not a check. Once `derive.order-elimination` began
//! binding its curve to the subject, this branch was the way round that
//! binding, so it is gone rather than annotated. Orders over extensions
//! are settled by elimination at every degree, which needs no
//! factorisation — and which is why this argument has no ceiling left to
//! hit: over the base field the factorisation it needs is affordable.

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

use crate::claims::{decimal, find_proved_assert, read_factors};
use crate::fq::{CurveFq, Fq, Point};
use crate::json::Node;

/// One coefficient list from the evidence, as a pair.
fn coefficients(node: &Node, key: &str, degree: u32, ctx: &str) -> Result<(BigUint, BigUint), String> {
    let raw = node
        .field(key, ctx)?
        .as_array()
        .ok_or_else(|| format!("{ctx}: {key} must be an array"))?;
    if raw.len() != degree as usize {
        return Err(format!(
            "{ctx}: {key} has {} coefficient(s), the field has degree {degree}",
            raw.len()
        ));
    }
    let first = decimal(
        raw[0]
            .as_str()
            .ok_or_else(|| format!("{ctx}: {key} holds a non-string"))?,
        key,
    )?;
    let second = match raw.get(1) {
        Some(node) => decimal(
            node.as_str()
                .ok_or_else(|| format!("{ctx}: {key} holds a non-string"))?,
            key,
        )?,
        None => BigUint::zero(),
    };
    Ok((first, second))
}

/// The single multiple of `order` inside the window, or a refusal.
fn unique_multiple(order: &BigUint, low: &BigInt, high: &BigInt) -> Result<BigUint, String> {
    if order.is_zero() {
        return Err("point-order: the order is zero".into());
    }
    // A window whose floor is not positive admits zero as a multiple of
    // anything, and zero would then be "pinned" as a group order. For a
    // real curve the floor is q + 1 - 2*sqrt(q) > 0 whenever p >= 5, so
    // this is unreachable — but an invariant is worth more than an
    // argument that it is unreachable, and the producer refuses here too,
    // in the same words.
    if low <= &BigInt::zero() {
        return Err(
            "point-order: the Hasse window must be positive; a non-positive \
             floor admits zero as a multiple"
                .into(),
        );
    }
    let order_int = BigInt::from(order.clone());
    // Ceiling division for the first multiple at or above the floor.
    let first = (low + &order_int - BigInt::one()) / &order_int;
    let last = high / &order_int;
    if first > last {
        return Err("point-order: no multiple of the witness order fits the Hasse window".into());
    }
    if first != last {
        return Err(format!(
            "point-order: {} multiples of the witness order fit the Hasse window, \
             so the group order is not pinned",
            &last - &first + BigInt::one()
        ));
    }
    (first * order_int)
        .to_biguint()
        .ok_or_else(|| "point-order: the pinned order is negative".into())
}

/// Re-establish a group order from a witness point.
///
/// **Base field only, and the subject's own curve.** This used to also
/// support `g2.cardinality` at degree 2, where no binding to the subject
/// was possible and the note said so out loud. Saying so was not enough:
/// with `derive.order-elimination` now checking `a' = 0` and running the
/// census on `r`, a bundle could have walked round that binding entirely
/// by proving its G2 order here instead, on any curve over `F_p^2` whose
/// order it could factor — the subject's own curve over the extension
/// being the easiest choice, since the certificate already carries the
/// factorisations that make it work.
///
/// Two arguments for one claim, one of them unbound, is not a choice a
/// reader should have to make. The unbound one is gone. G2 orders come
/// from elimination at every degree, which needs no factorisation and
/// ties the curve to the subject; this argument keeps the base field,
/// where it has no ceiling and where the curve is checked to be the
/// subject's own.
pub fn check_point_order(
    p: &BigUint,
    subject: &Node,
    asserts: &Node,
    payload: &Node,
    claims: &[Node],
    name: &str,
) -> Result<String, String> {
    if name != "curve.cardinality" {
        return Err(format!(
            "{name}: `proof.point-order` supports only `curve.cardinality`; a \
             group order over an extension is settled by \
             `derive.order-elimination`, which ties its curve to the subject"
        ));
    }
    let required_degree = 1u32;

    // The whole argument below — Euler's criterion on beta, the Hasse
    // window, the field itself — assumes p is prime, and nothing here can
    // establish that cheaply. So it is required to be established
    // elsewhere in this bundle, by evidence that is itself proved. A
    // bundle without that claim could otherwise carry a tier-A
    // cardinality over a composite "characteristic".
    let proved_p = decimal(
        find_proved_assert(claims, "field.characteristic", "p")?,
        "field.characteristic.p",
    )?;
    if &proved_p != p {
        return Err(format!(
            "{name}: the proved characteristic is not the subject's"
        ));
    }

    let field_block = payload.field("field", name)?;
    // `beta` is permitted here and rejected below, and the order matters.
    //
    // It is a key of the format's field block, so the closed set admits
    // it; whether it may appear *at this degree* is a different question
    // with a more specific answer, and the degree check gives it. Closing
    // the set against `beta` instead made a degree-2 payload under a
    // degree-1 claim fail with "unknown field" — true, unhelpful, and
    // pointing at the wrong thing. `xi` stays out: it belongs to a tower
    // this argument cannot reach at all.
    field_block.closed_keys(&["p", "degree", "beta"], "point-order field")?;
    let stated_p = decimal(field_block.str_field("p", name)?, "field.p")?;
    if &stated_p != p {
        return Err(format!(
            "{name}: the evidence names a different characteristic than the subject"
        ));
    }
    let degree_raw = decimal(field_block.str_field("degree", name)?, "field.degree")?;
    let degree = u32::try_from(degree_raw).map_err(|_| format!("{name}: absurd degree"))?;
    if degree != required_degree {
        return Err(format!(
            "{name}: expects a degree {required_degree} field, the evidence \
             declares degree {degree}"
        ));
    }
    let beta = match field_block.get("beta") {
        Some(node) => Some(decimal(
            node.as_str()
                .ok_or_else(|| format!("{name}: beta must be a string"))?,
            "field.beta",
        )?),
        None => None,
    };

    let field = Fq::new(stated_p, degree, beta).map_err(|e| format!("{name}: {e}"))?;

    let curve_block = payload.field("curve", name)?;
    curve_block.closed_keys(&["a", "b"], "point-order curve")?;
    let a = coefficients(curve_block, "a", degree, name)?;
    let b = coefficients(curve_block, "b", degree, name)?;

    // The curve in the evidence must be the subject's own, with no branch
    // and no exception. Without this the handler proves an order for
    // whatever curve the payload describes and the claim presents it as
    // the subject's: a certificate for y^2 = x^3 + 3 could carry, at tier
    // A, the order of y^2 = x^3 + 5 over the same field.
    //
    // This was conditional on degree 1 while degree 2 was allowed, and
    // the degree-2 branch was the one with no binding at all. With that
    // branch gone the condition has nothing left to select and would only
    // read as though some other case existed.
    let subject_a = decimal(subject.str_field("a", name)?, "subject.a")?;
    let subject_b = decimal(subject.str_field("b", name)?, "subject.b")?;
    if a.0 != subject_a || b.0 != subject_b {
        return Err(format!(
            "{name}: the evidence proves an order for a different curve \
             than the subject"
        ));
    }

    // One spelling per number, at the boundary where data is read. The
    // field would reduce these silently, which would accept a payload no
    // canonical producer could have written.
    for (value, what) in [
        (&a.0, "curve.a[0]"), (&a.1, "curve.a[1]"),
        (&b.0, "curve.b[0]"), (&b.1, "curve.b[1]"),
    ] {
        if value >= p {
            return Err(format!("{name}: {what} is not reduced mod p"));
        }
    }

    let a = field.element(a.0, a.1).map_err(|e| format!("{name}: {e}"))?;
    let b = field.element(b.0, b.1).map_err(|e| format!("{name}: {e}"))?;
    let curve = CurveFq::new(&field, a, b).map_err(|e| format!("{name}: {e}"))?;

    let point_block = payload.field("point", name)?;
    point_block.closed_keys(&["x", "y"], "point-order point")?;
    let x = coefficients(point_block, "x", degree, name)?;
    let y = coefficients(point_block, "y", degree, name)?;
    for (value, what) in [
        (&x.0, "point.x[0]"), (&x.1, "point.x[1]"),
        (&y.0, "point.y[0]"), (&y.1, "point.y[1]"),
    ] {
        if value >= p {
            return Err(format!("{name}: {what} is not reduced mod p"));
        }
    }
    let witness = Point::Affine {
        x: field.element(x.0, x.1).map_err(|e| format!("{name}: {e}"))?,
        y: field.element(y.0, y.1).map_err(|e| format!("{name}: {e}"))?,
    };
    if !curve.contains(&witness) {
        return Err(format!("{name}: the witness point is not on the curve"));
    }

    let order = decimal(payload.str_field("order", name)?, "order")?;
    let (product, factors) = read_factors(payload, name, order.bits() + 1)?;
    if product != order {
        return Err(format!(
            "{name}: the factors do not multiply to the order claimed for the witness"
        ));
    }

    // The order annihilates the point.
    let killed = curve
        .multiply(&order, &witness)
        .map_err(|_| format!("{name}: arithmetic in the field broke down"))?;
    if killed != Point::Infinity {
        return Err(format!(
            "{name}: the stated order does not take the witness to the identity"
        ));
    }

    // And nothing smaller does: stripping any single prime must break it.
    for (prime, _) in &factors {
        let reduced = &order / prime;
        let partial = curve
            .multiply(&reduced, &witness)
            .map_err(|_| format!("{name}: arithmetic in the field broke down"))?;
        if partial == Point::Infinity {
            return Err(format!(
                "{name}: the witness order is not exact; a proper divisor already \
                 reaches the identity"
            ));
        }
    }

    let (low, high) = field.hasse_window();
    let pinned = unique_multiple(&order, &low, &high).map_err(|e| format!("{name}: {e}"))?;

    let stated = decimal(asserts.str_field("n", name)?, "asserts.n")?;
    if stated != pinned {
        return Err(format!(
            "{name}: the window pins a different order than the claim asserts"
        ));
    }

    // Precise about scope rather than sweeping. The curve is the
    // subject's own, checked above, so there is no longer a case where
    // this claim proves an order for something the bundle has not tied
    // down — and therefore no caveat to carry.
    Ok(format!(
        "order of the subject's curve pinned by a witness of {} bits over the \
         base field",
        order.bits()
    ))
}

/// A cofactor, from a proved group order and a proved subgroup order.
///
/// Exact integer arithmetic and nothing else, which is why it stands at
/// the same tier as the Hasse check rather than below it. The subgroup
/// order is required to match the one already proved prime elsewhere in
/// the bundle: a cofactor split against some other number would be
/// arithmetic about nothing.
pub fn check_cofactor(
    asserts: &Node,
    payload: &Node,
    claims: &[Node],
    name: &str,
) -> Result<String, String> {
    let source = match name {
        "curve.order" => "curve.cardinality",
        "g2.order" => "g2.cardinality",
        other => return Err(format!("{other}: no group order claim is associated with it")),
    };
    let group_order = decimal(find_proved_assert(claims, source, "n")?, "group order")?;
    let cofactor = decimal(asserts.str_field("cofactor", name)?, "cofactor")?;
    let subgroup = decimal(asserts.str_field("n", name)?, "n")?;

    if subgroup.is_zero() || cofactor.is_zero() {
        return Err(format!("{name}: neither part may be zero"));
    }
    if &cofactor * &subgroup != group_order {
        return Err(format!(
            "{name}: the cofactor and the subgroup order do not multiply to {source}"
        ));
    }

    let proved = decimal(find_proved_assert(claims, "curve.order.prime", "n")?, "subgroup")?;
    if proved != subgroup {
        return Err(format!(
            "{name}: the subgroup order is not the one proved prime in this bundle"
        ));
    }

    // The cofactor arrives with its factorisation, and it is checked here
    // rather than carried along unread. Two reasons. Anything a
    // certificate states must be re-established, or the document is
    // partly assertion; and a subgroup-security policy needs to know the
    // largest prime factor of the cofactor, which is worth nothing unless
    // the split has been verified.
    // The cofactor's factorisation, when there is one.
    //
    // Optional, and this is the one place where optional costs something
    // real. A subgroup-security policy reads `largest_prime_factor`, and
    // without it that policy returns undecided — which is the honest
    // answer, because nobody established the number.
    //
    // It is optional because it has to be. BLS24-315's second group has a
    // 1005-bit cofactor whose composite part is 983 bits, and factoring
    // general numbers of that size is beyond anyone. Demanding a
    // factorisation there would mean the curve cannot be certified at
    // all, and a certificate that omits one claim is worth more than no
    // certificate.
    //
    // What is never optional: an asserted largest factor without a
    // factorisation behind it. That reads as established and is not.
    let detail = match (payload.get("factors"), asserts.get("largest_prime_factor")) {
        (Some(_), Some(node)) => {
            let (product, factors) = read_factors(payload, name, cofactor.bits() + 1)?;
            if product != cofactor {
                return Err(format!(
                    "{name}: the factors do not multiply to the cofactor"
                ));
            }
            let largest = factors
                .iter()
                .map(|(prime, _)| prime)
                .max()
                .cloned()
                .unwrap_or_else(BigUint::one);
            let stated = decimal(
                node.as_str()
                    .ok_or_else(|| format!("{name}: largest_prime_factor must be a string"))?,
                "largest",
            )?;
            if stated != largest {
                return Err(format!(
                    "{name}: the asserted largest prime factor is not the largest \
                     one in the factorisation"
                ));
            }
            format!(", largest prime factor {} bits", largest.bits())
        }
        (None, Some(_)) => {
            return Err(format!(
                "{name}: a largest prime factor is asserted with no factorisation \
                 to establish it"
            ))
        }
        (Some(_), None) => {
            return Err(format!(
                "{name}: a factorisation is offered but its largest prime factor \
                 is not asserted, so no policy can read it"
            ))
        }
        (None, None) => ", cofactor not factored".to_string(),
    };

    // A cofactor of one is the case where the subgroup is the whole
    // group, and reporting it in bits reads as noise. Say it plainly.
    if cofactor.is_one() {
        return Ok("cofactor 1: the subgroup is the whole group".into());
    }

    Ok(format!(
        "cofactor of {} bits{detail}, against a proved prime subgroup",
        cofactor.bits()
    ))
}
