//! Membership in a pairing-friendly family, re-derived from one integer.
//!
//! BLS12 and BN curves are generated rather than chosen: a single `u`
//! determines the characteristic, the subgroup order and the trace
//! through polynomials the family fixes. Recomputing them is exact
//! integer arithmetic over claims already proved, which is why this sits
//! at the same tier as the other `check.*` kinds.
//!
//! The polynomials are written out here rather than shared with the
//! producer. That is the arrangement the whole project rests on: two
//! implementations, in different languages, that have to agree. A shared
//! constant would let one transcription error pass twice.
//!
//! Everything is computed on signed integers. The trace of a BLS12 curve
//! with negative `u` is itself negative, and `p + 1 - #E` has no business
//! being evaluated in unsigned arithmetic where it would wrap rather than
//! go below zero.

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Signed, Zero};

use crate::claims::{decimal, find_proved_assert};
use crate::json::Node;

/// A signed decimal from the evidence.
///
/// The parameter of a BLS12 curve is usually negative, so this cannot go
/// through `decimal`, which is unsigned by design.
fn signed(text: &str, what: &str) -> Result<BigInt, String> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{what}: not a decimal integer"));
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return Err(format!("{what}: leading zero"));
    }
    if negative && digits == "0" {
        return Err(format!("{what}: negative zero is not a spelling of zero"));
    }
    let value = BigInt::parse_bytes(digits.as_bytes(), 10)
        .ok_or_else(|| format!("{what}: not a decimal integer"))?;
    Ok(if negative { -value } else { value })
}

/// p, r and t at this parameter, or a refusal.
fn derive(family: &str, u: &BigInt) -> Result<(BigInt, BigInt, BigInt), String> {
    let one = BigInt::one();
    match family {
        "bls12" => {
            // r = u^4 - u^2 + 1, t = u + 1, p = (u-1)^2 * r / 3 + u
            let u2 = u * u;
            let r = &u2 * &u2 - &u2 + &one;
            let shifted = u - &one;
            let numerator = &shifted * &shifted * &r;
            let three = BigInt::from(3u32);
            // Exact, and checked. A floor division here would produce a
            // number for a u that generates nothing, and the number would
            // look exactly like a characteristic.
            if !(&numerator % &three).is_zero() {
                return Err(
                    "(u - 1)^2 * r is not divisible by 3, so u generates no BLS12 curve"
                        .into(),
                );
            }
            Ok((numerator / three + u, r, u + &one))
        }
        "bls24" => {
            // r = u^8 - u^4 + 1, t = u + 1, p = (u-1)^2 * r / 3 + u.
            // BLS12 one cyclotomic step further along, with the same
            // exactness condition on the division.
            let u2 = u * u;
            let u4 = &u2 * &u2;
            let u8 = &u4 * &u4;
            let r = &u8 - &u4 + &one;
            let shifted = u - &one;
            let numerator = &shifted * &shifted * &r;
            let three = BigInt::from(3u32);
            if !(&numerator % &three).is_zero() {
                return Err(
                    "(u - 1)^2 * r is not divisible by 3, so u generates no BLS24 curve"
                        .into(),
                );
            }
            Ok((numerator / three + u, r, u + &one))
        }
        "bn" => {
            // p = 36u^4 + 36u^3 + 24u^2 + 6u + 1
            // r = 36u^4 + 36u^3 + 18u^2 + 6u + 1
            // t = 6u^2 + 1
            let u2 = u * u;
            let u3 = &u2 * u;
            let u4 = &u2 * &u2;
            let base = BigInt::from(36u32) * &u4 + BigInt::from(36u32) * &u3;
            let linear = BigInt::from(6u32) * u + &one;
            Ok((
                &base + BigInt::from(24u32) * &u2 + &linear,
                &base + BigInt::from(18u32) * &u2 + &linear,
                BigInt::from(6u32) * &u2 + &one,
            ))
        }
        other => Err(format!(
            "unknown family `{other}`; the list is closed, and a family \
             nobody can check is not a claim"
        )),
    }
}

pub fn check_family(
    p: &BigUint,
    asserts: &Node,
    payload: &Node,
    claims: &[Node],
    name: &str,
) -> Result<String, String> {
    let family = payload.str_field("family", name)?;
    if asserts.str_field("family", name)? != family {
        return Err(format!("{name}: the claim and its evidence name different families"));
    }
    let u = signed(payload.str_field("u", name)?, "u")?;
    if signed(asserts.str_field("u", name)?, "u")? != u {
        return Err(format!("{name}: the claim and its evidence give different parameters"));
    }

    let (derived_p, derived_r, derived_t) =
        derive(family, &u).map_err(|e| format!("{name}: {e}"))?;
    if derived_p.is_negative() || derived_r.is_negative() {
        return Err(format!("{name}: u generates a negative characteristic or order"));
    }

    // Against the subject, and against claims that are already proved.
    // Reading them any other way would let a family claim agree with
    // numbers nobody established.
    if derived_p.to_biguint().as_ref() != Some(p) {
        return Err(format!(
            "{name}: the family polynomial does not give the subject's characteristic"
        ));
    }

    let r = decimal(
        find_proved_assert(claims, "curve.order.prime", "n")?,
        "curve.order.prime.n",
    )?;
    if derived_r.to_biguint().as_ref() != Some(&r) {
        return Err(format!(
            "{name}: the family polynomial does not give the proved subgroup order"
        ));
    }

    let cardinality = decimal(
        find_proved_assert(claims, "curve.cardinality", "n")?,
        "curve.cardinality.n",
    )?;
    let trace = BigInt::from(p.clone()) + BigInt::one() - BigInt::from(cardinality);
    if derived_t != trace {
        return Err(format!(
            "{name}: the family polynomial does not give the trace implied by \
             the proved cardinality"
        ));
    }

    Ok(format!(
        "generated by the {family} polynomials at a {}-bit parameter",
        u.magnitude().bits()
    ))
}
