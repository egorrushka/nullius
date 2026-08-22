//! Curves published in a model other than short Weierstrass.
//!
//! Curve25519 is a Montgomery curve and Ed25519 a twisted Edwards one,
//! and between them they carry a large share of the world's signatures
//! and key agreement. The rest of this verifier speaks short Weierstrass
//! and nothing else.
//!
//! Converting quietly and certifying the result would produce a document
//! whose subject is a curve nobody uses under a name everybody
//! recognises. So the conversion is a claim: the subject states the model
//! and its parameters, and this recomputes the Weierstrass coefficients
//! the subject also states.
//!
//! What is established is that those coefficients follow from those
//! parameters, by exact arithmetic in the field. What is **not**
//! established is the birational equivalence itself — that is a theorem
//! about the shapes rather than a fact about these numbers, and this
//! format carries no proofs of theorems. The note returned says so.
//!
//! Every denominator is checked before it is inverted. A zero there does
//! not mean an awkward coefficient; it means the parameters describe no
//! curve, and the two deserve different messages.

use num_bigint::{BigInt, BigUint};
use num_traits::Zero;

use crate::claims::{decimal, find_proved_assert};
use crate::ec::invert;
use crate::json::Node;

/// A signed decimal. Edwards curves are routinely written with `a = -1`.
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
    let value = BigInt::parse_bytes(digits.as_bytes(), 10)
        .ok_or_else(|| format!("{what}: not a decimal integer"))?;
    Ok(if negative { -value } else { value })
}

fn reduce(value: &BigInt, p: &BigUint) -> BigUint {
    let modulus = BigInt::from(p.clone());
    let reduced = ((value % &modulus) + &modulus) % &modulus;
    reduced.to_biguint().expect("non-negative after reduction")
}

/// A modular inverse, refusing by name when the denominator vanishes.
fn inverse(value: &BigUint, p: &BigUint, what: &str) -> Result<BigUint, String> {
    if value.is_zero() {
        return Err(format!("{what} is zero, so these parameters describe no curve"));
    }
    invert(value, p).map_err(|_| format!("{what} has no inverse mod p"))
}

/// A and B, from the parameters of a twisted Edwards curve.
fn montgomery_from_edwards(
    a_e: &BigUint,
    d: &BigUint,
    p: &BigUint,
) -> Result<(BigUint, BigUint), String> {
    if a_e == d {
        return Err("a and d coincide, so the Edwards curve is singular".into());
    }
    if d.is_zero() {
        return Err("d is zero, so the curve is not an Edwards curve".into());
    }
    let difference = reduce(
        &(BigInt::from(a_e.clone()) - BigInt::from(d.clone())),
        p,
    );
    let inverted = inverse(&difference, p, "a - d")?;
    let two = BigUint::from(2u32);
    Ok((
        &two * ((a_e + d) % p) % p * &inverted % p,
        BigUint::from(4u32) * &inverted % p,
    ))
}

pub fn check_curve_model(
    p: &BigUint,
    subject: &Node,
    asserts: &Node,
    claims: &[Node],
    name: &str,
) -> Result<String, String> {
    // The arithmetic below happens in F_p, so p had better be prime, and
    // nothing here can establish that.
    let proved_p = decimal(
        find_proved_assert(claims, "field.characteristic", "p")?,
        "field.characteristic.p",
    )?;
    if &proved_p != p {
        return Err(format!("{name}: the proved characteristic is not the subject's"));
    }

    let model = asserts.str_field("model", name)?;
    let (a_m, b_m) = match model {
        "montgomery" => {
            let a = reduce(&signed(asserts.str_field("A", name)?, "A")?, p);
            let b = match asserts.get("B") {
                Some(node) => {
                    let text = node
                        .as_str()
                        .ok_or_else(|| format!("{name}: B must be a string"))?;
                    reduce(&signed(text, "B")?, p)
                }
                None => BigUint::from(1u32),
            };
            if b.is_zero() {
                return Err(format!("{name}: B is zero, so the equation is degenerate"));
            }
            // A^2 = 4 gives x^3 + A x^2 + x a repeated root.
            let four = BigUint::from(4u32);
            if reduce(&(BigInt::from(&a * &a % p) - BigInt::from(four)), p).is_zero() {
                return Err(format!("{name}: A^2 = 4, so the Montgomery curve is singular"));
            }
            (a, b)
        }
        "twisted-edwards" => {
            let a_e = reduce(&signed(asserts.str_field("a", name)?, "a")?, p);
            let d = reduce(&signed(asserts.str_field("d", name)?, "d")?, p);
            montgomery_from_edwards(&a_e, &d, p).map_err(|e| format!("{name}: {e}"))?
        }
        other => {
            return Err(format!(
                "{name}: unknown curve model `{other}`; the list is closed, and a \
                 model nobody can convert is not a claim"
            ))
        }
    };

    // a = (3 - A^2) / (3 B^2),  b = (2 A^3 - 9 A) / (27 B^3)
    let b_squared = &b_m * &b_m % p;
    let three = BigUint::from(3u32);
    let numerator_a = reduce(&(BigInt::from(three.clone()) - BigInt::from(&a_m * &a_m % p)), p);
    let derived_a = numerator_a
        * inverse(&(&three * &b_squared % p), p, "3B^2").map_err(|e| format!("{name}: {e}"))?
        % p;

    let a_cubed = a_m.modpow(&three, p);
    let numerator_b = reduce(
        &(BigInt::from(BigUint::from(2u32) * &a_cubed % p)
            - BigInt::from(BigUint::from(9u32) * &a_m % p)),
        p,
    );
    let b_cubed = b_m.modpow(&three, p);
    let derived_b = numerator_b
        * inverse(&(BigUint::from(27u32) * &b_cubed % p), p, "27B^3")
            .map_err(|e| format!("{name}: {e}"))?
        % p;

    let subject_a = decimal(subject.str_field("a", name)?, "subject.a")?;
    let subject_b = decimal(subject.str_field("b", name)?, "subject.b")?;
    if derived_a != subject_a || derived_b != subject_b {
        return Err(format!(
            "{name}: the model's parameters do not give the subject's Weierstrass \
             coefficients"
        ));
    }

    Ok(format!(
        "the subject's coefficients follow from its {model} parameters; the \
         birational equivalence itself is taken from the literature, not proved here"
    ))
}
