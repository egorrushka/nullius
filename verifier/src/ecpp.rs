//! Checking an Atkin-Morain certificate.
//!
//! Each step reduces the primality of N to the primality of a smaller q.
//! Given a curve E over Z/NZ, a point P on it, and integers t and s with
//!
//!     m = N + 1 - t,   m = s * q,   q > (N^(1/4) + 1)^2,
//!     m * P = O,       s * P != O,
//!
//! N is prime if q is. The chain repeats until q is small enough to settle
//! directly, and the whole thing is only as good as its last step, which is
//! why that step is checked rather than assumed.
//!
//! Producing such a certificate takes serious computation. Checking one is
//! a few hundred multiplications. That asymmetry is the entire reason this
//! project exists.

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};

use crate::ec::{is_prime_small, Curve, EcError, Point};

pub struct Step {
    pub n: BigUint,
    pub t: BigInt,
    pub s: BigUint,
    pub a: BigUint,
    pub x: BigUint,
    pub y: BigUint,
}

/// Above this the deterministic base set is no longer known to decide
/// primality, so nothing may be called prime here without a chain. 10^24
/// is comfortably inside the published bound.
/// The exponent, named so a test can find it.
///
/// The same bound is written in the producer, and nothing in either
/// program keeps the two in step — a comment saying they must not
/// diverge is not a mechanism. A test reads this name out of the source
/// and compares it with the Python copy, which is an external arbiter
/// rather than a build-time link: the two implementations are meant to
/// stay independent.
pub const SMALL_PRIME_LIMIT_EXP: u32 = 24;

pub fn small_prime_limit() -> BigUint {
    BigUint::from(10u32).pow(SMALL_PRIME_LIMIT_EXP)
}

pub fn verify_chain(claimed: &BigUint, steps: &[Step]) -> Result<String, String> {
    if steps.is_empty() {
        return Err("the certificate has no steps".into());
    }
    if &steps[0].n != claimed {
        return Err("the chain does not start at the number being claimed".into());
    }

    for (index, step) in steps.iter().enumerate() {
        let context = format!("step {}", index + 1);
        let q = check_step(step, &context)?;

        match steps.get(index + 1) {
            Some(next) => {
                if next.n != q {
                    return Err(format!(
                        "{context}: reduces to q, but the next step is about a different number"
                    ));
                }
            }
            None => {
                if q >= small_prime_limit() {
                    return Err(format!(
                        "{context}: the chain ends at a number too large to settle directly"
                    ));
                }
                if !is_prime_small(&q) {
                    return Err(format!("{context}: the chain ends at a composite number"));
                }
            }
        }
    }

    Ok(format!("Atkin-Morain chain of {} step(s) checked", steps.len()))
}

fn check_step(step: &Step, context: &str) -> Result<BigUint, String> {
    let n = &step.n;
    let one = BigUint::one();

    if n <= &BigUint::from(3u32) {
        return Err(format!("{context}: N is too small for a curve step"));
    }
    if !n.bit(0) || (n % BigUint::from(3u32)).is_zero() {
        return Err(format!("{context}: N is divisible by 2 or 3"));
    }

    // m = N + 1 - t, computed in signed arithmetic because t may be negative.
    let m = BigInt::from(n.clone()) + BigInt::one() - &step.t;
    if m.sign() != Sign::Plus {
        return Err(format!("{context}: m is not positive"));
    }
    let m = m.to_biguint().expect("checked positive");

    if step.s.is_zero() {
        return Err(format!("{context}: s is zero"));
    }
    let (q, remainder) = m.div_rem(&step.s);
    if !remainder.is_zero() {
        return Err(format!("{context}: s does not divide m"));
    }
    if q <= one {
        return Err(format!("{context}: q is trivial"));
    }

    // q must exceed (N^(1/4) + 1)^2, which is what makes the reduction sound.
    let quartic = n.nth_root(4) + &one;
    if q <= &quartic * &quartic {
        return Err(format!("{context}: q is too small for the reduction to hold"));
    }

    let b = Curve::b_from_point(&step.a, &step.x, &step.y, n);
    let curve = Curve::new(step.a.clone(), b, n.clone());

    // A singular curve would let the argument through with no content.
    let unit = curve.discriminant_unit();
    if unit.gcd(n) != one {
        return Err(format!("{context}: the curve is singular modulo N"));
    }

    let point = Point::Affine {
        x: step.x.clone() % n,
        y: step.y.clone() % n,
    };
    if !curve.contains(&point) {
        return Err(format!("{context}: the point is not on the curve"));
    }

    let describe = |err: EcError| match err {
        EcError::NotInvertible(factor) => format!(
            "{context}: arithmetic modulo N broke down, which means N has a factor near {}",
            factor.bits()
        ),
    };

    // m * P must vanish, and s * P must not: together they force a point of
    // order q, and a group of that size cannot live on a curve over a ring
    // unless N is prime.
    let m_point = curve.multiply(&m, &point).map_err(describe)?;
    if m_point != Point::Infinity {
        return Err(format!("{context}: m times the point is not the identity"));
    }
    let s_point = curve.multiply(&step.s, &point).map_err(describe)?;
    if s_point == Point::Infinity {
        return Err(format!("{context}: s times the point is the identity"));
    }

    Ok(q)
}
