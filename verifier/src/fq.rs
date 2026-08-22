//! Arithmetic over `F_p` and `F_p^2`, in one implementation.
//!
//! The two degrees are not two code paths. An element is always a pair
//! `c0 + c1*u`; at degree one the second coefficient is required to be
//! zero and `beta` is zero, which makes the multiplication formula
//! collapse to ordinary modular arithmetic on its own. One routine to
//! read, one routine to get wrong.
//!
//! Kept apart from `ec.rs` all the same. That module works over `Z/nZ`
//! for a modulus whose primality is the very thing under test, and its
//! inversions are allowed to fail informatively. Here the modulus is a
//! prime already established by another claim, so the shapes of the two
//! problems differ even though the group law looks alike.
//!
//! Affine coordinates, an inversion per operation, no attempt at
//! constant time. A verifier reads public documents; clarity wins.

use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Zero};

use crate::ec::{invert, EcError};

/// `c0 + c1*u`, with `u^2 = beta`.
pub type Elem = (BigUint, BigUint);

/// A point over this field, in the shared representation.
pub type Point = crate::curve::Pt<Elem>;

/// `F_p[u] / (u^2 - beta)`, or `F_p` itself when the degree is one.
pub struct Fq {
    pub p: BigUint,
    pub beta: BigUint,
    pub degree: u32,
}

fn to_uint(value: BigInt, modulus: &BigUint) -> BigUint {
    let m = BigInt::from(modulus.clone());
    value
        .mod_floor(&m)
        .to_biguint()
        .expect("mod_floor result is non-negative")
}

impl Fq {
    /// A field of the given degree, or a refusal.
    ///
    /// At degree two `beta` must be a quadratic non-residue, or the
    /// quotient is a ring with zero divisors and every conclusion drawn
    /// from it is void. Euler's criterion settles it in one exponentiation.
    pub fn new(p: BigUint, degree: u32, beta: Option<BigUint>) -> Result<Self, String> {
        if p < BigUint::from(5u32) || p.is_even() {
            return Err("field: p must be an odd prime above 3".into());
        }
        match (degree, beta) {
            (1, None) => Ok(Fq {
                p,
                beta: BigUint::zero(),
                degree: 1,
            }),
            (1, Some(_)) => Err("field: a prime field takes no beta".into()),
            (2, None) => Err("field: degree 2 needs a beta".into()),
            (2, Some(beta)) => {
                let beta = beta % &p;
                if beta.is_zero() {
                    return Err("field: beta must be non-zero".into());
                }
                let exponent = (&p - BigUint::one()) >> 1;
                if beta.modpow(&exponent, &p) != &p - BigUint::one() {
                    return Err(
                        "field: beta is a square mod p, so the quotient is not a field".into(),
                    );
                }
                Ok(Fq { p, beta, degree: 2 })
            }
            (other, _) => Err(format!("field: unsupported degree {other}")),
        }
    }

    /// The number of elements.
    pub fn order(&self) -> BigUint {
        match self.degree {
            1 => self.p.clone(),
            _ => &self.p * &self.p,
        }
    }

    /// Bounds on the order of a curve over this field, inclusive.
    ///
    /// At degree two the square root of q is p exactly, so the bound is
    /// tight. At degree one it is not, so the integer root is widened by
    /// one on each side. Widening is the safe direction: a wider window
    /// can only fail to pin an order, never pin a wrong one.
    pub fn hasse_window(&self) -> (BigInt, BigInt) {
        let q = BigInt::from(self.order());
        let one = BigInt::one();
        let spread = match self.degree {
            // sqrt(p^2) is exact on the nose, so the window is exact and
            // nothing is widened.
            2 => BigInt::from(BigUint::from(2u32) * &self.p),
            // Everything else, degree 1 included: floor(2*sqrt(q)) with a
            // unit of slack. Written as the general case rather than as
            // the degree-1 case, because the arms used to be `1 =>` and
            // `_ =>`, and the catch-all held the formula that is right
            // only at degree 2. `Fq::new` refuses every other degree, so
            // nothing could reach it — but a verifier whose fallback is
            // wrong for the case it is a fallback for is a trap laid for
            // whoever adds degree 3, and this project has been caught by
            // exactly that shape before.
            _ => BigInt::from(num_integer::Roots::sqrt(
                &(BigUint::from(4u32) * self.order()),
            )) + &one,
        };
        (&q + &one - &spread, &q + &one + &spread)
    }

    pub fn element(&self, c0: BigUint, c1: BigUint) -> Result<Elem, String> {
        let c1 = c1 % &self.p;
        if self.degree == 1 && !c1.is_zero() {
            return Err("field: a prime field has no second coefficient".into());
        }
        Ok((c0 % &self.p, c1))
    }

    pub fn is_zero(&self, a: &Elem) -> bool {
        a.0.is_zero() && a.1.is_zero()
    }

    pub fn add(&self, a: &Elem, b: &Elem) -> Elem {
        ((&a.0 + &b.0) % &self.p, (&a.1 + &b.1) % &self.p)
    }

    pub fn sub(&self, a: &Elem, b: &Elem) -> Elem {
        (
            to_uint(BigInt::from(a.0.clone()) - BigInt::from(b.0.clone()), &self.p),
            to_uint(BigInt::from(a.1.clone()) - BigInt::from(b.1.clone()), &self.p),
        )
    }

    /// `(a0 + a1 u)(b0 + b1 u) = a0b0 + beta a1b1 + (a0b1 + a1b0) u`.
    ///
    /// At degree one both second coefficients are zero, so this reduces to
    /// `a0b0` without a branch.
    pub fn mul(&self, a: &Elem, b: &Elem) -> Elem {
        let p = &self.p;
        let t0 = &a.0 * &b.0 % p;
        let t1 = &a.1 * &b.1 % p;
        let cross = to_uint(
            BigInt::from((&a.0 + &a.1) * (&b.0 + &b.1) % p)
                - BigInt::from(t0.clone())
                - BigInt::from(t1.clone()),
            p,
        );
        ((&t0 + &self.beta * &t1) % p, cross)
    }

    pub fn scale(&self, a: &Elem, k: u32) -> Elem {
        let k = BigUint::from(k);
        ((&a.0 * &k) % &self.p, (&a.1 * &k) % &self.p)
    }

    pub fn square(&self, a: &Elem) -> Elem {
        self.mul(a, a)
    }

    /// Inverse through the norm: `a^-1 = conjugate(a) / norm(a)`.
    pub fn inv(&self, a: &Elem) -> Result<Elem, EcError> {
        let p = &self.p;
        let norm = to_uint(
            BigInt::from(&a.0 * &a.0 % p) - BigInt::from(&self.beta * (&a.1 * &a.1 % p) % p),
            p,
        );
        let norm_inv = invert(&norm, p)?;
        let conjugate = (a.0.clone(), to_uint(-BigInt::from(a.1.clone()), p));
        Ok((
            &conjugate.0 * &norm_inv % p,
            &conjugate.1 * &norm_inv % p,
        ))
    }

    pub fn div(&self, a: &Elem, b: &Elem) -> Result<Elem, EcError> {
        Ok(self.mul(a, &self.inv(b)?))
    }
}

/// `y^2 = x^3 + a x + b` over an `Fq`.
/// `Fq` as a `Field`, so the shared group law can work over it.
///
/// The methods are already there; this only says so to the type system.
/// Nothing about degree 1 or 2 changes, and the corpus built before this
/// existed still reproduces byte for byte — which is the only evidence
/// worth having that a refactor of arithmetic changed nothing.
impl crate::curve::Field for Fq {
    type Elem = Elem;

    fn degree(&self) -> u32 {
        self.degree
    }

    fn characteristic(&self) -> &BigUint {
        &self.p
    }

    fn hasse_window(&self) -> (BigInt, BigInt) {
        Fq::hasse_window(self)
    }

    fn element_from(&self, coefficients: &[BigUint]) -> Result<Elem, String> {
        if coefficients.len() != self.degree as usize {
            return Err(format!(
                "a degree {} field takes {} coefficient(s), got {}",
                self.degree,
                self.degree,
                coefficients.len()
            ));
        }
        let second = coefficients.get(1).cloned().unwrap_or_else(BigUint::zero);
        self.element(coefficients[0].clone(), second)
    }

    fn is_zero(&self, a: &Elem) -> bool {
        Fq::is_zero(self, a)
    }
    fn add(&self, a: &Elem, b: &Elem) -> Elem {
        Fq::add(self, a, b)
    }
    fn sub(&self, a: &Elem, b: &Elem) -> Elem {
        Fq::sub(self, a, b)
    }
    fn mul(&self, a: &Elem, b: &Elem) -> Elem {
        Fq::mul(self, a, b)
    }
    fn square(&self, a: &Elem) -> Elem {
        Fq::square(self, a)
    }
    fn scale(&self, a: &Elem, k: u32) -> Elem {
        Fq::scale(self, a, k)
    }
    fn div(&self, a: &Elem, b: &Elem) -> Result<Elem, EcError> {
        Fq::div(self, a, b)
    }
}

/// The old names, so nothing that used them has to change.
pub type CurveFq<'a> = crate::curve::Curve<'a, Fq>;
