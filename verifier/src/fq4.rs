//! `F_p^4`, as a tower on `F_p^2`.
//!
//! The mirror of `core/field/fp4.py`, and deliberately a mirror rather
//! than a translation: the two are written from the same description and
//! not from each other, so a mistake in one has somewhere to show.
//!
//! **Why a tower.** `F_p^4` could be a quartic quotient of `F_p[w]`, and
//! then multiplication would be a four-term convolution reduced modulo an
//! irreducible quartic. Built as `F_p^2[v]/(v^2 - xi)` it is the same
//! two-term formula `Fq` already uses, over a coefficient ring that
//! happens to be an extension. One formula instead of two, and a quartic
//! reduction is a good place to make a mistake nothing else would catch.
//!
//! **The coefficient order is part of the format.** An element flattens
//! to four integers as `(c0.c0, c0.c1, c1.c0, c1.c1)`, and a second
//! implementation has to agree with that or read every certificate
//! wrongly while verifying happily.
//!
//! **One trap, recorded because it cost time.** Every element of `F_p` is
//! a square in `F_p^4`: for `a` in `F_p*`,
//! `a^((p^4-1)/2) = (a^(p-1))^((p^3+p^2+p+1)/2)`, the exponent is a whole
//! number because four odd terms sum to an even one, and `a^(p-1)` is
//! one. A search for a non-residue among the integers therefore never
//! succeeds — it does not fail, it simply runs out — so anything needing
//! a non-residue must look in the field itself.

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

use crate::curve::Field;
use crate::ec::EcError;
use crate::fq::{Elem as Fp2Elem, Fq};

/// `c0 + c1*v`, each coefficient in `F_p^2`.
pub type Elem4 = (Fp2Elem, Fp2Elem);

/// `F_p^2[v] / (v^2 - xi)`.
pub struct Fq4 {
    pub base: Fq,
    pub xi: Fp2Elem,
}

impl Fq4 {
    /// The field, or a refusal.
    ///
    /// `xi` must be a non-residue **in `F_p^2`**, which is a stronger
    /// demand than being one in `F_p` and is what makes the quotient a
    /// field rather than a ring with zero divisors.
    pub fn new(p: BigUint, beta: BigUint, xi: (BigUint, BigUint)) -> Result<Self, String> {
        let base = Fq::new(p.clone(), 2, Some(beta))?;
        let xi = base.element(xi.0, xi.1)?;
        if base.is_zero(&xi) {
            return Err("field: xi must be non-zero".into());
        }
        let exponent = (&p * &p - BigUint::one()) >> 1;
        if pow(&base, &xi, &exponent) == (BigUint::one(), BigUint::zero()) {
            return Err("field: xi is a square in F_p^2, so the quotient is not a field".into());
        }
        Ok(Fq4 { base, xi })
    }

    fn order(&self) -> BigUint {
        let p = &self.base.p;
        let square = p * p;
        &square * &square
    }

    /// Bounds on the order of a curve over this field, inclusive.
    ///
    /// Exact, with nothing widened: the square root of `p^4` is `p^2` on
    /// the nose. About `2^631` wide for a 315-bit p — which is why the
    /// witness argument cannot reach these curves and elimination can.
    fn window(&self) -> (BigInt, BigInt) {
        let q = BigInt::from(self.order());
        let spread =
            BigInt::from(BigUint::from(2u32) * &self.base.p * &self.base.p);
        (&q + BigInt::one() - &spread, &q + BigInt::one() + &spread)
    }

}

/// Exponentiation in the base field, needed only for the residue test.
fn pow(base: &Fq, a: &Fp2Elem, exponent: &BigUint) -> Fp2Elem {
    let mut result = (BigUint::one(), BigUint::zero());
    let mut acc = a.clone();
    for index in 0..exponent.bits() {
        if exponent.bit(index) {
            result = base.mul(&result, &acc);
        }
        acc = base.square(&acc);
    }
    result
}

impl Field for Fq4 {
    type Elem = Elem4;

    fn degree(&self) -> u32 {
        4
    }

    fn characteristic(&self) -> &BigUint {
        &self.base.p
    }

    fn hasse_window(&self) -> (BigInt, BigInt) {
        self.window()
    }

    fn element_from(&self, coefficients: &[BigUint]) -> Result<Elem4, String> {
        if coefficients.len() != 4 {
            return Err(format!(
                "a degree 4 field takes four coefficients, got {}",
                coefficients.len()
            ));
        }
        Ok((
            self.base
                .element(coefficients[0].clone(), coefficients[1].clone())?,
            self.base
                .element(coefficients[2].clone(), coefficients[3].clone())?,
        ))
    }

    fn is_zero(&self, a: &Elem4) -> bool {
        self.base.is_zero(&a.0) && self.base.is_zero(&a.1)
    }

    fn add(&self, a: &Elem4, b: &Elem4) -> Elem4 {
        (self.base.add(&a.0, &b.0), self.base.add(&a.1, &b.1))
    }

    fn sub(&self, a: &Elem4, b: &Elem4) -> Elem4 {
        (self.base.sub(&a.0, &b.0), self.base.sub(&a.1, &b.1))
    }

    /// `(a0 + a1 v)(b0 + b1 v) = a0b0 + xi a1b1 + (a0b1 + a1b0) v`.
    ///
    /// The same shape as the degree-2 formula, over `F_p^2` instead of
    /// `F_p`. Karatsuba on the cross term, and here the saving is a
    /// multiplication in an extension rather than in the integers, so it
    /// is worth more than it looks.
    fn mul(&self, a: &Elem4, b: &Elem4) -> Elem4 {
        let f = &self.base;
        let t0 = f.mul(&a.0, &b.0);
        let t1 = f.mul(&a.1, &b.1);
        let cross = f.sub(
            &f.sub(&f.mul(&f.add(&a.0, &a.1), &f.add(&b.0, &b.1)), &t0),
            &t1,
        );
        (f.add(&t0, &f.mul(&self.xi, &t1)), cross)
    }

    fn square(&self, a: &Elem4) -> Elem4 {
        self.mul(a, a)
    }

    fn scale(&self, a: &Elem4, k: u32) -> Elem4 {
        (self.base.scale(&a.0, k), self.base.scale(&a.1, k))
    }

    /// Inversion through the norm down to `F_p^2`, which is as far as it
    /// needs to go: `a^-1 = conjugate(a) / (a0^2 - xi a1^2)`.
    fn div(&self, a: &Elem4, b: &Elem4) -> Result<Elem4, EcError> {
        let f = &self.base;
        let norm = f.sub(&f.square(&b.0), &f.mul(&self.xi, &f.square(&b.1)));
        let norm_inv = f.inv(&norm)?;
        let conjugate = (b.0.clone(), f.sub(&(BigUint::zero(), BigUint::zero()), &b.1));
        let inverse = (
            f.mul(&conjugate.0, &norm_inv),
            f.mul(&conjugate.1, &norm_inv),
        );
        Ok(self.mul(a, &inverse))
    }
}
