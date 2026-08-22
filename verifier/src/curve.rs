//! The group law, written once, over whatever field it is handed.
//!
//! There were two temptations here and both were refused.
//!
//! The first was to give `F_p^4` its own curve type. The arithmetic
//! genuinely differs between degrees — a tower multiplies differently
//! from a pair of integers — but the group law does not: the same slope,
//! the same doubling, the same left-to-right ladder. Two copies of it
//! would be two things to keep in step, and this project spent a review
//! cycle on bugs of exactly that shape, where a value was read correctly
//! in one place and not in its twin.
//!
//! The second was to widen the existing element type to a vector of
//! coefficients and branch on its length inside every operation. That
//! reads shorter and hides the degree in a runtime value, so a
//! degree-two element could reach degree-four code and be quietly padded.
//! An error in the type system is worth more than an error in a comment.
//!
//! So: a trait for the arithmetic a curve needs, one generic curve, and
//! each field implements the trait however its degree requires. What
//! stays duplicated is what is genuinely different, and nothing else.

use num_bigint::{BigInt, BigUint};
use num_traits::Zero;

use crate::ec::EcError;

/// What a curve needs of the field it lives over.
///
/// Deliberately small. Anything a field can do that the group law does
/// not need — norms, square roots, exponentiation — stays on the concrete
/// type where it can be written in whatever way suits that degree.
pub trait Field {
    /// One element. `Eq` because the group law compares abscissas, and
    /// `Clone` because affine formulas need the operands afterwards.
    type Elem: Clone + PartialEq + Eq;

    /// How many integers an element of this field is written as. Part
    /// of the format, not an implementation detail: a payload carries
    /// exactly this many coefficients per parameter.
    fn degree(&self) -> u32;

    /// The characteristic, for the one spelling per number check that
    /// every payload reader has to make.
    fn characteristic(&self) -> &BigUint;

    /// An element from its coefficients, low order first. Refuses a list
    /// of the wrong length rather than padding it, because a padded list
    /// silently describes a different point.
    fn element_from(&self, coefficients: &[BigUint]) -> Result<Self::Elem, String>;

    /// Bounds on the order of a curve over this field, inclusive.
    ///
    /// Every field knows its own, and the shapes differ: at degrees 2 and
    /// 4 the square root of `q` is exact, at degree 1 it is not and the
    /// integer root must be widened. Putting it on the trait means a
    /// caller can check an order against the window without asking which
    /// degree it is looking at.
    fn hasse_window(&self) -> (BigInt, BigInt);

    fn is_zero(&self, a: &Self::Elem) -> bool;
    fn add(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem;
    fn sub(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem;
    fn mul(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem;
    fn square(&self, a: &Self::Elem) -> Self::Elem;
    /// Multiplication by a small integer, which every degree can do
    /// without a full field multiplication.
    fn scale(&self, a: &Self::Elem, k: u32) -> Self::Elem;
    fn div(&self, a: &Self::Elem, b: &Self::Elem) -> Result<Self::Elem, EcError>;
}

/// A point, or the identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pt<E> {
    Infinity,
    Affine { x: E, y: E },
}

/// `y^2 = x^3 + a x + b` over any `Field`.
pub struct Curve<'a, F: Field> {
    pub field: &'a F,
    pub a: F::Elem,
    pub b: F::Elem,
}

impl<'a, F: Field> Curve<'a, F> {
    pub fn new(field: &'a F, a: F::Elem, b: F::Elem) -> Result<Self, String> {
        let curve = Curve { field, a, b };
        // 4a^3 + 27b^2 must not vanish, or the points are not a group and
        // every order computed on them is about nothing.
        let cube = field.mul(&field.square(&curve.a), &curve.a);
        let disc = field.add(
            &field.scale(&cube, 4),
            &field.scale(&field.square(&curve.b), 27),
        );
        if field.is_zero(&disc) {
            return Err("curve: 4a^3 + 27b^2 vanishes, so the curve is singular".into());
        }
        Ok(curve)
    }

    pub fn contains(&self, point: &Pt<F::Elem>) -> bool {
        let Pt::Affine { x, y } = point else {
            return true;
        };
        let f = self.field;
        let right = f.add(&f.add(&f.mul(&f.square(x), x), &f.mul(&self.a, x)), &self.b);
        f.square(y) == right
    }

    pub fn double(&self, point: &Pt<F::Elem>) -> Result<Pt<F::Elem>, EcError> {
        let Pt::Affine { x, y } = point else {
            return Ok(Pt::Infinity);
        };
        let f = self.field;
        if f.is_zero(y) {
            return Ok(Pt::Infinity);
        }
        let numerator = f.add(&f.scale(&f.square(x), 3), &self.a);
        let slope = f.div(&numerator, &f.scale(y, 2))?;
        let x_new = f.sub(&f.square(&slope), &f.scale(x, 2));
        let y_new = f.sub(&f.mul(&slope, &f.sub(x, &x_new)), y);
        Ok(Pt::Affine { x: x_new, y: y_new })
    }

    pub fn add(
        &self,
        left: &Pt<F::Elem>,
        right: &Pt<F::Elem>,
    ) -> Result<Pt<F::Elem>, EcError> {
        let (Pt::Affine { x: x1, y: y1 }, Pt::Affine { x: x2, y: y2 }) = (left, right) else {
            return Ok(match left {
                Pt::Infinity => right.clone(),
                _ => left.clone(),
            });
        };
        if x1 == x2 {
            return if y1 == y2 && !self.field.is_zero(y1) {
                self.double(left)
            } else {
                Ok(Pt::Infinity)
            };
        }
        let f = self.field;
        let slope = f.div(&f.sub(y2, y1), &f.sub(x2, x1))?;
        let x_new = f.sub(&f.sub(&f.square(&slope), x1), x2);
        let y_new = f.sub(&f.mul(&slope, &f.sub(x1, &x_new)), y1);
        Ok(Pt::Affine { x: x_new, y: y_new })
    }

    /// Left-to-right double-and-add. Everything here is public, so there
    /// is nothing to hide from a timing observer and no reason to pay for
    /// hiding it.
    pub fn multiply(
        &self,
        scalar: &BigUint,
        point: &Pt<F::Elem>,
    ) -> Result<Pt<F::Elem>, EcError> {
        if scalar.is_zero() {
            return Ok(Pt::Infinity);
        }
        let mut result = Pt::Infinity;
        for index in (0..scalar.bits()).rev() {
            result = self.double(&result)?;
            if scalar.bit(index) {
                result = self.add(&result, point)?;
            }
        }
        Ok(result)
    }
}
