//! Arithmetic the verifier does for itself.
//!
//! Two things live here: modular integers, and points on a short
//! Weierstrass curve in affine coordinates. Affine means an inversion per
//! operation, which is slower than projective coordinates and much easier
//! to read. For a verifier that trade is the right way round.
//!
//! The modulus is not assumed prime. Certificate checking works over a
//! number whose primality is exactly what is in question, so an inversion
//! can genuinely fail. When it does we say so instead of guessing.

use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Zero};

/// A point, or the identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Point {
    Infinity,
    Affine { x: BigUint, y: BigUint },
}

/// `y^2 = x^3 + ax + b` over `Z/nZ`, where n need not be prime.
pub struct Curve {
    pub a: BigUint,
    pub b: BigUint,
    pub n: BigUint,
}

#[derive(Debug)]
pub enum EcError {
    /// A denominator shared a factor with the modulus, which for a prime
    /// modulus cannot happen and for a composite one reveals it.
    NotInvertible(BigUint),
}

fn to_uint(value: BigInt, modulus: &BigUint) -> BigUint {
    let m = BigInt::from(modulus.clone());
    let reduced = value.mod_floor(&m);
    reduced.to_biguint().expect("mod_floor result is non-negative")
}

/// Modular inverse by the extended Euclidean algorithm.
pub fn invert(value: &BigUint, modulus: &BigUint) -> Result<BigUint, EcError> {
    let value = value % modulus;
    if value.is_zero() {
        return Err(EcError::NotInvertible(modulus.clone()));
    }
    let extended = BigInt::from(value.clone()).extended_gcd(&BigInt::from(modulus.clone()));
    if !extended.gcd.is_one() {
        let shared = extended
            .gcd
            .to_biguint()
            .unwrap_or_else(|| modulus.clone());
        return Err(EcError::NotInvertible(shared));
    }
    Ok(to_uint(extended.x, modulus))
}

impl Curve {
    pub fn new(a: BigUint, b: BigUint, n: BigUint) -> Self {
        Curve {
            a: a % &n,
            b: b % &n,
            n,
        }
    }

    /// Recover b from a point that is required to lie on the curve.
    pub fn b_from_point(a: &BigUint, x: &BigUint, y: &BigUint, n: &BigUint) -> BigUint {
        let left = (y * y) % n;
        let right = (x * x % n * x % n + a * x % n) % n;
        let left = BigInt::from(left) - BigInt::from(right);
        to_uint(left, n)
    }

    /// `4a^3 + 27b^2`, whose invertibility means the curve is non-singular.
    pub fn discriminant_unit(&self) -> BigUint {
        let n = &self.n;
        let a3 = &self.a * &self.a % n * &self.a % n;
        let b2 = &self.b * &self.b % n;
        (BigUint::from(4u32) * a3 + BigUint::from(27u32) * b2) % n
    }

    pub fn contains(&self, point: &Point) -> bool {
        match point {
            Point::Infinity => true,
            Point::Affine { x, y } => {
                let n = &self.n;
                let left = y * y % n;
                let right = (x * x % n * x % n + &self.a * x % n + &self.b) % n;
                left == right
            }
        }
    }

    pub fn double(&self, point: &Point) -> Result<Point, EcError> {
        let Point::Affine { x, y } = point else {
            return Ok(Point::Infinity);
        };
        let n = &self.n;
        if (y + y) % n == BigUint::zero() {
            return Ok(Point::Infinity);
        }
        let numerator = (BigUint::from(3u32) * (x * x % n) % n + &self.a) % n;
        let slope = numerator * invert(&((y + y) % n), n)? % n;

        let x_new = to_uint(
            BigInt::from(&slope * &slope % n) - BigInt::from(x + x),
            n,
        );
        let y_new = to_uint(
            BigInt::from(slope.clone()) * (BigInt::from(x.clone()) - BigInt::from(x_new.clone()))
                - BigInt::from(y.clone()),
            n,
        );
        Ok(Point::Affine { x: x_new, y: y_new })
    }

    pub fn add(&self, left: &Point, right: &Point) -> Result<Point, EcError> {
        let (Point::Affine { x: x1, y: y1 }, Point::Affine { x: x2, y: y2 }) = (left, right) else {
            return Ok(match left {
                Point::Infinity => right.clone(),
                _ => left.clone(),
            });
        };
        if x1 == x2 {
            return if y1 == y2 {
                self.double(left)
            } else {
                Ok(Point::Infinity)
            };
        }
        let n = &self.n;
        let dy = to_uint(BigInt::from(y2.clone()) - BigInt::from(y1.clone()), n);
        let dx = to_uint(BigInt::from(x2.clone()) - BigInt::from(x1.clone()), n);
        let slope = dy * invert(&dx, n)? % n;

        let x_new = to_uint(
            BigInt::from(&slope * &slope % n) - BigInt::from(x1.clone()) - BigInt::from(x2.clone()),
            n,
        );
        let y_new = to_uint(
            BigInt::from(slope.clone()) * (BigInt::from(x1.clone()) - BigInt::from(x_new.clone()))
                - BigInt::from(y1.clone()),
            n,
        );
        Ok(Point::Affine { x: x_new, y: y_new })
    }

    /// Left-to-right double-and-add. Not constant time, and it does not
    /// need to be: everything here is public.
    pub fn multiply(&self, scalar: &BigUint, point: &Point) -> Result<Point, EcError> {
        if scalar.is_zero() {
            return Ok(Point::Infinity);
        }
        let mut result = Point::Infinity;
        for index in (0..scalar.bits()).rev() {
            result = self.double(&result)?;
            if scalar.bit(index) {
                result = self.add(&result, point)?;
            }
        }
        Ok(result)
    }
}

/// Deterministic Miller-Rabin, used only where determinism is established.
///
/// For n below 3.3 * 10^24 the bases below decide primality outright; that
/// is a published, independently checked result, and it is the one place
/// this verifier leans on something it does not recompute. Above that
/// bound the caller must not use this function, and does not.

const BASES: [u32; 13] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41];

pub fn is_prime_small(n: &BigUint) -> bool {
    let two = BigUint::from(2u32);
    if n < &two {
        return false;
    }
    for base in BASES {
        let candidate = BigUint::from(base);
        if n == &candidate {
            return true;
        }
        if (n % &candidate).is_zero() {
            return false;
        }
    }

    let one = BigUint::one();
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut r = 0u64;
    while !d.bit(0) {
        d >>= 1;
        r += 1;
    }

    'outer: for base in BASES {
        let mut x = BigUint::from(base).modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }
        for _ in 1..r {
            x = x.modpow(&two, n);
            if x == n_minus_one {
                continue 'outer;
            }
        }
        return false;
    }
    true
}
