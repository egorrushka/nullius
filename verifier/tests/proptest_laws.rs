//! Laws the arithmetic must obey, checked over thousands of random inputs.
//!
//! The fuzzer attacks the parser and the whole path; this attacks the
//! algebra underneath. A field is a field or it is not, and the cheapest
//! way to catch a formula that is subtly wrong — a sign, a missing
//! reduction, a cross term — is to assert the laws a field must satisfy
//! and let random inputs hunt for the counterexample a fixed test would
//! never reach.
//!
//! Field laws run over a small prime: correctness of a formula does not
//! depend on the size of p, and a small modulus buys far more cases per
//! second, so the search is deeper where depth is what finds bugs. Curve
//! laws run over the real secp256k1, with points generated as multiples
//! of the generator so every one of them genuinely lies on the curve —
//! random (x, y) pairs almost never do.

use num_bigint::BigUint;
use num_traits::Zero;
use proptest::prelude::*;

use ccert::ec::{Curve, Point};
use ccert::fq::{Elem, Fq};

// --- field: a small prime and a beta that is a non-residue there ---
const P: u64 = 2_147_483_647; // 2^31 - 1
const BETA: u64 = 3;

fn fp() -> Fq {
    Fq::new(BigUint::from(P), 1, None).unwrap()
}
fn fp2() -> Fq {
    Fq::new(BigUint::from(P), 2, Some(BigUint::from(BETA))).unwrap()
}

fn coeff() -> impl Strategy<Value = BigUint> {
    (0u64..P).prop_map(BigUint::from)
}

// a prime-field element
fn e1() -> impl Strategy<Value = Elem> {
    coeff().prop_map(|c0| (c0, BigUint::zero()))
}
// an F_p^2 element
fn e2() -> impl Strategy<Value = Elem> {
    (coeff(), coeff()).prop_map(|(c0, c1)| (c0, c1))
}

fn one1() -> Elem {
    (BigUint::from(1u32), BigUint::zero())
}

macro_rules! field_laws {
    ($name:ident, $field:expr, $strat:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1500))]
            #[test]
            fn $name(a in $strat, b in $strat, c in $strat) {
                let f = $field;
                // commutativity
                prop_assert_eq!(f.add(&a, &b), f.add(&b, &a));
                prop_assert_eq!(f.mul(&a, &b), f.mul(&b, &a));
                // associativity of +
                prop_assert_eq!(f.add(&f.add(&a, &b), &c), f.add(&a, &f.add(&b, &c)));
                // distributivity
                prop_assert_eq!(
                    f.mul(&a, &f.add(&b, &c)),
                    f.add(&f.mul(&a, &b), &f.mul(&a, &c))
                );
                // additive inverse via sub
                let zero = f.sub(&a, &a);
                prop_assert!(f.is_zero(&zero));
                // identities
                prop_assert_eq!(f.add(&a, &f.sub(&b, &b)), a.clone());
                prop_assert_eq!(f.mul(&a, &one1()), a.clone());
                // square agrees with mul
                prop_assert_eq!(f.square(&a), f.mul(&a, &a));
                // multiplicative inverse, for non-zero a
                if !f.is_zero(&a) {
                    let inv = f.inv(&a).expect("non-zero element inverts over a field");
                    prop_assert_eq!(f.mul(&a, &inv), one1());
                }
                // division undoes multiplication, for non-zero b
                if !f.is_zero(&b) {
                    let q = f.div(&a, &b).expect("division by non-zero");
                    prop_assert_eq!(f.mul(&q, &b), a.clone());
                }
            }
        }
    };
}

field_laws!(prime_field_is_a_field, fp(), e1());
field_laws!(quadratic_extension_is_a_field, fp2(), e2());

// --- curve: real secp256k1, points as [k]G ---
fn secp256k1() -> Curve {
    let p = BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16).unwrap();
    Curve::new(BigUint::zero(), BigUint::from(7u32), p)
}
fn generator() -> Point {
    Point::Affine {
        x: BigUint::parse_bytes(
            b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16).unwrap(),
        y: BigUint::parse_bytes(
            b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16).unwrap(),
    }
}
// -P = (x, p - y) on this curve; computed here so ec.rs is left untouched.
fn neg(c: &Curve, point: &Point) -> Point {
    match point {
        Point::Infinity => Point::Infinity,
        Point::Affine { x, y } => Point::Affine { x: x.clone(), y: (&c.n - y) % &c.n },
    }
}
fn scalar() -> impl Strategy<Value = BigUint> {
    proptest::collection::vec(any::<u8>(), 1..16)
        .prop_map(|bytes| BigUint::from_bytes_le(&bytes) + BigUint::from(1u32))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn multiples_of_the_generator_stay_on_the_curve(k in scalar()) {
        let c = secp256k1();
        let p = c.multiply(&k, &generator()).unwrap();
        prop_assert!(c.contains(&p));
    }

    #[test]
    fn identity_and_inverse(k in scalar()) {
        let c = secp256k1();
        let p = c.multiply(&k, &generator()).unwrap();
        // P + O = P, O + P = P
        prop_assert_eq!(c.add(&p, &Point::Infinity).unwrap(), p.clone());
        prop_assert_eq!(c.add(&Point::Infinity, &p).unwrap(), p.clone());
        // P + (-P) = O
        prop_assert_eq!(c.add(&p, &neg(&c, &p)).unwrap(), Point::Infinity);
    }

    #[test]
    fn addition_commutes(j in scalar(), k in scalar()) {
        let c = secp256k1();
        let g = generator();
        let p = c.multiply(&j, &g).unwrap();
        let q = c.multiply(&k, &g).unwrap();
        prop_assert_eq!(c.add(&p, &q).unwrap(), c.add(&q, &p).unwrap());
    }

    #[test]
    fn addition_associates(i in scalar(), j in scalar(), k in scalar()) {
        let c = secp256k1();
        let g = generator();
        let p = c.multiply(&i, &g).unwrap();
        let q = c.multiply(&j, &g).unwrap();
        let r = c.multiply(&k, &g).unwrap();
        let left = c.add(&c.add(&p, &q).unwrap(), &r).unwrap();
        let right = c.add(&p, &c.add(&q, &r).unwrap()).unwrap();
        prop_assert_eq!(left, right);
    }

    #[test]
    fn scalar_is_a_homomorphism(j in scalar(), k in scalar()) {
        let c = secp256k1();
        let g = generator();
        // [j]([k]G) = [j*k]G
        let lhs = c.multiply(&j, &c.multiply(&k, &g).unwrap()).unwrap();
        let rhs = c.multiply(&(&j * &k), &g).unwrap();
        prop_assert_eq!(lhs, rhs);
        // [j]G + [k]G = [j+k]G
        let sum = c.add(&c.multiply(&j, &g).unwrap(), &c.multiply(&k, &g).unwrap()).unwrap();
        let combined = c.multiply(&(&j + &k), &g).unwrap();
        prop_assert_eq!(sum, combined);
    }
}
