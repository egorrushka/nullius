//! What each claim means, and how it is re-established.
//!
//! One function per evidence type, and each one is written so that it can
//! be read without the rest of the project in mind: it takes the numbers
//! the bundle states, recomputes what it can, and refuses when the two
//! disagree. Nothing here trusts the producer's arithmetic.
//!
//! These live apart from `verify.rs` because that file is about the shape
//! of a document, and this one is about mathematics. Mixing them made the
//! only component people are expected to audit harder to read.

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};

use sha1::{Digest as Sha1Digest, Sha1};

use crate::ec::{is_prime_small, Curve, EcError, Point};
use crate::ecpp::{small_prime_limit, verify_chain, Step};
use crate::json::Node;

/// Parse a decimal string in the one spelling the format allows.
pub fn decimal(text: &str, ctx: &str) -> Result<BigUint, String> {
    let valid = text == "0"
        || (!text.starts_with('0')
            && !text.is_empty()
            && text.bytes().all(|b| b.is_ascii_digit()));
    if !valid {
        return Err(format!("{ctx}: not a canonical decimal string: `{text}`"));
    }
    BigUint::parse_bytes(text.as_bytes(), 10).ok_or_else(|| format!("{ctx}: bad decimal"))
}

pub fn signed(text: &str, ctx: &str) -> Result<BigInt, String> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let magnitude = decimal(digits, ctx)?;
    if negative && magnitude == BigUint::from(0u32) {
        return Err(format!("{ctx}: `-0` is not canonical"));
    }
    let value = BigInt::from(magnitude);
    Ok(if negative { -value } else { value })
}

/// Bounds on the number of points, recomputed with integer arithmetic.
pub fn hasse(p: &BigUint) -> (BigUint, BigUint) {
    let one = BigUint::one();
    let root = (&one + &one + &one + &one).mul_root(p);
    let centre = p + &one;
    (&centre - &root - &one, &centre + &root + &one)
}

trait MulRoot {
    fn mul_root(&self, other: &BigUint) -> BigUint;
}

impl MulRoot for BigUint {
    /// isqrt(self * other), so `2*sqrt(p)` never touches a float.
    fn mul_root(&self, other: &BigUint) -> BigUint {
        (self * other).sqrt()
    }
}

pub fn find_assert<'a>(claims: &'a [Node], claim: &str, field: &str) -> Result<&'a str, String> {
    for node in claims {
        if node.get("claim").and_then(Node::as_str) == Some(claim) {
            return node
                .field("asserts", claim)?
                .str_field(field, claim)
                .map_err(|e| e.to_string());
        }
    }
    Err(format!("this bundle needs claim `{claim}`, which is absent"))
}

pub fn parse_steps(payload: &Node, name: &str) -> Result<Vec<Step>, String> {
    let raw = payload
        .field("steps", name)?
        .as_array()
        .ok_or_else(|| format!("{name}: steps must be an array"))?;
    let mut steps = Vec::with_capacity(raw.len());
    for node in raw {
        steps.push(Step {
            n: decimal(node.str_field("N", name)?, "step.N")?,
            t: signed(node.str_field("t", name)?, "step.t")?,
            s: decimal(node.str_field("s", name)?, "step.s")?,
            a: decimal(node.str_field("a", name)?, "step.a")?,
            x: decimal(node.str_field("x", name)?, "step.x")?,
            y: decimal(node.str_field("y", name)?, "step.y")?,
        });
    }
    Ok(steps)
}

/// Reads a factor list, proving each entry prime and returning the product.
///
/// A composite smuggled in as a factor is the way both the order argument
/// and the discriminant argument fail quietly, so this is the one helper
/// worth reading twice.
pub fn read_factors(
    payload: &Node,
    ctx: &str,
) -> Result<(BigUint, Vec<(BigUint, u32)>), String> {
    let raw = payload
        .field("factors", ctx)?
        .as_array()
        .ok_or_else(|| format!("{ctx}: factors must be an array"))?;
    let mut product = BigUint::one();
    let mut collected = Vec::new();
    for entry in raw {
        let prime = decimal(entry.str_field("prime", ctx)?, "factor.prime")?;
        let exponent = decimal(entry.str_field("exponent", ctx)?, "factor.exponent")?;
        if prime < BigUint::from(2u32) || exponent < BigUint::one() {
            return Err(format!("{ctx}: a factor is not a prime power"));
        }
        match entry.get("steps") {
            Some(_) => {
                let steps = parse_steps(entry, ctx)?;
                verify_chain(&prime, &steps)
                    .map_err(|e| format!("{ctx}: factor of {} bits: {e}", prime.bits()))?;
            }
            None => {
                // Without a chain the only tool left is the deterministic
                // base set, and that decides nothing above its bound.
                if prime >= small_prime_limit() || !is_prime_small(&prime) {
                    return Err(format!(
                        "{ctx}: a factor of {} bits came with no chain and is \
                         too large to settle here",
                        prime.bits()
                    ));
                }
            }
        }
        let exponent =
            u32::try_from(exponent).map_err(|_| format!("{ctx}: absurd exponent"))?;
        product *= prime.pow(exponent);
        collected.push((prime, exponent));
    }
    Ok((product, collected))
}

/// Re-check an Atkin-Morain chain from the evidence pool.
pub fn check_ecpp(name: &str, asserts: &Node, payload: &Node) -> Result<String, String> {
    let field = if name == "field.characteristic" { "p" } else { "n" };
    let claimed = decimal(asserts.str_field(field, name)?, name)?;
    if asserts.str_field("prime", name)? != "proved" {
        return Err(format!("{name}: an ECPP chain proves primality outright"));
    }
    let subject = decimal(payload.str_field("subject", name)?, name)?;
    if subject != claimed {
        return Err(format!("{name}: the chain is about a different number"));
    }

    let steps = parse_steps(payload, name)?;
    verify_chain(&claimed, &steps).map_err(|e| format!("{name}: {e}"))
}

pub fn check_hasse(p: &BigUint, asserts: &Node, claims: &[Node]) -> Result<String, String> {
    let low = decimal(asserts.str_field("low", "curve.hasse")?, "curve.hasse.low")?;
    let high = decimal(asserts.str_field("high", "curve.hasse")?, "curve.hasse.high")?;
    let contains = decimal(
        asserts.str_field("contains", "curve.hasse")?,
        "curve.hasse.contains",
    )?;

    let (expected_low, expected_high) = hasse(p);
    if low != expected_low || high != expected_high {
        return Err("curve.hasse: the stated bounds are not the Hasse bounds for this p".into());
    }
    if contains < low || contains > high {
        return Err("curve.hasse: the stated value lies outside the bounds".into());
    }

    // The claim is only about the cardinality if it is the cardinality.
    let n = decimal(find_assert(claims, "curve.order", "n")?, "curve.order.n")?;
    if n != contains {
        return Err("curve.hasse: bounds a value that is not the stated cardinality".into());
    }
    Ok("bounds recomputed from p".into())
}

pub fn check_twist(p: &BigUint, asserts: &Node, claims: &[Node]) -> Result<String, String> {
    let identity = asserts.str_field("identity", "twist.cardinality")?;
    if identity != "n + n_twist = 2p + 2" {
        return Err(format!("twist.cardinality: unexpected identity `{identity}`"));
    }
    let twist = decimal(
        asserts.str_field("n_twist", "twist.cardinality")?,
        "twist.cardinality.n_twist",
    )?;
    let n = decimal(find_assert(claims, "curve.order", "n")?, "curve.order.n")?;
    let two = BigUint::from(2u32);
    if &n + &twist != &two * p + &two {
        return Err("twist.cardinality: the identity does not hold".into());
    }
    Ok("identity re-derived; sound only if the cardinality is".into())
}

/// The order is pinned down by a point of prime order n with n larger than
/// the Hasse window: the window then holds no other multiple of n, so the
/// group order has nowhere else to be.
pub fn check_order(
    p: &BigUint,
    subject: &Node,
    asserts: &Node,
    payload: &Node,
) -> Result<String, String> {
    let n = decimal(asserts.str_field("n", "curve.order")?, "curve.order.n")?;
    if asserts.str_field("cofactor", "curve.order")? != "1" {
        return Err("curve.order: only cofactor 1 is supported".into());
    }

    // n^2 > 16p is n > 4*sqrt(p), without a square root.
    if &n * &n <= BigUint::from(16u32) * p {
        return Err("curve.order: n does not exceed the Hasse window".into());
    }
    let (low, high) = hasse(p);
    if n < low || n > high {
        return Err("curve.order: n is outside the Hasse window".into());
    }

    let a = decimal(subject.str_field("a", "subject")?, "subject.a")?;
    let b = decimal(subject.str_field("b", "subject")?, "subject.b")?;
    let curve = Curve::new(a, b, p.clone());
    if curve.discriminant_unit().gcd(p) != BigUint::one() {
        return Err("curve.order: the curve is singular".into());
    }

    let witness = payload.field("point", "curve.order")?;
    let point = Point::Affine {
        x: decimal(witness.str_field("x", "point")?, "point.x")?,
        y: decimal(witness.str_field("y", "point")?, "point.y")?,
    };
    if !curve.contains(&point) {
        return Err("curve.order: the witness point is not on the curve".into());
    }

    let describe = |err: EcError| match err {
        EcError::NotInvertible(_) => "curve.order: arithmetic modulo p broke down".to_string(),
    };
    if curve.multiply(&n, &point).map_err(describe)? != Point::Infinity {
        return Err("curve.order: n times the witness is not the identity".into());
    }

    Ok("witness of order n; no other multiple fits the window".into())
}

/// The exact order of p in the group modulo n, which for a curve is the
/// embedding degree: the smallest k with n dividing p^k - 1.
///
/// The order d is established, not measured. Given a complete factorisation
/// of n - 1 into proved primes, d is the order exactly when p^d = 1 and
/// p^(d/l) != 1 for every prime l dividing d. Both directions matter: the
/// first bounds the order above, the second rules out every proper divisor
/// at once.
pub fn check_order_of_element(
    p: &BigUint,
    asserts: &Node,
    payload: &Node,
    claims: &[Node],
) -> Result<String, String> {
    let ctx = "curve.embedding";
    let one = BigUint::one();

    let base = decimal(payload.str_field("base", ctx)?, "embedding.base")?;
    let modulus = decimal(payload.str_field("modulus", ctx)?, "embedding.modulus")?;
    let order = decimal(payload.str_field("order", ctx)?, "embedding.order")?;
    let claimed = decimal(asserts.str_field("degree", ctx)?, "embedding.degree")?;

    if base != *p {
        return Err(format!("{ctx}: the base is not the field characteristic"));
    }
    let n = decimal(find_assert(claims, "curve.order", "n")?, "curve.order.n")?;
    if modulus != n {
        return Err(format!("{ctx}: the modulus is not the group order"));
    }
    if order != claimed {
        return Err(format!("{ctx}: the evidence is about a different degree"));
    }

    // The factorisation must be complete and its parts genuinely prime,
    // or a "prime" divisor could hide a smaller order behind it.
    let group_order = &n - &one;
    let (product, factors) = read_factors(payload, ctx)?;
    if product != group_order {
        return Err(format!("{ctx}: the factors do not multiply back to n - 1"));
    }
    let primes: Vec<BigUint> = factors.into_iter().map(|(prime, _)| prime).collect();

    if (&group_order % &order) != BigUint::zero() {
        return Err(format!("{ctx}: the degree does not divide n - 1"));
    }
    if base.modpow(&order, &n) != one {
        return Err(format!("{ctx}: the base raised to the degree is not one"));
    }
    for prime in &primes {
        if (&order % prime) != BigUint::zero() {
            continue;
        }
        if base.modpow(&(&order / prime), &n) == one {
            return Err(format!("{ctx}: the true order is smaller than claimed"));
        }
    }

    // A degree this size is what makes pairing transfers useless; a small
    // one would be the headline finding about the curve.
    let ratio = if order.bits() + 8 >= n.bits() {
        "comparable to n"
    } else {
        "far below n"
    };
    Ok(format!("exact order, {} bits, {ratio}", order.bits()))
}

/// The discriminant of the CM field the curve comes from.
///
/// Every discriminant splits as f^2 * D with D fundamental, and D is what
/// names the field. Checking the split is one multiplication; the work is
/// showing D really is fundamental, which needs its factorisation into
/// proved primes with no repeats.
///
/// The size of |D| is a fact, not a verdict. A tiny discriminant means the
/// curve has an efficiently computable endomorphism: a liability to some
/// policies, a feature to others. This verifier reports it and stops there.
pub fn check_cm(
    p: &BigUint,
    asserts: &Node,
    payload: &Node,
    claims: &[Node],
) -> Result<String, String> {
    let ctx = "curve.cm";
    let trace = signed(asserts.str_field("trace", ctx)?, "cm.trace")?;
    let fundamental = signed(asserts.str_field("fundamental", ctx)?, "cm.fundamental")?;
    let conductor = decimal(asserts.str_field("conductor", ctx)?, "cm.conductor")?;

    if payload.str_field("fundamental", ctx)? != asserts.str_field("fundamental", ctx)?
        || payload.str_field("conductor", ctx)? != asserts.str_field("conductor", ctx)?
    {
        return Err(format!("{ctx}: the evidence is about a different discriminant"));
    }

    // The trace is not taken on faith: it follows from p and the order.
    let n = decimal(find_assert(claims, "curve.order", "n")?, "curve.order.n")?;
    let expected = BigInt::from(p.clone()) + BigInt::one() - BigInt::from(n);
    if trace != expected {
        return Err(format!("{ctx}: the trace does not match p and n"));
    }

    let discriminant = &trace * &trace - BigInt::from(4u32) * BigInt::from(p.clone());
    if discriminant.sign() != Sign::Minus {
        return Err(format!("{ctx}: the discriminant is not negative"));
    }
    let square = BigInt::from(conductor.clone()) * BigInt::from(conductor.clone());
    if &square * &fundamental != discriminant {
        return Err(format!("{ctx}: conductor squared times D is not the discriminant"));
    }

    // Fundamental means D = 1 mod 4 with D squarefree, or D = 4m with
    // m = 2 or 3 mod 4 and m squarefree. Anything else is not maximal, so
    // the conductor was understated and |D| overstated.
    let magnitude = (-&fundamental).to_biguint().expect("negative discriminant");
    let four = BigUint::from(4u32);
    let residue = ((&fundamental % BigInt::from(4u32)) + BigInt::from(4u32))
        % BigInt::from(4u32);
    let core = if residue == BigInt::one() {
        magnitude.clone()
    } else if residue.is_zero() {
        let quarter = &magnitude / &four;
        let quarter_residue = (&quarter % &four).to_string();
        if quarter_residue != "1" && quarter_residue != "2" {
            return Err(format!("{ctx}: D is divisible by four but not fundamental"));
        }
        quarter
    } else {
        return Err(format!("{ctx}: D is neither 0 nor 1 modulo 4"));
    };

    let (product, factors) = read_factors(payload, ctx)?;
    if core == BigUint::one() {
        if !factors.is_empty() {
            return Err(format!("{ctx}: factors given for a unit"));
        }
    } else {
        if product != core {
            return Err(format!("{ctx}: the factors do not multiply back to |D|"));
        }
        if factors.iter().any(|(_, exponent)| *exponent != 1) {
            return Err(format!("{ctx}: D is not squarefree, so it is not fundamental"));
        }
    }

    Ok(format!("|D| is {} bits, fundamental", magnitude.bits()))
}


/// Rerun the derivation that turns a published seed into the curve.
///
/// The procedure is ANSI X9.62, also A.1.3 of FIPS 186-4. With t the bit
/// length of p, s = (t - 1) / 160 and h = t - 160s:
///
///   H  = SHA-1(seed); c0 is the rightmost h bits with the leftmost cleared
///   Wi = SHA-1((seed + i) mod 2^g) for i = 1..s
///   c  = c0 || W1 || ... || Ws
///
/// and the curve must satisfy c * b^2 = -27 (mod p).
///
/// SHA-1 being broken for collisions does not weaken this. Nothing here
/// rests on the difficulty of finding two inputs that hash alike; the check
/// reproduces one published derivation from one published seed.
///
/// What this establishes is narrow and worth stating plainly: b follows
/// from the seed. Where the seed came from is a separate question this
/// check cannot touch.
pub fn check_rigidity(
    p: &BigUint,
    subject: &Node,
    asserts: &Node,
    payload: &Node,
) -> Result<String, String> {
    let ctx = "param.rigidity";
    if asserts.str_field("reproduced", ctx)? != "1" {
        return Err(format!("{ctx}: the claim does not assert a reproduction"));
    }
    let method = asserts.str_field("method", ctx)?;
    if method != "ansi-x9.62-sha1" {
        return Err(format!("{ctx}: unknown derivation method `{method}`"));
    }
    if payload.str_field("method", ctx)? != method {
        return Err(format!("{ctx}: the evidence names a different method"));
    }

    let seed_hex = payload.str_field("seed", ctx)?;
    let seed = decode_hex(seed_hex).ok_or_else(|| format!("{ctx}: the seed is not hex"))?;
    if seed.len() * 8 < 160 {
        return Err(format!("{ctx}: the seed is shorter than the standard allows"));
    }

    let b = decimal(subject.str_field("b", "subject")?, "subject.b")?;
    let c = derive_c(&seed, p);

    // c * b^2 = -27 (mod p), written without a negative number.
    let left = &c * &b % p * &b % p;
    let right = (p - BigUint::from(27u32) % p) % p;
    if left != right {
        return Err(format!("{ctx}: the seed does not reproduce this curve"));
    }
    Ok(format!("b re-derived from a {}-bit seed", seed.len() * 8))
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || text.is_empty() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

fn derive_c(seed: &[u8], p: &BigUint) -> BigUint {
    let bits = seed.len() * 8;
    let length = p.bits() as usize;
    let blocks = (length - 1) / 160;
    let remainder = length - 160 * blocks;

    let digest = BigUint::from_bytes_be(&Sha1::digest(seed));
    let mask = (BigUint::one() << remainder) - BigUint::one();
    let mut c0 = digest & mask;
    if c0.bit((remainder - 1) as u64) {
        c0.set_bit((remainder - 1) as u64, false);
    }

    let mut value = c0;
    let base = BigUint::from_bytes_be(seed);
    let modulus = BigUint::one() << bits;
    for index in 1..=blocks {
        let stepped = (&base + BigUint::from(index)) % &modulus;
        let mut bytes = stepped.to_bytes_be();
        while bytes.len() < seed.len() {
            bytes.insert(0, 0);
        }
        value = (value << 160) | BigUint::from_bytes_be(&Sha1::digest(&bytes));
    }
    value
}
