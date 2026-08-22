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

/// A value from another claim, but only if that claim is proved.
///
/// The plain `find_assert` reads whatever it finds. That is enough when a
/// value is being reported and not leaned on; it is not enough when a
/// conclusion rests on it. A bundle could otherwise state a cardinality
/// on `candidate.sea`, which carries no weight at all, and then split it
/// with `check.cofactor` to obtain a proved-looking subgroup order. The
/// arithmetic in that split is exact and the tier table is honest about
/// each evidence kind on its own; the hole is that nothing checked what
/// the arithmetic was standing on.
///
/// The third design rule — nothing rests on anything weaker than itself —
/// was enforced only through declared `depends_on` edges, and declaring
/// them was optional. This closes that at the point of reading, which
/// does not depend on a producer choosing to be honest.
///
/// `claim` must be a literal from the verifier's own source. Taking the
/// name from bundle data would introduce an indirection nobody could
/// audit.
/// The number of points on the curve, from whichever claim states it.
///
/// `curve.order` carries the subgroup order and a cofactor. On a curve
/// with cofactor one those are the same number, which is why several
/// handlers read it and were right to. On a pairing-friendly curve they
/// are not: BLS12-381's cofactor is 126 bits wide, and a trace computed
/// from the subgroup order is a trace for no curve at all.
///
/// So `curve.cardinality` wins when it is present. Present-but-weak is
/// distinguished from absent on purpose: falling back to `curve.order`
/// because the cardinality was only a candidate would be a silent
/// downgrade, and this file exists to have none of those.
pub fn find_cardinality(claims: &[Node], declared: &[&str], ctx: &str) -> Result<BigUint, String> {
    let stated = claims
        .iter()
        .any(|c| c.get("claim").and_then(Node::as_str) == Some("curve.cardinality"));
    // Whichever claim supplies the number has to be one the caller
    // declared. The static table cannot express "curve.cardinality when
    // the bundle has one", so the requirement is enforced here, where the
    // read happens. Declared-and-unread was one hole; read-and-undeclared
    // is the same hole facing the other way.
    let source = if stated { "curve.cardinality" } else { "curve.order" };
    if !declared.contains(&source) {
        return Err(format!(
            "{ctx}: reads `{source}` and must declare it"
        ));
    }
    if !stated {
        // The fallback is safe only because of something nothing checked.
        //
        // `curve.order` names a subgroup order. Reading it as the number
        // of points is right exactly when the two coincide, and today
        // they always do on the path that reaches here: the only evidence
        // kind that can establish `curve.order` without a
        // `curve.cardinality` claim beside it is `check.order-unique`,
        // which pins the cardinality itself and asserts it under that
        // name. `check.cofactor` cannot get here, because it requires
        // `curve.cardinality` to exist.
        //
        // That is an argument, and an argument is not a check. A future
        // evidence kind producing `curve.order` as a subgroup order would
        // silently make `curve.hasse`, `curve.cm` and `twist.cardinality`
        // read `r` where they mean `#E` — the fourth instance of the one
        // pattern that has produced every serious bug in this project.
        // So the invariant is stated here, where the read happens, and it
        // fails loudly rather than being rediscovered.
        let kind = claims
            .iter()
            .find(|c| c.get("claim").and_then(Node::as_str) == Some("curve.order"))
            .ok_or_else(|| format!("{ctx}: this bundle needs a cardinality and has none"))?
            .field("evidence", "curve.order")?
            .str_field("type", "curve.order")?;
        if kind != "check.order-unique" {
            return Err(format!(
                "{ctx}: with no `curve.cardinality` claim the number of points \
                 can only come from `curve.order`, and only `check.order-unique` \
                 establishes that it is the number of points; this bundle offers \
                 `{kind}`"
            ));
        }
    }
    decimal(
        find_proved_assert(claims, source, "n")?,
        if stated { "curve.cardinality.n" } else { "curve.order.n" },
    )
}

pub fn find_proved_assert<'a>(
    claims: &'a [Node],
    claim: &str,
    field: &str,
) -> Result<&'a str, String> {
    for node in claims {
        if node.get("claim").and_then(Node::as_str) != Some(claim) {
            continue;
        }
        let kind = node
            .field("evidence", claim)?
            .str_field("type", claim)
            .map_err(|e| e.to_string())?;
        match crate::verify::tier_of(kind) {
            Some(crate::verify::Tier::Proved) => {}
            Some(tier) => {
                return Err(format!(
                    "this bundle rests on `{claim}`, which is only {}",
                    tier.label()
                ))
            }
            None => {
                return Err(format!(
                    "this bundle rests on `{claim}`, whose evidence type \
                     `{kind}` is unknown"
                ))
            }
        }
        return node
            .field("asserts", claim)?
            .str_field(field, claim)
            .map_err(|e| e.to_string());
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
        // A chain step is six numbers and nothing else. Anything beside
        // them is a line in the argument that no check covers, which is
        // the same defect as an elimination point ruling nothing out.
        node.closed_keys(&["N", "t", "s", "a", "x", "y"], "chain step")?;
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
/// Factors from a payload, with their primality settled.
///
/// `max_bits` is the size of the number the product will be compared
/// against, plus one. It exists to stop a hostile certificate from
/// costing hundreds of megabytes before it is rejected: `prime = 2` with
/// `exponent = 4e9` is a well formed entry, and computing that power to
/// discover the product is wrong is a poor order of operations.
///
/// The early refusal is exact rather than a heuristic. For `p >= 2`,
/// `bits(p^e) >= e*(bits(p) - 1) + 1`, and it is that lower bound which
/// is compared against `max_bits` — once it exceeds, the power cannot
/// divide the target and no honest factorisation is ever refused.
///
/// Comparing `bits(p) * e` instead looks equivalent and is not. That is
/// an upper bound, and using it rejected `2^3` against a four-bit
/// cofactor: every curve with a power-of-two cofactor, which is every
/// Edwards curve. The two expressions agree only when `p` is not a power
/// of two, which is why the mistake survived a corpus of four curves.
pub fn read_factors(
    payload: &Node,
    ctx: &str,
    max_bits: u64,
) -> Result<(BigUint, Vec<(BigUint, u32)>), String> {
    let raw = payload
        .field("factors", ctx)?
        .as_array()
        .ok_or_else(|| format!("{ctx}: factors must be an array"))?;
    let mut product = BigUint::one();
    let mut collected = Vec::new();
    for entry in raw {
        entry.closed_keys(&["prime", "exponent", "steps"], "factor")?;
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
        // e*(bits(p) - 1) + 1, which is the true lower bound on
        // bits(p^e). The obvious bits(p)*e overestimates, and for p = 2
        // it overestimates by enough to reject an honest cofactor of 8 —
        // every Edwards curve in existence. A guard against hostile input
        // that refuses ordinary input is worse than no guard.
        let lower_bound = (exponent as u64)
            .saturating_mul(prime.bits().saturating_sub(1))
            .saturating_add(1);
        if lower_bound > max_bits {
            return Err(format!(
                "{ctx}: a factor entry exceeds the number it claims to divide"
            ));
        }
        product *= prime.pow(exponent);
        // A second guard, against many small factors accumulating past
        // the target rather than one large one overshooting it.
        if product.bits() > max_bits {
            return Err(format!(
                "{ctx}: the factors already exceed the number they claim to \
                 multiply to"
            ));
        }
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

pub fn check_hasse(
    p: &BigUint,
    asserts: &Node,
    claims: &[Node],
    declared: &[&str],
) -> Result<String, String> {
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
    let n = find_cardinality(claims, declared, "curve.hasse")?;
    if n != contains {
        return Err("curve.hasse: bounds a value that is not the stated cardinality".into());
    }
    Ok("bounds recomputed from p".into())
}

pub fn check_twist(
    p: &BigUint,
    asserts: &Node,
    payload: Option<&Node>,
    claims: &[Node],
    declared: &[&str],
) -> Result<String, String> {
    let identity = asserts.str_field("identity", "twist.cardinality")?;
    if identity != "n + n_twist = 2p + 2" {
        return Err(format!("twist.cardinality: unexpected identity `{identity}`"));
    }
    let twist = decimal(
        asserts.str_field("n_twist", "twist.cardinality")?,
        "twist.cardinality.n_twist",
    )?;
    let n = find_cardinality(claims, declared, "twist.cardinality")?;
    let two = BigUint::from(2u32);
    if &n + &twist != &two * p + &two {
        return Err("twist.cardinality: the identity does not hold".into());
    }

    // The factorisation, when the bundle carries one. Optional because
    // the number is around 2p and factoring it is not always affordable —
    // but never taken on trust when present, because a twist-security
    // policy reads the largest prime factor from it, and an unchecked
    // split would let a curve look safer against small-subgroup attacks
    // than it is.
    let detail = match (payload, asserts.get("largest_prime_factor")) {
        (Some(payload), Some(node)) => {
            let (product, factors) = read_factors(payload, "twist.cardinality", twist.bits() + 1)?;
            if product != twist {
                return Err(
                    "twist.cardinality: the factors do not multiply to the twist order"
                        .into(),
                );
            }
            let largest = factors
                .iter()
                .map(|(prime, _)| prime)
                .max()
                .cloned()
                .unwrap_or_else(BigUint::one);
            let stated = decimal(
                node.as_str()
                    .ok_or("twist.cardinality: largest_prime_factor must be a string")?,
                "largest_prime_factor",
            )?;
            if stated != largest {
                return Err(
                    "twist.cardinality: the asserted largest prime factor is not \
                     the largest one in the factorisation"
                        .into(),
                );
            }
            format!(", largest prime factor {} bits", largest.bits())
        }
        // An assertion with no factorisation to support it is worse than
        // neither: it reads as established.
        (None, Some(_)) => {
            return Err(
                "twist.cardinality: a largest prime factor is asserted with no \
                 factorisation to establish it"
                    .into(),
            )
        }
        _ => String::new(),
    };

    Ok(format!(
        "identity re-derived; sound only if the cardinality is{detail}"
    ))
}

/// The order is pinned down by a point of prime order n with n larger than
/// the Hasse window: the window then holds no other multiple of n, so the
/// group order has nowhere else to be.
pub fn check_order(
    p: &BigUint,
    subject: &Node,
    asserts: &Node,
    payload: &Node,
    claims: &[Node],
) -> Result<String, String> {
    // The Hasse window this argument leans on is a statement about a
    // curve over a field, and there is no field unless p is prime. The
    // same requirement as in the point-order handler, for the same
    // reason: nothing here can establish primality, so it must be
    // established elsewhere in the bundle by proved evidence.
    let proved_p = decimal(
        find_proved_assert(claims, "field.characteristic", "p")?,
        "field.characteristic.p",
    )?;
    if &proved_p != p {
        return Err("curve.order: the proved characteristic is not the subject's".into());
    }
    let n = decimal(asserts.str_field("n", "curve.order")?, "curve.order.n")?;
    if asserts.str_field("cofactor", "curve.order")? != "1" {
        return Err("curve.order: only cofactor 1 is supported".into());
    }

    // n must be the very prime this bundle proved, and this is the line
    // the whole argument turns on.
    //
    // The classical statement needs n prime: then order(P) is 1 or n, the
    // point is affine so it is not 1, and a window narrower than n admits
    // one multiple. Without primality, `n·P = O` shows only that
    // order(P) divides n — and a point of order 2 satisfies every even n
    // in the window.
    //
    // The dependency on `curve.order.prime` was declared and its tier was
    // checked, but its value was never read. Declared and not consumed is
    // the same as not declared: a bundle could pair a 2-torsion point
    // with a composite n two away from the true order and be told
    // `proved`. Built and confirmed against Curve25519 before this line
    // existed.
    let proved_prime = decimal(
        find_proved_assert(claims, "curve.order.prime", "n")?,
        "curve.order.prime.n",
    )?;
    if n != proved_prime {
        return Err(
            "curve.order: n is not the subgroup order proved prime in this bundle"
                .into(),
        );
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
    witness.closed_keys(&["x", "y"], "curve.order point")?;
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
    let n = decimal(find_proved_assert(claims, "curve.order", "n")?, "curve.order.n")?;
    // The embedding degree is the order of p modulo the subgroup order,
    // and that only means anything if the modulus is prime. The claim
    // declared `curve.order.prime` and never read it; binding the two
    // here makes the declaration do work rather than sit there.
    let proved_prime = decimal(
        find_proved_assert(claims, "curve.order.prime", "n")?,
        "curve.order.prime.n",
    )?;
    if n != proved_prime {
        return Err(format!(
            "{ctx}: the modulus is not the subgroup order proved prime here"
        ));
    }
    if modulus != n {
        return Err(format!("{ctx}: the modulus is not the group order"));
    }
    if order != claimed {
        return Err(format!("{ctx}: the evidence is about a different degree"));
    }

    // The factorisation must be complete and its parts genuinely prime,
    // or a "prime" divisor could hide a smaller order behind it.
    let group_order = &n - &one;
    let (product, factors) = read_factors(payload, ctx, group_order.bits() + 1)?;
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

    // The two-adicity of n - 1, when the claim states it. Optional
    // because older bundles do not carry it, but never taken on trust:
    // it is recomputed from the same factorisation that was just proved
    // complete, so asserting it adds nothing a reader must believe.
    let adicity = match asserts.get("two_adicity") {
        Some(node) => {
            let stated = decimal(
                node.as_str()
                    .ok_or_else(|| format!("{ctx}: two_adicity must be a string"))?,
                "two_adicity",
            )?;
            let mut counted = BigUint::zero();
            let mut rest = group_order.clone();
            let two = BigUint::from(2u32);
            while (&rest % &two).is_zero() && !rest.is_zero() {
                rest /= &two;
                counted += BigUint::one();
            }
            if stated != counted {
                return Err(format!(
                    "{ctx}: the stated two-adicity is not the exponent of 2 in n - 1"
                ));
            }
            format!(", 2-adicity {counted}")
        }
        None => String::new(),
    };

    // A degree this size is what makes pairing transfers useless; a small
    // one would be the headline finding about the curve.
    let ratio = if order.bits() + 8 >= n.bits() {
        "comparable to n"
    } else {
        "far below n"
    };
    Ok(format!("exact order, {} bits, {ratio}{adicity}", order.bits()))
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
    declared: &[&str],
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
    let n = find_cardinality(claims, declared, "curve.cm")?;
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

    let (product, factors) = read_factors(payload, ctx, core.bits() + 1)?;
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
