//! Re-establishes what a bundle claims, from the bundle alone.
//!
//! The rule this file exists to enforce: an unrecognised claim type or
//! evidence type is a hard failure. A verifier that shrugs at what it does
//! not understand gives a producer a way to smuggle anything past it, and
//! then a green result means nothing at all.
//!
//! Nothing here trusts the producer's arithmetic. Bounds are recomputed,
//! identities re-derived, hashes taken over the original bytes.

use num_bigint::BigUint;
use num_traits::Zero;
use sha2::{Digest, Sha256};

use crate::claims;
use crate::json::Node;

pub const FORMAT: &str = "ccert";
pub const VERSION: &str = "0";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    /// Proved outright by the evidence.
    Proved,
    /// Follows from other claims here, and only if those hold.
    Derived,
    /// Computed but not proved. Carries no weight.
    Candidate,
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::Proved => "proved",
            Tier::Derived => "derived",
            Tier::Candidate => "candidate",
        }
    }
}

/// Evidence kind to tier. The verifier's copy of the table, which is the
/// only copy that matters: a bundle cannot promote itself.
/// Claims that a given evidence kind is required to declare as
/// dependencies, keyed by the claim it supports.
///
/// The tier check on declared edges is sound but was only ever reached
/// when a producer chose to declare them, and declaring was optional. A
/// handler that reads another claim is resting on it whether or not an
/// edge says so, so the edges the handlers actually need are required
/// here, in pass one, before any arithmetic runs.
///
/// The entries mirror what each handler reads. Adding a read to a handler
/// without adding it here leaves the same hole open again, so the two are
/// meant to be edited together.
fn required_deps(evidence: &str, claim: &str) -> &'static [&'static str] {
    match (evidence, claim) {
        ("proof.point-order", _) => &["field.characteristic"],
        // `curve.order.prime` is here because the handler reads r for the
        // census that separates the twist from the subject's own curve
        // over the extension. A read is a dependency whether or not an
        // edge says so, and this table is the place that makes it one.
        ("derive.order-elimination", _) => &[
            "field.characteristic",
            "curve.cardinality",
            "curve.order.prime",
        ],
        ("check.cofactor", "curve.order") => &["curve.cardinality", "curve.order.prime"],
        ("check.cofactor", "g2.order") => &["g2.cardinality", "curve.order.prime"],
        ("check.order-unique", _) => &["curve.order.prime", "field.characteristic"],
        ("check.curve-model", _) => &["field.characteristic"],
        ("derive.twist-class", _) => &[
            "field.characteristic",
            "curve.cardinality",
            "g2.cardinality",
        ],
        ("check.family", _) => &[
            "field.characteristic",
            "curve.order.prime",
            "curve.cardinality",
        ],
        ("proof.multiplicative-order", _) => &["curve.order", "curve.order.prime"],
        ("check.hasse", _) => &["curve.order"],
        ("proof.cm-discriminant", _) => &["curve.order"],
        ("derive.twist-sum", _) => &["curve.order"],
        _ => &[],
    }
}

pub fn tier_of(evidence: &str) -> Option<Tier> {
    Some(match evidence {
        "candidate.pseudoprime" | "candidate.sea" => Tier::Candidate,
        "proof.ecpp"
        | "proof.multiplicative-order"
        | "proof.cm-discriminant"
        | "check.hasse"
        | "check.order-unique"
        | "check.seed-derivation"
        | "proof.point-order"
        | "check.cofactor"
        | "check.family"
        | "derive.twist-class"
        | "check.curve-model"
        | "derive.order-elimination" => Tier::Proved,
        "derive.twist-sum" => Tier::Derived,
        _ => return None,
    })
}

const KNOWN_CLAIMS: &[&str] = &[
    "field.characteristic",
    "curve.cardinality",
    "curve.order.prime",
    "curve.order",
    "curve.embedding",
    "curve.cm",
    "param.rigidity",
    "curve.hasse",
    "twist.cardinality",
    "g2.cardinality",
    "g2.order",
    "curve.family",
    "g2.twist",
    "curve.model",
];

pub struct Outcome {
    pub claim: String,
    pub tier: Tier,
    pub note: String,
    /// What this claim declared it rests on.
    ///
    /// Carried out of the verification rather than read from the file a
    /// second time. The edges here are the ones pass one checked — every
    /// one present, every one at a sufficient tier — so anything built
    /// from them describes the argument that was actually verified rather
    /// than the one the document claims.
    pub depends_on: Vec<String>,
}

pub struct Report {
    pub digest: String,
    pub subject: String,
    pub outcomes: Vec<Outcome>,
}

impl Report {
    pub fn count(&self, tier: Tier) -> usize {
        self.outcomes.iter().filter(|o| o.tier == tier).count()
    }
}

/// The keys a claim's `asserts` object may carry, per claim type.
///
/// `asserts` was the one level left open. It is not a harmless place to
/// leave open: it is the object a policy reads directly and the object a
/// person diffs, so an unread field here reaches both a machine verdict
/// and a human reader with nothing behind it — the same defect the closed
/// key sets elsewhere exist to prevent, at the level where it matters
/// most. A reviewer found the gap and closed it in the producer; this is
/// the same rule on the side that is the source of truth, so that a field
/// the producer refuses is a field the verifier refuses too.
///
/// `curve.model` carries the union of the Montgomery and twisted-Edwards
/// vocabularies; the curve-model handler narrows to the model-specific
/// set once it has read `model`. That narrowing is arithmetic and lives
/// there, not here.
fn asserts_keys(claim: &str) -> Option<&'static [&'static str]> {
    Some(match claim {
        "field.characteristic" => &["p", "prime"],
        "curve.cardinality" => &["n"],
        "curve.order.prime" => &["n", "prime"],
        "curve.order" => &["n", "cofactor", "largest_prime_factor"],
        "curve.embedding" => &["degree", "two_adicity"],
        "curve.cm" => &["trace", "conductor", "fundamental"],
        "param.rigidity" => &["method", "reproduced"],
        "curve.hasse" => &["low", "high", "contains"],
        "twist.cardinality" => &["identity", "n_twist", "largest_prime_factor"],
        "g2.cardinality" => &["n"],
        "g2.order" => &["n", "cofactor", "largest_prime_factor"],
        "curve.family" => &["family", "u"],
        "g2.twist" => &["related", "class", "degree"],
        "curve.model" => &["model", "A", "B", "a", "d"],
        _ => return None,
    })
}

/// The keys each evidence payload may carry, beside its `type`.
///
/// A table rather than a check inside each handler, for the same reason
/// `required_deps` is a table: a rule that lives in twelve places is a
/// rule with twelve chances to be forgotten in one of them.
///
/// This covers the top level of a payload. Objects nested inside — a
/// chain step, a factor entry, a point — are read by the routines that
/// consume them, and closing those is a separate piece of work rather
/// than something this table quietly implies it has done.
fn payload_keys(kind: &str) -> Option<&'static [&'static str]> {
    Some(match kind {
        "proof.ecpp" => &["type", "subject", "steps"],
        "proof.point-order" => &["type", "field", "curve", "point", "order", "factors"],
        "proof.multiplicative-order" => &["type", "base", "modulus", "order", "factors"],
        "proof.cm-discriminant" => &["type", "fundamental", "conductor", "factors"],
        "check.order-unique" => &["type", "point"],
        "check.cofactor" => &["type", "factors"],
        "check.family" => &["type", "family", "u"],
        "check.curve-model" => &["type", "model"],
        "check.seed-derivation" => &["type", "method", "seed"],
        "check.hasse" => &["type"],
        "derive.order-elimination" => &["type", "field", "curve", "points"],
        "derive.twist-class" => &["type", "index", "v"],
        "derive.twist-sum" => &["type", "factors"],
        // A candidate records what produced it and nothing else. The
        // tier already says the number rests on a tool's word; a field
        // beside it would be that word given somewhere to hide.
        "candidate.sea" | "candidate.pseudoprime" => &["type", "tool"],
        _ => return None,
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

pub fn verify(source: &str, root: &Node) -> Result<Report, String> {
    if root.str_field("format", "bundle")? != FORMAT {
        return Err("not a ccert bundle".into());
    }
    let version = root.str_field("version", "bundle")?;
    if version != VERSION {
        return Err(format!("unsupported format version `{version}`"));
    }
    for (key, _) in root.as_object().ok_or("bundle must be an object")? {
        if !matches!(
            key.as_str(),
            "format" | "version" | "subject" | "claims" | "evidence"
        ) {
            return Err(format!("unknown top-level field `{key}`"));
        }
    }

    let subject = root.field("subject", "bundle")?;
    subject.closed_keys(
        &["kind", "model", "field", "a", "b", "label", "source", "optional_steps"],
        "subject",
    )?;
    subject
        .field("field", "subject")?
        .closed_keys(&["kind", "p"], "subject.field")?;
    let p = check_subject(subject)?;

    let evidence = root.field("evidence", "bundle")?;
    check_evidence_pool(source, evidence)?;

    let claims = root
        .field("claims", "bundle")?
        .as_array()
        .ok_or("claims must be an array")?;

    // Pass one: structure, uniqueness, evidence linkage.
    let mut names: Vec<&str> = Vec::new();
    let mut used: Vec<&str> = Vec::new();
    for claim in claims {
        let name = claim.str_field("claim", "claim")?;
        if !KNOWN_CLAIMS.contains(&name) {
            return Err(format!("unknown claim type `{name}`"));
        }
        claim.closed_keys(&["claim", "asserts", "evidence", "depends_on"], name)?;
        // And inside `asserts`, per claim type. An unknown claim never
        // reaches here — it was refused above — so a missing table entry
        // is a real gap, not a case to wave through: `asserts_keys`
        // returns None only for a claim `KNOWN_CLAIMS` does not list, and
        // that cannot happen past the check above.
        let allowed = asserts_keys(name)
            .ok_or_else(|| format!("{name}: no asserts shape for this claim"))?;
        claim
            .field("asserts", name)?
            .closed_keys(allowed, &format!("{name} asserts"))?;
        claim
            .field("evidence", name)?
            .closed_keys(&["type", "ref"], name)?;
        if names.contains(&name) {
            return Err(format!("claim `{name}` stated more than once"));
        }
        names.push(name);

        let block = claim.field("evidence", name)?;
        let kind = block.str_field("type", name)?;
        let tier = tier_of(kind).ok_or_else(|| format!("unknown evidence type `{kind}`"))?;

        if let Some(reference) = block.get("ref") {
            let address = reference
                .as_str()
                .ok_or_else(|| format!("{name}: evidence ref must be a string"))?;
            let stored = evidence
                .get(address)
                .ok_or_else(|| format!("{name}: evidence `{address}` is not in the pool"))?;
            let stored_kind = stored.str_field("type", name)?;
            if stored_kind != kind {
                return Err(format!(
                    "{name}: claim says `{kind}` but its evidence says `{stored_kind}`"
                ));
            }
            let allowed = payload_keys(stored_kind)
                .ok_or_else(|| format!("{name}: no payload shape for `{stored_kind}`"))?;
            stored.closed_keys(allowed, &format!("{name} evidence"))?;
            used.push(address);
        } else if tier == Tier::Candidate {
            return Err(format!("{name}: a candidate must record what produced it"));
        }

        // Outside the block below, and that is the point: a claim with no
        // `depends_on` at all must not skip the requirement. Absence of a
        // declaration was exactly how a handler could read another claim
        // with nothing checking what it read.
        let declared: Vec<&str> = match claim.get("depends_on") {
            Some(deps) => deps
                .as_array()
                .ok_or("depends_on must be an array")?
                .iter()
                .filter_map(Node::as_str)
                .collect(),
            None => Vec::new(),
        };
        for needed in required_deps(kind, &name) {
            if !declared.contains(needed) {
                return Err(format!(
                    "{name}: `{kind}` rests on `{needed}` and must declare it"
                ));
            }
        }

        if let Some(deps) = claim.get("depends_on") {
            for dep in deps.as_array().ok_or("depends_on must be an array")? {
                let dep = dep.as_str().ok_or("depends_on entries must be strings")?;
                let target = claims
                    .iter()
                    .find(|c| c.get("claim").and_then(Node::as_str) == Some(dep))
                    .ok_or_else(|| format!("{name}: depends on `{dep}`, which is absent"))?;
                // Nothing may rest on something weaker than itself. A
                // proved claim leaning on a candidate is a false
                // certificate with extra steps, and a derived one leaning
                // on a candidate quietly inherits its emptiness.
                let dep_kind = target.field("evidence", dep)?.str_field("type", dep)?;
                let dep_tier = tier_of(dep_kind)
                    .ok_or_else(|| format!("unknown evidence type `{dep_kind}`"))?;
                let too_weak = match tier {
                    Tier::Proved => dep_tier != Tier::Proved,
                    Tier::Derived => dep_tier == Tier::Candidate,
                    Tier::Candidate => false,
                };
                if too_weak {
                    return Err(format!(
                        "{name} is {} but depends on `{dep}`, which is only {}",
                        tier.label(),
                        dep_tier.label()
                    ));
                }
            }
        }
    }

    for (address, _) in evidence.as_object().ok_or("evidence must be an object")? {
        if !used.contains(&address.as_str()) {
            return Err(format!("evidence `{address}` is referenced by nothing"));
        }
    }

    // Pass two: re-derive what can be re-derived.
    let mut outcomes = Vec::new();
    for claim in claims {
        let name = claim.str_field("claim", "claim")?.to_string();
        let kind = claim.field("evidence", &name)?.str_field("type", &name)?;
        let tier = tier_of(kind).expect("checked in pass one");
        let asserts = claim.field("asserts", &name)?;
        // Recomputed here rather than carried from pass one, which keeps
        // the two passes independent: pass one decides whether the graph
        // is well formed, pass two decides whether the arithmetic holds,
        // and neither should be able to corrupt the other's view.
        let declared: Vec<&str> = claim
            .get("depends_on")
            .and_then(Node::as_array)
            .map(|entries| entries.iter().filter_map(Node::as_str).collect())
            .unwrap_or_default();

        let note = match kind {
            "proof.ecpp" => {
                let block = claim.field("evidence", &name)?;
                let address = block.str_field("ref", &name)?;
                let payload = evidence
                    .get(address)
                    .ok_or_else(|| format!("{name}: evidence missing"))?;
                claims::check_ecpp(&name, asserts, payload)?
            }
            "proof.multiplicative-order" => {
                let block = claim.field("evidence", &name)?;
                let address = block.str_field("ref", &name)?;
                let payload = evidence
                    .get(address)
                    .ok_or_else(|| format!("{name}: evidence missing"))?;
                claims::check_order_of_element(&p, asserts, payload, claims)?
            }
            "proof.cm-discriminant" => {
                let block = claim.field("evidence", &name)?;
                let address = block.str_field("ref", &name)?;
                let payload = evidence
                    .get(address)
                    .ok_or_else(|| format!("{name}: evidence missing"))?;
                claims::check_cm(&p, asserts, payload, claims, &declared)?
            }
            "check.seed-derivation" => {
                let block = claim.field("evidence", &name)?;
                let address = block.str_field("ref", &name)?;
                let payload = evidence
                    .get(address)
                    .ok_or_else(|| format!("{name}: evidence missing"))?;
                claims::check_rigidity(&p, subject, asserts, payload)?
            }
            "check.order-unique" => {
                let block = claim.field("evidence", &name)?;
                let address = block.str_field("ref", &name)?;
                let payload = evidence
                    .get(address)
                    .ok_or_else(|| format!("{name}: evidence missing"))?;
                claims::check_order(&p, subject, asserts, payload, claims)?
            }
            "proof.point-order" => {
                let block = claim.field("evidence", &name)?;
                let address = block.str_field("ref", &name)?;
                let payload = evidence
                    .get(address)
                    .ok_or_else(|| format!("{name}: evidence missing"))?;
                crate::point_order::check_point_order(&p, subject, asserts, payload, claims, &name)?
            }
            "derive.order-elimination" => {
                let block = claim.field("evidence", &name)?;
                let address = block.str_field("ref", &name)?;
                let payload = evidence
                    .get(address)
                    .ok_or_else(|| format!("{name}: evidence missing"))?;
                crate::elimination::check_order_elimination(
                    &p, subject, asserts, payload, claims, &name,
                )?
            }
            "check.curve-model" => {
                crate::curve_model::check_curve_model(&p, subject, asserts, claims, &name)?
            }
            "derive.twist-class" => {
                let block = claim.field("evidence", &name)?;
                let address = block.str_field("ref", &name)?;
                let payload = evidence
                    .get(address)
                    .ok_or_else(|| format!("{name}: evidence missing"))?;
                crate::twist_class::check_twist_class(
                    &p, subject, asserts, payload, claims, &name,
                )?
            }
            "check.family" => {
                let block = claim.field("evidence", &name)?;
                let address = block.str_field("ref", &name)?;
                let payload = evidence
                    .get(address)
                    .ok_or_else(|| format!("{name}: evidence missing"))?;
                crate::family::check_family(&p, asserts, payload, claims, &name)?
            }
            "check.cofactor" => {
                let block = claim.field("evidence", &name)?;
                let address = block.str_field("ref", &name)?;
                let payload = evidence
                    .get(address)
                    .ok_or_else(|| format!("{name}: evidence missing"))?;
                crate::point_order::check_cofactor(asserts, payload, claims, &name)?
            }
            "check.hasse" => claims::check_hasse(&p, asserts, claims, &declared)?,
            "derive.twist-sum" => {
                let payload = claim
                    .field("evidence", &name)?
                    .get("ref")
                    .and_then(Node::as_str)
                    .and_then(|address| evidence.get(address));
                claims::check_twist(&p, asserts, payload, claims, &declared)?
            }
            "candidate.sea" | "candidate.pseudoprime" => {
                let evidence_block = claim.field("evidence", &name)?;
                let address = evidence_block
                    .str_field("ref", &name)
                    .unwrap_or("(none)")
                    .to_string();
                let tool = evidence
                    .get(&address)
                    .and_then(|e| e.get("tool"))
                    .and_then(Node::as_str)
                    .unwrap_or("unknown tool");
                format!("not proved; produced by {tool}")
            }
            other => return Err(format!("unknown evidence type `{other}`")),
        };

        outcomes.push(Outcome {
            claim: name,
            tier,
            note,
            depends_on: declared.iter().map(|d| d.to_string()).collect(),
        });
    }

    Ok(Report {
        digest: hex_digest(trim_final_newline(source.as_bytes())),
        subject: describe(subject),
        outcomes,
    })
}

fn trim_final_newline(bytes: &[u8]) -> &[u8] {
    match bytes.split_last() {
        Some((b'\n', rest)) => rest,
        _ => bytes,
    }
}

fn check_subject(subject: &Node) -> Result<BigUint, String> {
    if subject.str_field("kind", "subject")? != "elliptic-curve" {
        return Err("this verifier only understands elliptic curves".into());
    }
    if subject.str_field("model", "subject")? != "short-weierstrass" {
        return Err("this verifier only understands short Weierstrass curves".into());
    }
    let field = subject.field("field", "subject")?;
    if field.str_field("kind", "subject.field")? != "prime" {
        return Err("this verifier only understands prime fields".into());
    }
    let p = claims::decimal(field.str_field("p", "subject.field")?, "subject.field.p")?;
    let a = claims::decimal(subject.str_field("a", "subject")?, "subject.a")?;
    let b = claims::decimal(subject.str_field("b", "subject")?, "subject.b")?;

    if p <= BigUint::from(3u32) {
        return Err("p must exceed 3".into());
    }
    if !p.bit(0) {
        return Err("p is even, so it is not an odd prime".into());
    }
    if a >= p || b >= p {
        return Err("coefficients must be reduced modulo p".into());
    }

    // 4a^3 + 27b^2 must not vanish, or the points of the subject are not
    // a group and every claim in the document is about nothing. The
    // evidence handlers each check the curve *they* were handed;
    // nothing checked the one the whole bundle is named after, which is
    // the one case where the omission would have been invisible.
    let discriminant = (BigUint::from(4u32) * a.modpow(&BigUint::from(3u32), &p)
        + BigUint::from(27u32) * b.modpow(&BigUint::from(2u32), &p))
        % &p;
    if discriminant.is_zero() {
        return Err(
            "the subject is singular: 4a^3 + 27b^2 vanishes mod p, so its points \
             are not a group"
                .into(),
        );
    }
    Ok(p)
}

fn check_evidence_pool(source: &str, evidence: &Node) -> Result<(), String> {
    let entries = evidence
        .as_object()
        .ok_or("evidence pool must be an object")?;
    for (address, value) in entries {
        if !is_address(address) {
            return Err(format!("evidence key `{address}` is not a content address"));
        }
        // Hash the original bytes, not a re-encoding of the parsed value.
        let raw = &source.as_bytes()[value.span.clone()];
        let actual = hex_digest(raw);
        if &actual != address {
            return Err(format!(
                "evidence does not hash to its key; the pool has been altered\n  \
                 key    {address}\n  actual {actual}"
            ));
        }
    }
    Ok(())
}

fn is_address(text: &str) -> bool {
    text.len() == 71
        && text.starts_with("sha256:")
        && text[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn describe(subject: &Node) -> String {
    let label = subject.get("label").and_then(Node::as_str).unwrap_or("unnamed curve");
    let bits = subject
        .get("field")
        .and_then(|f| f.get("p"))
        .and_then(Node::as_str)
        .and_then(|p| BigUint::parse_bytes(p.as_bytes(), 10))
        .map(|p| p.bits())
        .unwrap_or(0);
    format!("{label} ({bits}-bit prime field)")
}
