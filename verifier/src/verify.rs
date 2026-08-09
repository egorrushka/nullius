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
use num_traits::One;
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
/// Evidence kind to tier. The verifier's copy of the table, which is the
/// only copy that matters: a bundle cannot promote itself.
fn tier_of(evidence: &str) -> Option<Tier> {
    Some(match evidence {
        "candidate.pseudoprime" | "candidate.sea" => Tier::Candidate,
        "proof.ecpp"
        | "proof.multiplicative-order"
        | "proof.cm-discriminant"
        | "check.hasse"
        | "check.order-unique"
        | "check.seed-derivation" => Tier::Proved,
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
];

pub struct Outcome {
    pub claim: String,
    pub tier: Tier,
    pub note: String,
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
            used.push(address);
        } else if tier == Tier::Candidate {
            return Err(format!("{name}: a candidate must record what produced it"));
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
                claims::check_cm(&p, asserts, payload, claims)?
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
                claims::check_order(&p, subject, asserts, payload)?
            }
            "check.hasse" => claims::check_hasse(&p, asserts, claims)?,
            "derive.twist-sum" => claims::check_twist(&p, asserts, claims)?,
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

        outcomes.push(Outcome { claim: name, tier, note });
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
