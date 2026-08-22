//! The verifier, as a library.
//!
//! It was a binary and nothing else until the page needed to run it. The
//! obvious way to give a browser a verifier is to write one in
//! JavaScript, and that is the way this project must not take: two
//! implementations of the same argument drift, and the one people would
//! actually use — the one in the page — would be the one nobody audited.
//!
//! So the command line and the browser share this crate. The same
//! Atkin-Morain chains, the same elimination, the same refusals, compiled
//! twice. What the page reports is what `ccert-verify` reports, because
//! it *is* `ccert-verify`.
//!
//! The JSON writer lives here for the same reason. Two encoders would be
//! two formats eventually, and a consumer pinning a hash of the output
//! would find it depended on which program produced it.

pub mod claims;
pub mod curve;
pub mod curve_model;
pub mod ec;
pub mod ecpp;
pub mod elimination;
pub mod family;
pub mod fq;
pub mod fq4;
pub mod json;
pub mod point_order;
pub mod twist_class;
pub mod verify;

use verify::Tier;

/// A JSON string, escaped by hand.
///
/// Written out rather than pulled in, for the same reason the rest of
/// this crate is: a verifier people are asked to read end to end should
/// not need a dependency to say what it found. Only the characters JSON
/// requires are escaped, and control characters go to \u form.
pub fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The verdict, with keys in a fixed order.
///
/// Sorted and compact, so the output is reproducible byte for byte the
/// way a certificate is. A consumer diffing two runs should see nothing,
/// and one pinning a hash of this should be able to.
pub fn report_json(path: &str, report: &verify::Report) -> String {
    let mut out = String::from("{");
    out.push_str(&format!("\"bundle\":{},", quote(path)));
    out.push_str(&format!("\"digest\":{},", quote(&report.digest)));
    out.push_str("\"outcomes\":[");
    for (index, outcome) in report.outcomes.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"claim\":{},\"depends_on\":[",
            quote(&outcome.claim)
        ));
        for (position, dependency) in outcome.depends_on.iter().enumerate() {
            if position > 0 {
                out.push(',');
            }
            out.push_str(&quote(dependency));
        }
        out.push_str(&format!(
            "],\"note\":{},\"tier\":{}}}",
            quote(&outcome.note),
            quote(outcome.tier.label()),
        ));
    }
    out.push_str("],");
    out.push_str(&format!(
        "\"proved\":{},\"derived\":{},\"unproved\":{},",
        report.count(Tier::Proved),
        report.count(Tier::Derived),
        report.count(Tier::Candidate),
    ));
    out.push_str("\"result\":\"accepted\",");
    out.push_str(&format!("\"subject\":{}", quote(&report.subject)));
    out.push('}');
    out
}

/// A refusal, in the same shape.
///
/// Machine consumers need the reason as much as the verdict, and a
/// refusal arriving as a bare exit code tells an automated caller nothing
/// about which claim went wrong.
pub fn refusal_json(path: &str, reason: &str) -> String {
    format!(
        "{{\"bundle\":{},\"reason\":{},\"result\":\"refused\"}}",
        quote(path),
        quote(reason),
    )
}

/// Verify one bundle's text, and return the verdict as JSON.
///
/// The whole interface, deliberately. Everything the caller needs is in
/// the string that comes back, and nothing about the caller leaks in — no
/// paths, no environment, no clock. That is what makes the browser build
/// and the command-line build the same program rather than two programs
/// that agree today.
pub fn verify_text(name: &str, source: &str) -> String {
    let node = match json::parse(source) {
        Ok(node) => node,
        Err(error) => return refusal_json(name, &error),
    };
    match verify::verify(source, &node) {
        Ok(report) => report_json(name, &report),
        Err(reason) => refusal_json(name, &reason),
    }
}

/// The browser's entry point.
///
/// One function, taking the file's text and returning the same JSON the
/// command line prints. Compiled only for wasm, so a native build carries
/// no trace of it and needs none of its dependencies.
#[cfg(target_arch = "wasm32")]
mod browser {
    use wasm_bindgen::prelude::*;

    /// Verify a certificate, in the page, with nothing sent anywhere.
    ///
    /// The name is what appears in the verdict, so a caller can pass the
    /// file's own name and have the output read like the command line's.
    #[wasm_bindgen]
    pub fn verify_certificate(name: &str, source: &str) -> String {
        super::verify_text(name, source)
    }

    /// What this build is, so a page can say so rather than assume.
    #[wasm_bindgen]
    pub fn verifier_version() -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }
}
