//! One place that decides whether an input broke a rule, shared by the
//! fuzzer (millions of mutations, on Linux) and the corpus test (every
//! known vector, on any platform including Windows). Two runners, one
//! definition of "held", so a rule the fuzzer checks is a rule the test
//! checks and neither drifts from the other.
//!
//! The verifier is total and pure: bytes in, a verdict string out, no
//! panic, no clock, no I/O. These checks say what a correct verdict must
//! look like, and — for a mutation of a certificate that was valid — what
//! an ACCEPT is allowed to mean. A returned Err names the rule that broke;
//! the callers turn that into a fuzzer crash or a failed assertion.
//!
//! Note on the verdict format: it is a report, not a certificate. Only
//! `.ccert` inputs are canonical; the verdict carries counts as JSON
//! numbers and keys in reading order, so it is read here by locating
//! fields, not by running it back through the canonical parser (which
//! rightly refuses numbers).

use crate::verify_text;

/// The value of a `"key":"value"` string field in the verdict, located
/// without a JSON dependency because the verdict is our own output.
fn string_field(out: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = out.find(&needle)? + needle.len();
    let rest = &out[start..];
    let end = rest.find('"')?; // values here contain no escaped quotes
    Some(rest[..end].to_string())
}

/// True if two byte strings differ only by a single trailing newline,
/// which the digest excludes on purpose (the canonical form allows one).
/// A mutation that only adds or removes that newline has not changed the
/// document, so it is not evidence of anything.
fn without_final_newline(x: &[u8]) -> &[u8] {
    if x.last() == Some(&b'\n') { &x[..x.len() - 1] } else { x }
}

fn same_but_final_newline(a: &[u8], b: &[u8]) -> bool {
    without_final_newline(a) == without_final_newline(b)
}

pub enum Verdict {
    Accepted { digest: String },
    Refused,
}

/// Check the invariants that hold for *any* input:
/// 1. verify_text does not panic (guaranteed by getting here at all);
/// 2. the output is exactly one of two shapes — an accepted verdict
///    carrying a digest, or a refusal carrying a reason.
/// Returns Err(rule) if a rule broke.
pub fn check_output(source: &str) -> Result<Verdict, String> {
    let out = verify_text("fuzz", source);
    let accepted = out.contains("\"result\":\"accepted\"");
    let refused = out.contains("\"result\":\"refused\"");
    match (accepted, refused) {
        (true, false) => {
            let digest = string_field(&out, "digest")
                .ok_or("accepted verdict without a digest")?;
            Ok(Verdict::Accepted { digest })
        }
        (false, true) => {
            string_field(&out, "reason").ok_or("refusal without a reason")?;
            Ok(Verdict::Refused)
        }
        _ => Err(format!(
            "verdict is neither cleanly accepted nor refused: {}",
            &out[..out.len().min(80)]
        )),
    }
}

/// The whole-path target: any bytes at all. Non-UTF-8 is not a finding —
/// the interface takes a &str; it just has nothing to check.
pub fn fuzz_verify(data: &[u8]) -> Result<(), String> {
    if let Ok(s) = std::str::from_utf8(data) {
        check_output(s)?;
    }
    Ok(())
}

/// The parser target: exercise the reader alone, faster and deeper into
/// its own branches. It may accept or reject; it may not panic.
pub fn fuzz_parse(data: &[u8]) -> Result<(), String> {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = crate::json::parse(s); // total: Ok or Err, never a panic
    }
    Ok(())
}

/// The differential target, run on mutations of a *valid* certificate.
///
/// The one that catches "accepted a lie": the verifier hashes the raw
/// bytes, so if a mutated certificate is still accepted, its digest must
/// equal the original's — byte-for-byte the same document under the hash —
/// and the mutation must have been nothing more than the trailing newline
/// the digest ignores. An ACCEPT whose digest matches while the bytes
/// meaningfully differ would be a collision the format exists to prevent.
pub fn check_mutation(original: &str, mutated: &str) -> Result<(), String> {
    let base = match check_output(original)? {
        Verdict::Accepted { digest } => digest,
        Verdict::Refused => return Err("differential seed was not accepted".into()),
    };
    if let Verdict::Accepted { digest } = check_output(mutated)? {
        if digest == base && !same_but_final_newline(original.as_bytes(), mutated.as_bytes()) {
            return Err(format!(
                "accepted a mutated certificate under the original digest {base}"
            ));
        }
    }
    Ok(())
}
