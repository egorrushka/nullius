//! Independent verifier for `.ccert` bundles.
//!
//! Reads a bundle and re-establishes every claim it can, from the file
//! alone. Exits 0 only when the document is well formed, its evidence pool
//! is intact, and each claim's evidence checks out.
//!
//! Deliberate constraints, because this is the component people are meant
//! to read line by line before trusting anything else in the project: pure
//! Rust arithmetic, no network, no filesystem writes, no configuration.

mod claims;
mod ec;
mod ecpp;
mod json;
mod verify;

use std::process::ExitCode;

use verify::Tier;

fn usage() -> String {
    "usage: ccert-verify [--require-proved] <bundle.ccert>\n\
     \n\
     Exit codes: 0 verified, 1 verification failed, 2 usage or I/O error.\n\
     \n\
     --require-proved  fail unless every claim is proved outright"
        .to_string()
}

fn main() -> ExitCode {
    let mut path: Option<String> = None;
    let mut require_proved = false;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--require-proved" => require_proved = true,
            "-h" | "--help" => {
                println!("{}", usage());
                return ExitCode::SUCCESS;
            }
            other if other.starts_with('-') => {
                eprintln!("unknown option `{other}`\n\n{}", usage());
                return ExitCode::from(2);
            }
            other => {
                if path.is_some() {
                    eprintln!("expected exactly one bundle\n\n{}", usage());
                    return ExitCode::from(2);
                }
                path = Some(other.to_string());
            }
        }
    }

    let Some(path) = path else {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    };

    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("cannot read {path}: {err}");
            return ExitCode::from(2);
        }
    };
    let source = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            eprintln!("{path}: not valid UTF-8");
            return ExitCode::FAILURE;
        }
    };

    let node = match json::parse(&source) {
        Ok(node) => node,
        Err(err) => {
            eprintln!("REJECTED  {path}\n  {err}");
            return ExitCode::FAILURE;
        }
    };

    let report = match verify::verify(&source, &node) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("REJECTED  {path}\n  {err}");
            return ExitCode::FAILURE;
        }
    };

    println!("bundle:   {path}");
    println!("digest:   {}", report.digest);
    println!("subject:  {}", report.subject);
    println!();
    for outcome in &report.outcomes {
        println!(
            "  [{:>9}]  {:<22}  {}",
            outcome.tier.label(),
            outcome.claim,
            outcome.note
        );
    }

    let proved = report.count(Tier::Proved);
    let derived = report.count(Tier::Derived);
    let candidate = report.count(Tier::Candidate);
    println!("\n{proved} proved, {derived} derived, {candidate} not proved");

    // Derived claims are allowed here: the verifier has already refused any
    // bundle where one rests on something unproved, so a derived claim in a
    // bundle that got this far stands on proof.
    if require_proved && candidate > 0 {
        eprintln!("\nFAILED  --require-proved was given and {candidate} claim(s) are unproved");
        return ExitCode::FAILURE;
    }
    if candidate > 0 {
        println!(
            "\nThe document is sound and its evidence checks out, but {candidate} claim(s)\n\
             rest on nothing more than a program's word. Read them as unproved."
        );
    }
    ExitCode::SUCCESS
}
