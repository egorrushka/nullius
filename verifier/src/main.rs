//! Independent verifier for `.ccert` bundles.
//!
//! Reads a bundle and re-establishes every claim it can, from the file
//! alone. Exits 0 only when the document is well formed, its evidence pool
//! is intact, and each claim's evidence checks out.
//!
//! Deliberate constraints, because this is the component people are meant
//! to read line by line before trusting anything else in the project: pure
//! Rust arithmetic, no network, no filesystem writes, no configuration.

// The modules live in the library beside this file, so the browser build
// and the command line run the same code rather than two copies of it.
use ccert::{json, refusal_json, report_json, verify};

use std::process::ExitCode;

use verify::Tier;

fn usage() -> String {
    "usage: ccert-verify [--require-proved] [--strict] [--explain] [--json] \
<bundle.ccert>\n\
     \n\
     Exit codes: 0 verified, 1 verification failed, 2 usage or I/O error.\n\
     \n\
     --require-proved  fail unless every claim is proved outright\n\
     --strict          also fail on any claim below proved\n\
     --explain         show what each claim rests on, and how far down\n\
     --json            machine-readable verdict on stdout"
        .to_string()
}

/// A JSON string, escaped by hand.
///
/// Written out rather than pulled in, for the same reason the rest of
/// this program is: a verifier people are asked to read end to end should
/// not need a dependency to say what it found. Only the characters JSON
/// requires are escaped, and control characters go to \u form.

/// What a claim rests on, all the way down.
///
/// The verifier already walks this graph: pass one checks that every
/// declared dependency is present and standing high enough. Printing it
/// costs nothing and answers the question a reader actually has, which is
/// not "is this proved" but "proved on top of what".
fn explain_tree(report: &verify::Report) {
    use std::collections::HashMap;

    let tiers: HashMap<&str, Tier> = report
        .outcomes
        .iter()
        .map(|o| (o.claim.as_str(), o.tier))
        .collect();
    let edges: HashMap<&str, &[String]> = report
        .outcomes
        .iter()
        .map(|o| (o.claim.as_str(), o.depends_on.as_slice()))
        .collect();

    println!("\nWhat each claim rests on\n");
    println!(
        "A tier describes everything beneath a claim, not the claim alone:\n\
         nothing proved rests on anything less, and nothing derived rests on\n\
         a bare candidate. Read a tree down to its leaves and the tier at the\n\
         top is the weakest thing in it.\n"
    );
    for outcome in &report.outcomes {
        println!("{}  [{}]", outcome.claim, outcome.tier.label());
        if outcome.depends_on.is_empty() {
            // Nothing below it. Either the claim is self-contained — a
            // primality chain needs no other claim — or it is a leaf the
            // reader should look at directly.
            println!("     rests on nothing else in this bundle");
        } else {
            let mut seen = Vec::new();
            for (position, dep) in outcome.depends_on.iter().enumerate() {
                let last = position + 1 == outcome.depends_on.len();
                walk(dep, &tiers, &edges, "     ", last, &mut seen);
            }
        }

        // The floor of the argument. It always equals the claim's own
        // tier, and that is a property rather than a coincidence: pass
        // one refuses a proved claim resting on anything below proved,
        // and a derived one resting on a candidate. Printed only when it
        // fails, which is to say never, unless the tier rules have been
        // broken. A line that cannot appear is worth more here than one
        // that always does.
        let mut visited = Vec::new();
        let weakest = floor(&outcome.claim, &tiers, &edges, &mut visited);
        if weakest != outcome.tier {
            println!(
                "     !! the weakest thing underneath is {}, so the tier above \
                 overstates it",
                weakest.label()
            );
        }
        println!();
    }
}

/// One branch of the tree.
fn walk(
    claim: &str,
    tiers: &std::collections::HashMap<&str, Tier>,
    edges: &std::collections::HashMap<&str, &[String]>,
    prefix: &str,
    last: bool,
    seen: &mut Vec<String>,
) {
    let tier = tiers.get(claim).map(|t| t.label()).unwrap_or("absent");
    let elbow = if last { "`- " } else { "|- " };
    // A claim reached twice is printed once with a note. The graph is
    // acyclic — pass one would have refused otherwise — but it is not a
    // tree, and repeating a whole subtree would bury the part that is new.
    if seen.contains(&claim.to_string()) {
        println!("{prefix}{elbow}{claim} [{tier}], shown above");
        return;
    }
    seen.push(claim.to_string());
    println!("{prefix}{elbow}{claim} [{tier}]");

    let Some(children) = edges.get(claim) else {
        return;
    };
    let deeper = format!("{prefix}{}", if last { "   " } else { "|  " });
    for (position, child) in children.iter().enumerate() {
        walk(child, tiers, edges, &deeper, position + 1 == children.len(), seen);
    }
}

/// The weakest tier anywhere beneath a claim, itself included.
fn floor(
    claim: &str,
    tiers: &std::collections::HashMap<&str, Tier>,
    edges: &std::collections::HashMap<&str, &[String]>,
    visited: &mut Vec<String>,
) -> Tier {
    if visited.contains(&claim.to_string()) {
        return Tier::Proved;
    }
    visited.push(claim.to_string());
    let mut weakest = tiers.get(claim).copied().unwrap_or(Tier::Candidate);
    if let Some(children) = edges.get(claim) {
        for child in children.iter() {
            let below = floor(child, tiers, edges, visited);
            if rank(below) < rank(weakest) {
                weakest = below;
            }
        }
    }
    weakest
}

fn rank(tier: Tier) -> u8 {
    match tier {
        Tier::Proved => 3,
        Tier::Derived => 2,
        Tier::Candidate => 1,
    }
}

fn main() -> ExitCode {
    let mut path: Option<String> = None;
    let mut require_proved = false;

    let mut json_output = false;
    let mut strict = false;
    let mut explain = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--require-proved" => require_proved = true,
            "--json" => json_output = true,
            // Stricter than --require-proved, which tolerates derived
            // claims on the grounds that the verifier already refused any
            // bundle where one rests on something unproved. That
            // reasoning is sound and someone may still not want to take
            // it: a derived claim is true only as far as what it derives
            // from, and a caller entitled to demand everything stand on
            // its own gets a flag for it.
            "--strict" => strict = true,
            "--explain" => explain = true,
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
            if json_output {
                println!("{}", refusal_json(&path, &err));
            } else {
                eprintln!("REJECTED  {path}\n  {err}");
            }
            return ExitCode::FAILURE;
        }
    };

    if json_output {
        println!("{}", report_json(&path, &report));
        let candidate = report.count(Tier::Candidate);
        let derived = report.count(Tier::Derived);
        let refused = (require_proved && candidate > 0) || (strict && derived + candidate > 0);
        return if refused { ExitCode::FAILURE } else { ExitCode::SUCCESS };
    }

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
    if explain {
        explain_tree(&report);
    }

    if require_proved && candidate > 0 {
        eprintln!("\nFAILED  --require-proved was given and {candidate} claim(s) are unproved");
        return ExitCode::FAILURE;
    }
    if strict && derived + candidate > 0 {
        eprintln!(
            "\nFAILED  --strict was given and {} claim(s) are not proved outright",
            derived + candidate
        );
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
