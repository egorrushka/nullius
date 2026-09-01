//! Runs the shared oracle over every shipped vector, on any platform,
//! as an ordinary `cargo test` — the layer that works where cargo-fuzz
//! does not (Windows), and the regression net for every finding the
//! fuzzer turns into a vector.

use std::fs;
use std::path::PathBuf;

use ccert::fuzz_oracle::{check_mutation, check_output, fuzz_parse, Verdict};

fn vectors(kind: &str) -> Vec<(String, String)> {
    // The crate is `verifier/`; the vectors live at the repo root under
    // `spec/vectors`, one level up from CARGO_MANIFEST_DIR.
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("verifier/ has a parent")
        .to_path_buf();
    let dir = repo.join("spec").join("vectors").join(kind);
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "ccert").unwrap_or(false) {
                if let Ok(text) = fs::read_to_string(&path) {
                    out.push((path.display().to_string(), text));
                }
            }
        }
    }
    out
}

#[test]
fn every_vector_yields_a_well_formed_verdict() {
    let all = vectors("valid").into_iter().chain(vectors("invalid"));
    let mut n = 0;
    for (name, text) in all {
        check_output(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        n += 1;
    }
    // A floor, not an exact count: enough to catch a broken path or an
    // empty directory without pinning a number the growing corpus will
    // outrun. The real tree ships more than this.
    assert!(n >= 50, "expected the shipped corpus, found only {n} vectors");
}

#[test]
fn valid_accepted_invalid_refused() {
    for (name, text) in vectors("valid") {
        assert!(
            matches!(check_output(&text), Ok(Verdict::Accepted { .. })),
            "{name} was not accepted"
        );
    }
    for (name, text) in vectors("invalid") {
        assert!(
            matches!(check_output(&text), Ok(Verdict::Refused)),
            "{name} was not refused"
        );
    }
}

/// A small deterministic mutator, so the differential invariant is
/// exercised on every valid seed without a fuzzer present. libFuzzer does
/// this far harder in CI; this keeps the same rule enforced everywhere.
fn mutations(seed: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let n = seed.len().max(1);
    for k in 0..96usize {
        let i = k.wrapping_mul(2654435761) % n;
        let mut m = seed.to_vec();
        match k % 4 {
            0 => {
                if i < m.len() {
                    m[i] ^= 0x20;
                }
            }
            1 => m.insert(i.min(m.len()), b'0'),
            2 => {
                if i < m.len() {
                    m.remove(i);
                }
            }
            _ => m.truncate(i),
        }
        out.push(m);
    }
    let mut plus = seed.to_vec();
    plus.push(b'\n');
    out.push(plus);
    if seed.last() == Some(&b'\n') {
        out.push(seed[..seed.len() - 1].to_vec());
    }
    out
}

#[test]
fn no_mutation_is_accepted_under_the_original_digest() {
    for (name, text) in vectors("valid") {
        for candidate in mutations(text.as_bytes()) {
            let _ = fuzz_parse(&candidate); // must never panic
            if let Ok(mutated) = std::str::from_utf8(&candidate) {
                check_mutation(&text, mutated).unwrap_or_else(|e| panic!("{name}: {e}"));
            }
        }
    }
}
