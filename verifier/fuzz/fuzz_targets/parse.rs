#![no_main]
//! The reader alone: faster, and deeper into the parser's own branches
//! than the full verifier reaches. It may accept or reject any bytes; it
//! may not panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(rule) = ccert::fuzz_oracle::fuzz_parse(data) {
        panic!("parser invariant broken: {rule}");
    }
});
