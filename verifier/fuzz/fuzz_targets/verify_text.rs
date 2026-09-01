#![no_main]
//! The whole path: arbitrary bytes -> verdict. The verifier must not
//! panic, hang, or misuse memory on any input, and its verdict must be
//! exactly one of the two shapes. `check_output` returning Err is a
//! finding; the assert turns it into a libFuzzer crash with the input
//! saved for triage and, once fixed, a new negative vector.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(rule) = ccert::fuzz_oracle::fuzz_verify(data) {
        panic!("verifier invariant broken: {rule}");
    }
});
