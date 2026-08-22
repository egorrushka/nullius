// verifier-stamp: placeholder
// Placeholder. Replaced by tools/inline_wasm.py once the verifier has
// been built for the browser.
//
// It exists so the page builds without a wasm toolchain: a contributor
// working on layout should not need a Rust target installed, and a build
// that failed for a missing module would send them looking in the wrong
// place.
//
// What it must not do is pretend. Every call refuses with a reason, the
// page shows that reason, and nobody reads a certificate here believing
// it was checked when it was not.
//
//     rustup target add wasm32-unknown-unknown
//     cargo install wasm-bindgen-cli
//     tools\build_wasm.bat

export function load() {
  return Promise.reject(new Error("the verifier was not built for the browser"));
}

export async function verify() {
  throw new Error("the verifier was not built for the browser");
}

export async function version() {
  throw new Error("the verifier was not built for the browser");
}

export const SIZE_BYTES = 0;
