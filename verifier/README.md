# ccert-verify

Reads a `.ccert` bundle and re-checks every claim in it. Exits 0 only if
all claims verify. Any unknown claim type is a failure.

Build:

    cargo build --release

Or on Windows, from the project root:

    tools\build_verifier.bat

Deliberate constraints: pure-Rust bignum only, no network, no filesystem
writes, and a size budget of roughly a thousand lines.
