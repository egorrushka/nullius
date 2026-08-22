@echo off
rem Builds the verifier for the browser and inlines it into the page.
rem     tools\build_wasm.bat
rem
rem The page has always claimed you need not take its word for anything,
rem and until now it could not honour that: it displayed certificates and
rem judged them by policy, but nothing in it re-derived a single claim.
rem A reader who dropped in a file and saw green marks would reasonably
rem conclude the file had been checked. It had not.
rem
rem This closes that. The module below is the same Rust that
rem ccert-verify.exe is, compiled for a different machine — not a second
rem implementation in JavaScript, which would drift from the first and be
rem the one nobody audited.
rem
rem Needs, once:
rem     rustup target add wasm32-unknown-unknown
rem     cargo install wasm-bindgen-cli
setlocal
pushd "%~dp0\.."

echo === compiling the verifier for wasm32
cargo build --release --target wasm32-unknown-unknown --manifest-path verifier\Cargo.toml
if errorlevel 1 (
    echo Build failed. Is the wasm32 target installed?
    echo     rustup target add wasm32-unknown-unknown
    popd
    exit /b 1
)

echo.
echo === generating the JavaScript binding
rem --target web, because the page is opened from file:// and there is no
rem bundler between it and the browser. --no-typescript because nothing
rem here consumes the declarations.
wasm-bindgen ^
    verifier\target\wasm32-unknown-unknown\release\ccert.wasm ^
    --out-dir web\src\wasm ^
    --target web ^
    --no-typescript
if errorlevel 1 (
    echo wasm-bindgen failed. Is it installed and the same version as the
    echo wasm-bindgen dependency in verifier\Cargo.toml?
    echo     cargo install wasm-bindgen-cli
    popd
    exit /b 1
)

echo.
echo === inlining the module so the page stays one file
python tools\inline_wasm.py
if errorlevel 1 (
    popd
    exit /b 1
)

echo.
echo Done. Now: tools\web_build.bat
popd
endlocal
