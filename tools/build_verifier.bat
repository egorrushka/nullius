@echo off
rem Builds the independent verifier. Requires rustup.
rem
rem Downloaded files arrive with whatever timestamp they were given, which
rem can be older than the last build. Cargo compares dates and would then
rem skip the rebuild, leaving a stale binary that fails in confusing ways.
rem So the sources get their dates refreshed first.
setlocal
pushd "%~dp0\..\verifier"

powershell -NoProfile -Command ^
  "Get-ChildItem src\*.rs, Cargo.toml | ForEach-Object { $_.LastWriteTime = Get-Date }" >nul 2>&1

echo Sources:
for %%F in (src\*.rs) do echo   %%~tF  %%~zF bytes  %%~nxF
echo.

cargo build --release
if errorlevel 1 (
    echo.
    echo Build failed. Is rustup installed and on PATH?
    popd
    exit /b 1
)
echo.
echo Built: verifier\target\release\ccert-verify.exe
popd
endlocal
