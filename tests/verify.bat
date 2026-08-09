@echo off
rem Verifies a bundle. Defaults to corpus\secp256k1.ccert.
rem     tools\verify.bat
rem     tools\verify.bat corpus\secp256k1.ccert --require-proved
setlocal
pushd "%~dp0\.."

set TARGET=%~1
if "%TARGET%"=="" set TARGET=corpus\secp256k1.ccert

if not exist "verifier\target\release\ccert-verify.exe" (
    echo Verifier not built. Running tools\build_verifier.bat first.
    call "%~dp0build_verifier.bat" || exit /b 1
)

verifier\target\release\ccert-verify.exe %2 %3 "%TARGET%"
set RC=%ERRORLEVEL%
popd
endlocal
exit /b %RC%
