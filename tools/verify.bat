@echo off
rem Verifies a bundle with the independent verifier.
rem
rem     tools\verify.bat                                   corpus\secp256k1.ccert
rem     tools\verify.bat corpus\secp256k1.ccert
rem     tools\verify.bat --require-proved corpus\secp256k1.ccert
rem
rem Exit codes: 0 verified, 1 verification failed, 2 usage or I/O error.
setlocal
pushd "%~dp0\.."

set EXE=verifier\target\release\ccert-verify.exe
if not exist "%EXE%" (
    echo Verifier not built yet, building it first.
    call "%~dp0build_verifier.bat"
    if errorlevel 1 (
        popd
        exit /b 1
    )
)

if "%~1"=="" (
    "%EXE%" corpus\secp256k1.ccert
) else (
    "%EXE%" %*
)
set RC=%ERRORLEVEL%

popd
endlocal
exit /b %RC%
