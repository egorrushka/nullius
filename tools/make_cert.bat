@echo off
rem Builds a .ccert bundle into corpus\.
rem     tools\make_cert.bat                    -> secp256k1
rem     tools\make_cert.bat secp256k1 C:\pari\gp.exe
setlocal
pushd "%~dp0\.."

set CURVE=%~1
if "%CURVE%"=="" set CURVE=secp256k1

if "%~2"=="" (
    python -m core.bundle.builder --curve %CURVE% --out corpus
) else (
    python -m core.bundle.builder --curve %CURVE% --out corpus --gp "%~2"
)
set RC=%ERRORLEVEL%

popd
endlocal
exit /b %RC%
