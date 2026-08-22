@echo off
rem Applies a policy to a bundle. Policies decide; they never compute.
rem
rem     tools\policy.bat                              SafeCurves on secp256k1
rem     tools\policy.bat glv-endomorphism
rem     tools\policy.bat safecurves-2024 corpus\secp256k1.ccert
rem     tools\policy.bat --list
rem
rem Exit codes: 0 passes, 1 fails or cannot be decided, 2 bad input.
setlocal
pushd "%~dp0\.."

if "%~1"=="--list" (
    python -m core.policy.engine --list
    goto done
)

set POLICY=%~1
if "%POLICY%"=="" set POLICY=safecurves-2024

set TARGET=%~2
if "%TARGET%"=="" set TARGET=corpus\secp256k1.ccert

python -m core.policy.engine "%TARGET%" --policy "%POLICY%"

:done
set RC=%ERRORLEVEL%
popd
endlocal
exit /b %RC%
