@echo off
rem Builds every known curve, verifies each, then shows the policy matrix.
rem     tools\corpus.bat
setlocal
pushd "%~dp0\.."

for %%C in (secp256k1 p-256) do (
    echo === %%C ===
    python -m core.bundle.builder --curve %%C --out corpus --quiet
    if errorlevel 1 (
        echo Build failed for %%C
        popd
        exit /b 1
    )
    verifier\target\release\ccert-verify.exe corpus\%%C.ccert
    if errorlevel 1 (
        echo Verification failed for %%C
        popd
        exit /b 1
    )
    echo.
)

python -m core.policy.engine --corpus corpus
set RC=%ERRORLEVEL%
popd
endlocal
exit /b %RC%
