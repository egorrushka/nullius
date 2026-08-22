@echo off
rem Builds every known curve, verifies each, then shows the policy matrix.
rem     tools\corpus.bat
rem
rem The list of curves comes from tools.build_curve rather than from a
rem line in this file. Two lists drift, and this one already had: it knew
rem about the prime-field curves and not the pairing-friendly ones.
setlocal
pushd "%~dp0\.."

for /f "delims=" %%C in ('python -m tools.build_curve --list') do (
    echo === %%C ===
    python -m tools.build_curve --curve %%C --out corpus --quiet
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
