@echo off
rem Checks the PARI/GP backend end to end against secp256k1.
rem Pass an explicit path if gp is not on PATH, e.g.:
rem     tools\gp_selftest.bat C:\pari\gp.exe
setlocal
pushd "%~dp0\.."

if "%~1"=="" (
    python -m core.backends.gp --self-test
) else (
    python -m core.backends.gp --self-test --gp "%~1"
)
set RC=%ERRORLEVEL%

if not "%RC%"=="0" (
    echo.
    echo Self test failed. Usual causes:
    echo   - gp.exe not on PATH: pass its full path as an argument
    echo   - seadata not installed: point counting will crawl
)

popd
endlocal
exit /b %RC%
