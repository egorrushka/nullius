@echo off
rem Assembles the viewer release into release\ccert-viewer, plus a zip.
rem Builds whatever is missing first, so this is safe to run from cold.
setlocal
pushd "%~dp0\.."

if not exist "verifier\target\release\ccert-verify.exe" (
    call "%~dp0build_verifier.bat" || ( popd & exit /b 1 )
)

if not exist "corpus\secp256k1.ccert" (
    echo No corpus yet, building it.
    call "%~dp0corpus.bat" || ( popd & exit /b 1 )
)

call "%~dp0web_build.bat"
if errorlevel 1 ( popd & exit /b 1 )

python tools\make_release.py
set RC=%ERRORLEVEL%
popd
endlocal
exit /b %RC%
