@echo off
rem Builds the static site into web\dist. No server needed to view it:
rem the whole thing is files, which is the point of the registry mode.
setlocal
pushd "%~dp0\..\web"
call "%~dp0web_data.bat"
if errorlevel 1 ( popd & exit /b 1 )

rem The page imports the verifier module. A tree that has never built it
rem for the browser gets the placeholder instead, which refuses with a
rem reason rather than pretending — so the page still builds, still
rem opens, and says plainly that it verified nothing.
if not exist src\verifier.generated.js (
    echo No browser verifier; using the placeholder. Run tools\build_wasm.bat
    echo to compile one, and the page will check certificates itself.
    copy /Y src\verifier.placeholder.js src\verifier.generated.js >nul
)

npm run build
set RC=%ERRORLEVEL%
popd
endlocal
exit /b %RC%
