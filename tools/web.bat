@echo off
rem Opens the dossier viewer in development mode, at http://localhost:5173
rem Press Ctrl+C in this window to stop it.
setlocal
pushd "%~dp0\..\web"

if not exist "public\data\index.json" (
    echo No corpus published yet, doing that first.
    call "%~dp0web_data.bat"
    if errorlevel 1 ( popd & exit /b 1 )
)

npm run dev
popd
endlocal
