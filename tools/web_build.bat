@echo off
rem Builds the static site into web\dist. No server needed to view it:
rem the whole thing is files, which is the point of the registry mode.
setlocal
pushd "%~dp0\..\web"
call "%~dp0web_data.bat"
if errorlevel 1 ( popd & exit /b 1 )
npm run build
set RC=%ERRORLEVEL%
popd
endlocal
exit /b %RC%
