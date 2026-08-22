@echo off
rem Publishes the corpus into the web app's data folder.
rem Run this after tools\corpus.bat, and again whenever a bundle changes.
setlocal
pushd "%~dp0\.."
python tools\export_web.py
set RC=%ERRORLEVEL%
popd
endlocal
exit /b %RC%
