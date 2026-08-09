@echo off
rem Runs the whole suite. Tests that need gp skip themselves when it is absent.
setlocal
pushd "%~dp0\.."
python -m pytest tests -q %*
set RC=%ERRORLEVEL%
popd
endlocal
exit /b %RC%
