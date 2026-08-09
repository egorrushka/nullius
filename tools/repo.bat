@echo off
rem Collects exactly the files that belong in the repository, into
rem release\repo. Drag the contents of that folder into GitHub.
setlocal
pushd "%~dp0\.."
python tools\stage_repo.py
set RC=%ERRORLEVEL%
if "%RC%"=="0" (
    echo.
    echo Open release\repo in Explorer and drag its contents into GitHub.
    start "" "release\repo"
)
popd
endlocal
exit /b %RC%
