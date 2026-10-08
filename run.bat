@echo off
cd /d "%~dp0"
title Cross-Platform DFIR Framework
set PY=
where python >nul 2>&1 && set PY=python
if "%PY%"=="" where py >nul 2>&1 && set PY=py
if "%PY%"=="" goto nopython
%PY% -c "import networkx, Evtx, boto3, psutil" >nul 2>&1
if errorlevel 1 (
  echo Zaroori packages install ho rahe hain. Ye sirf ek baar hoga, internet chahiye.
  %PY% -m pip install -r requirements.txt
)
:menu
cls
echo ===================================================
echo    Cross-Platform DFIR Framework
echo ===================================================
echo    1. Demo: simulated attack across Windows, Linux and AWS
echo    2. Full evaluation on simulated scenarios, about 1 minute
echo    3. Validation on REAL public data, downloads 44 MB first time, about 3 minutes
echo    4. Tampering demo: for the viva
echo    5. Analyse my own logs
echo    6. Export this laptop's Windows Security log, run as Administrator
echo    7. Pull AWS CloudTrail events and account state, needs AWS credentials
echo    8. Self-tests
echo    9. TRIAGE this laptop: collect live evidence, analyse, report
echo    0. Exit
echo.
set /p c=Choice: 
if "%c%"=="1" (
  %PY% main.py demo
  pause
  goto menu
)
if "%c%"=="2" (
  %PY% main.py evaluate
  pause
  goto menu
)
if "%c%"=="3" (
  %PY% main.py real-eval
  pause
  goto menu
)
if "%c%"=="4" (
  %PY% main.py tamper-demo
  pause
  goto menu
)
if "%c%"=="5" (
  set /p d=Folder path with windows_security.xml or *.evtx, auth.log, cloudtrail.json: 
  %PY% main.py analyze --input "%d%"
  pause
  goto menu
)
if "%c%"=="6" (
  %PY% main.py collect-live --out live_logs --fmt evtx
  echo.
  echo Ab option 5 chalao aur folder me live_logs likho.
  pause
  goto menu
)
if "%c%"=="7" (
  set /p days=Kitne din ke events? 
  %PY% main.py collect-aws --out live_logs --days %days%
  echo.
  echo Ab option 5 chalao aur folder me live_logs likho.
  pause
  goto menu
)
if "%c%"=="8" (
  %PY% main.py selftest
  pause
  goto menu
)
if "%c%"=="9" (
  %PY% main.py triage
  pause
  goto menu
)
if "%c%"=="0" exit /b
goto menu
:nopython
echo Python nahi mila. python.org/downloads se install karo, aur install ke time "Add python.exe to PATH" tick karna.
pause
