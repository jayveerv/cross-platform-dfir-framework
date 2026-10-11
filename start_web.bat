@echo off
cd /d "%~dp0"
title CP-DFIR Web Console
set PY=
where python >nul 2>&1 && set PY=python
if "%PY%"=="" where py >nul 2>&1 && set PY=py
if "%PY%"=="" goto nopython
%PY% -c "import networkx, Evtx, boto3, psutil, flask" >nul 2>&1
if errorlevel 1 (
  echo Zaroori packages install ho rahe hain. Ye sirf ek baar hoga, internet chahiye.
  %PY% -m pip install -r requirements.txt
)
echo.
echo  Browser me CP-DFIR Web Console khul raha hai: http://127.0.0.1:8765
echo  Ye window khuli rakho. Band karoge to console band ho jayega.
echo  Live triage ke liye is file par right-click karke "Run as administrator" chuno.
echo.
%PY% main.py web
pause
exit /b
:nopython
echo Python nahi mila. python.org/downloads se install karo, aur install ke time "Add python.exe to PATH" tick karna.
pause
