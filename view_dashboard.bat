@echo off
cd /d "%~dp0"
set PY=
where python >nul 2>&1 && set PY=python
if "%PY%"=="" where py >nul 2>&1 && set PY=py
if "%PY%"=="" (
  echo Python nahi mila. python.org/downloads se install karo.
  pause
  exit /b
)
if not exist results\evaluation.json (
  echo Pehle run.bat me option 2 ^(Full evaluation^) chalao, phir ye dashboard banega.
  pause
  exit /b
)
%PY% make_dashboard.py
