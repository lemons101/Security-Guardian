@echo off
cd /d "%~dp0"

set ATLAS_HOST=127.0.0.1
set ATLAS_PORT=8511

if exist "F:\Anaconda\Scripts\conda.exe" (
  F:\Anaconda\Scripts\conda.exe run -n env1 python -B -u atlas_lab\app.py
  exit /b %ERRORLEVEL%
)

where conda >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  conda run -n env1 python -B -u atlas_lab\app.py
  exit /b %ERRORLEVEL%
)

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  python -B -u atlas_lab\app.py
  exit /b %ERRORLEVEL%
)

echo Cannot find F:\Anaconda\Scripts\conda.exe, conda, or python.
echo Please update run_dashboard.cmd with your env1 python path.
pause
exit /b 1
