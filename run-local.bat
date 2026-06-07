@echo off
cd /d "%~dp0"

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  echo Checking python...
  python --version
  echo Starting OpenClaw Security Console with python...
  python -u openclaw_security_console\app.py
  echo.
  echo OpenClaw Security Console exited with code %ERRORLEVEL%.
  echo If it exited immediately, try: py -3 openclaw_security_console\app.py
  pause
  exit /b %ERRORLEVEL%
)

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  echo Checking py launcher...
  py -3 --version
  echo Starting OpenClaw Security Console with py -3...
  py -3 -u openclaw_security_console\app.py
  echo.
  echo OpenClaw Security Console exited with code %ERRORLEVEL%.
  pause
  exit /b %ERRORLEVEL%
)

echo Python was not found. Please install Python 3.10+ or add it to PATH.
exit /b 1
