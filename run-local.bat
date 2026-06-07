@echo off
cd /d "%~dp0"

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  echo Checking python...
  python --version
  echo Starting Atlas Lab with python...
  python -u atlas_lab\app.py
  echo.
  echo Atlas Lab exited with code %ERRORLEVEL%.
  echo If it exited immediately, try: py -3 atlas_lab\app.py
  pause
  exit /b %ERRORLEVEL%
)

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  echo Checking py launcher...
  py -3 --version
  echo Starting Atlas Lab with py -3...
  py -3 -u atlas_lab\app.py
  echo.
  echo Atlas Lab exited with code %ERRORLEVEL%.
  pause
  exit /b %ERRORLEVEL%
)

echo Python was not found. Please install Python 3.10+ or add it to PATH.
exit /b 1
