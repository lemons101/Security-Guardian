@echo off
cd /d "%~dp0"

where conda >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
  echo conda was not found in PATH.
  echo.
  echo Try opening "Anaconda Prompt" or "Miniconda Prompt", then run:
  echo   cd /d "%~dp0"
  echo   conda activate env1
  echo   python -u openclaw_security_console\app.py
  echo.
  echo Or use the full path to env1 python.exe:
  echo   C:\path\to\miniconda3\envs\env1\python.exe -u openclaw_security_console\app.py
  pause
  exit /b 1
)

echo Starting OpenClaw Security Console with conda env: env1
conda run -n env1 python -u openclaw_security_console\app.py
echo.
echo OpenClaw Security Console exited with code %ERRORLEVEL%.
pause
exit /b %ERRORLEVEL%
