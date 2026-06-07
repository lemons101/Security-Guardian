@echo off
cd /d "%~dp0"

where conda >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
  echo conda was not found in PATH.
  echo.
  echo Try opening "Anaconda Prompt" or "Miniconda Prompt", then run:
  echo   cd /d "%~dp0"
  echo   conda activate env1
  echo   python -u atlas_lab\app.py
  echo.
  echo Or use the full path to env1 python.exe:
  echo   C:\path\to\miniconda3\envs\env1\python.exe -u atlas_lab\app.py
  pause
  exit /b 1
)

echo Starting Atlas Lab with conda env: env1
conda run -n env1 python -u atlas_lab\app.py
echo.
echo Atlas Lab exited with code %ERRORLEVEL%.
pause
exit /b %ERRORLEVEL%
