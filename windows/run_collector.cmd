@echo off
setlocal
set "APPDIR=C:\Program Files\NessusDrataCollector"
set "DATADIR=C:\ProgramData\NessusDrataCollector"
set "PY=%APPDIR%\.venv\Scripts\python.exe"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

if not exist "%PY%" (
  echo [FATAL] interpreter not found: %PY%
  exit /b 2
)

"%PY%" -m nessus_drata.cli run ^
  --config "%DATADIR%\config\config.yaml" ^
  --checks "%DATADIR%\config\checks.yaml" ^
  --log-level INFO
set "RC=%ERRORLEVEL%"

echo [%DATE% %TIME%] exit=%RC% >> "%DATADIR%\logs\task-history.log"
exit /b %RC%
