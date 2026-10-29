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

if not exist "%DATADIR%\logs" mkdir "%DATADIR%\logs"

REM Global flags go BEFORE the subcommand; argparse rejects them after "run".
REM Secrets: machine-scope env vars, or %DATADIR%\config\.env (read automatically).
"%PY%" -m nessus_drata.cli ^
  --config "%DATADIR%\config\config.yaml" ^
  --checks "%DATADIR%\config\checks.yaml" ^
  --log-level INFO ^
  run
set "RC=%ERRORLEVEL%"

echo [%DATE% %TIME%] exit=%RC% >> "%DATADIR%\logs\task-history.log"
exit /b %RC%
