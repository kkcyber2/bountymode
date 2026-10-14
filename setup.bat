@echo off
REM One-click setup for Bounty Mode (Windows).
REM
REM   setup.bat
REM
REM Installs the package, asks for your OpenRouter key and name, writes .env, and
REM launches the UI.  Everything real happens in run.py; this is a thin wrapper
REM so the same command works on every platform.
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
  py -3 run.py %*
  goto :eof
)

where python >nul 2>nul
if %errorlevel%==0 (
  python run.py %*
  goto :eof
)

echo Python 3.9+ is required but was not found on PATH.
exit /b 1
