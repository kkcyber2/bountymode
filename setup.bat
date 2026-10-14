@echo off
REM One-click setup for Bounty Mode (Windows).
REM
REM   setup.bat
REM
REM Installs the package, asks for your OpenRouter key and name, writes .env, and
REM launches the UI.  Everything real happens in setup.py; this is a thin wrapper
REM so the same command works on every platform.
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
  py -3 setup.py %*
  goto :eof
)

where python >nul 2>nul
if %errorlevel%==0 (
  python setup.py %*
  goto :eof
)

echo Python 3.9+ is required but was not found on PATH.
exit /b 1
