@echo off
setlocal
cd /d "%~dp0"
title CipherShare AES - Research Project Setup

echo ============================================================
echo CipherShare AES - One-time setup and launch (Windows)
echo ============================================================
echo.
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  set "PYTHON=py"
) else (
  where python >nul 2>nul
  if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python is not installed or cannot be found.
    echo Install Python from https://www.python.org/downloads/windows/
    echo Close this window, install Python, and double-click this file again.
    pause
    exit /b 1
  )
  set "PYTHON=python"
)

if not exist ".venv\Scripts\python.exe" (
  echo [1/4] Creating Python environment...
  %PYTHON% -m venv .venv
  if errorlevel 1 goto :fail
)

echo [2/4] Installing the libraries needed by the project...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :fail

echo [3/4] Checking for an administrator account...
".venv\Scripts\python.exe" -c "from app import create_app; import sqlite3; a=create_app(); c=sqlite3.connect(a.config['DATABASE']); print('Current administrators:', c.execute('SELECT count(*) FROM users WHERE role=?',('admin',)).fetchone()[0]); c.close()"
if errorlevel 1 goto :fail

echo.
echo If this is your first installation, create an administrator.
echo If you already created one, answer N.
choice /C YN /M "Create an administrator now"
if errorlevel 2 goto :start
".venv\Scripts\python.exe" create_admin.py
if errorlevel 1 goto :fail

:start
echo.
echo [4/4] Starting CipherShare AES...
echo Open http://127.0.0.1:5000 in Chrome, Edge or Firefox.
echo Keep this window open while using the application.
echo To stop the server, press Ctrl+C in this window.
echo.
".venv\Scripts\python.exe" app.py
if errorlevel 1 goto :fail
pause
exit /b 0

:fail
echo.
echo Something went wrong. Please take a photo of the error in this window.
echo Check your internet connection and Python installation.
pause
exit /b 1
