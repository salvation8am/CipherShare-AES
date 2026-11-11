@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Python environment not found. Run the README installation steps first.
  pause
  exit /b 1
)
call ".venv\Scripts\activate.bat"
echo Open http://127.0.0.1:5000 in your web browser.
python app.py
pause
