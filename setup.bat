@echo off
echo ===================================
echo   PhishGuard - Setup
echo ===================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    exit /b 1
)

REM Create virtual environment
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Initialize database
echo Initializing database...
python -c "from app import app, db; app.app_context().push(); db.create_all()"

REM Create demo data
echo Setting up demo data...
python demo_data.py

echo.
echo ===================================
echo   Setup Complete!
echo ===================================
echo.
echo To start the application, run: start.bat
echo.
pause
