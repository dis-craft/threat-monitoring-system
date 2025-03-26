@echo off
echo Checking and installing dependencies for Zomato Application...

REM Check if pip is installed
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: pip is not installed. Please install pip first.
    pause
    exit /b 1
)

echo Installing dependencies...
pip install flask==2.3.3 werkzeug==2.3.7 requests==2.31.0
pip install pandas numpy

echo Dependency installation complete!
echo.
echo If you're still having issues, try running the following commands manually:
echo pip install flask==2.3.3
echo pip install werkzeug==2.3.7 
echo pip install requests==2.31.0
echo pip install pandas
echo pip install numpy
echo.
pause 