@echo off
echo Zomato Application WiFi Setup and Launch
echo =======================================
echo.

REM Get the computer's IP address
echo Detecting your IP address...
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4 Address"') do (
    set IP=%%a
    goto :got_ip
)
:got_ip
set IP=%IP:~1%
echo Your IP address appears to be: %IP%
echo.

REM Create data_kdd directory if it doesn't exist
if not exist "data_kdd" (
    echo Creating data_kdd directory...
    mkdir data_kdd
)

REM Check if kdd_test.csv exists
if not exist "data_kdd\kdd_test.csv" (
    echo WARNING: KDD dataset not found in data_kdd directory.
    echo A sample dataset has been created, but you may want to replace it with the full KDD dataset.
)

REM Check dependencies
echo Checking dependencies...
python -c "import flask, werkzeug, requests, pandas, numpy" >nul 2>&1
if %errorlevel% neq 0 (
    echo Some dependencies are missing. Running dependency installation...
    call check_dependencies.bat
)

REM Open firewall
echo Setting up firewall rule...
netsh advfirewall firewall show rule name="Zomato App (Port 8000)" >nul 2>&1
if %errorlevel% neq 0 (
    echo Adding firewall rule for port 8000...
    netsh advfirewall firewall add rule name="Zomato App (Port 8000)" dir=in action=allow protocol=TCP localport=8000
) else (
    echo Firewall rule already exists.
)

echo.
echo =======================================
echo STARTING ZOMATO APPLICATION
echo.
echo Access the application from any device on the WiFi network using:
echo    http://%IP%:8000
echo.
echo Use these credentials to log in:
echo    Admin: admin / admin123
echo    User:  user1 / password123
echo.
echo Press Ctrl+C to stop the server when done.
echo =======================================
echo.

REM Start the application
python run.py 