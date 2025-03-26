@echo off
echo Setting up the Zomato app with Network Anomaly Detection...

REM Create symbolic link to data_kdd directory if it doesn't exist
if not exist "data_kdd" (
    echo Creating link to KDD dataset...
    mklink /D data_kdd ..\data_kdd
) else (
    echo KDD dataset link already exists.
)

REM Install requirements
echo Installing requirements...
pip install flask==2.3.3 werkzeug==2.3.7 requests==2.31.0
pip install pandas numpy

echo Setup complete! Run the application with: python run.py 