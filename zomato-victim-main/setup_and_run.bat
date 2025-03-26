@echo off
echo Setting up the Zomato Victim app with Network Anomaly Detection...

REM Create symbolic link to data_kdd directory
cd zomato-victim-main
echo Creating link to KDD dataset...
mklink /D data_kdd ..\..\data_kdd

REM Install requirements
echo Installing requirements...
pip install -r requirements.txt
pip install pandas numpy

REM Run the app
echo Starting Zomato app...
python app.py 