@echo off
REM Replace this path with your actual ZAP installation path
set ZAP_PATH="C:\Program Files\OWASP ZAP\zap.bat"
set ZAP_API_KEY=zap123

echo Starting ZAP in daemon mode with API key: %ZAP_API_KEY%
echo (This window must remain open while using the vulnerability scanner)

REM Set environment variable for the Python app
set "ZAP_API_KEY=%ZAP_API_KEY%"

REM Start ZAP in daemon mode with the API key
%ZAP_PATH% -daemon -host 127.0.0.1 -port 8080 -config api.key=%ZAP_API_KEY% -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true