@echo off
echo Opening Windows Firewall for Zomato Application on port 8000...
netsh advfirewall firewall add rule name="Zomato App (Port 8000)" dir=in action=allow protocol=TCP localport=8000
echo Firewall rule added. If you still have connection issues, please check your firewall settings manually.
pause 