# Zomato Application with Network Anomaly Detection

A Flask-based web application that simulates a food delivery platform with integrated network traffic anomaly detection.

## Project Structure

```
zomato-app/
├── app/                          # Main application package
│   ├── controllers/              # Route handlers and controllers
│   ├── services/                 # Service modules
│   │   └── anomaly_detection/    # Anomaly detection logic
│   ├── static/                   # Static assets (CSS)
│   ├── templates/                # HTML templates
│   └── __init__.py              # App initialization
├── run.py                        # Application entry point
├── run_on_wifi.bat               # Script to run the app accessible over WiFi
├── setup.bat                     # Setup script for Windows
└── requirements.txt              # Python dependencies
```

## Setup Instructions

### For Windows:

1. Ensure you have Python 3.7+ installed
2. Download and extract the KDD Cup dataset to a directory named `data_kdd` in the parent directory
3. Run the setup script:

```
setup.bat
```

4. Start the application:

```
python run.py
```

### WiFi Access (For Windows):

To make the application accessible to all devices on your WiFi network, use the provided `run_on_wifi.bat` script:

1. Open Command Prompt or PowerShell as Administrator
2. Navigate to the `zomato-app` directory
3. Run:
   ```
   run_on_wifi.bat
   ```
4. The script will:
   - Detect your IP address
   - Set up required directories
   - Check and install dependencies
   - Add a firewall rule for port 8000
   - Start the application
5. Other devices on the same WiFi network can access the application by entering the URL displayed in the terminal (typically `http://YOUR_IP_ADDRESS:8000`)

If you're having connection issues:
- Make sure all devices are on the same WiFi network
- Check that your firewall isn't blocking the connection
- Verify that your WiFi router doesn't have client isolation enabled

### For Linux/macOS:

1. Ensure you have Python 3.7+ installed
2. Download and extract the KDD Cup dataset to a directory named `data_kdd` in the parent directory
3. Create a symbolic link to the dataset:

```
ln -s ../data_kdd data_kdd
```

4. Install dependencies:

```
pip install -r requirements.txt
```

5. Start the application with network access:

```
python -c "import run; from app import create_app; app = create_app(); app.run(debug=True, port=8000, host='0.0.0.0')"
```

## Usage

1. Access the application at: http://localhost:8000 (or the WiFi IP displayed when starting with `run_on_wifi.bat`)
2. Login with provided credentials:
   - Admin: `admin` / `admin123`
   - User: `user1` / `password123`
3. Access the network anomaly detection dashboard from the navigation menu
4. Start anomaly detection with the provided KDD dataset
5. Monitor detected anomalies in real-time

## Features

- **Food Delivery Platform**: Browse restaurants, place orders, and write reviews
- **Network Anomaly Detection**: Real-time rule-based detection of network traffic anomalies
- **Security Scanning**: Admin-only security vulnerability scanning
- **Dashboard**: Real-time visualization of detected anomalies

## Troubleshooting WiFi Access

If other devices cannot connect to your application:

1. **Firewall Issues**: Run `open_firewall.bat` as Administrator
2. **IP Address Changes**: WiFi IP addresses can change occasionally, run `run_on_wifi.bat` again to get the updated address
3. **Dependencies Missing**: Run `check_dependencies.bat`
4. **Data Issues**: Ensure the KDD dataset is properly placed in the `data_kdd` directory

## Note

This application intentionally contains security vulnerabilities for educational purposes and should not be used in a production environment. 