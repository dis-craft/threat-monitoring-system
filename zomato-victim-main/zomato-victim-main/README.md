# Zomato Security Vulnerability Demo

This application demonstrates a food delivery platform with intentional security vulnerabilities for educational purposes. It includes an OWASP ZAP integration for automatically scanning and reporting security issues.

## Application Features

- User authentication and authorization
- Restaurant listing and management
- Food ordering system
- Reviews and ratings
- Admin dashboard

## Security Vulnerabilities

This application intentionally contains several security vulnerabilities for demonstration purposes:

1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Insecure Authentication
4. Missing Access Controls
5. Information Leakage

## OWASP ZAP Integration

The application includes a built-in security scanner using OWASP ZAP (Zed Attack Proxy), which automatically detects and reports vulnerabilities.

### Setup Instructions for ZAP Scanner

#### 1. Install OWASP ZAP

Download and install OWASP ZAP from the [official website](https://www.zaproxy.org/download/).

#### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

#### 3. Start ZAP in Daemon Mode

Start the ZAP application in daemon mode with an API key:

**Windows**:
```
"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat" -daemon -config api.key=YourApiKey
```

**Linux/Mac**:
```
/path/to/zap.sh -daemon -config api.key=YourApiKey
```

Replace `YourApiKey` with a secure key of your choice, and make sure to use the correct path to your ZAP installation.

#### 4. Set Environment Variables

Set the ZAP API key as an environment variable:

**Windows**:
```
set ZAP_API_KEY=YourApiKey
```

**Linux/Mac**:
```
export ZAP_API_KEY=YourApiKey
```

#### 5. Run the Application

```bash
python app.py
```

#### 6. Access the Security Dashboard

1. Navigate to the application in your browser: `http://localhost:5000`
2. Log in as an admin user (username: admin, password: admin123)
3. Go to the Admin Panel
4. Click on "Security" in the navigation menu or the "View Security Dashboard" button in the admin panel

#### 7. Run a Security Scan

Click the "Run New Scan" button on the security dashboard to start an automated vulnerability scan. The scan will:

1. Crawl the website using ZAP's spider
2. Perform an AJAX spider scan to discover JavaScript-driven content
3. Run an active scan to identify vulnerabilities
4. Display results categorized by risk level

### Understanding Scan Results

The scan results are displayed in a user-friendly dashboard with:

- Summary statistics showing vulnerabilities by risk level
- Detailed information for each vulnerability
- Descriptions of the issues
- Recommendations for fixing the vulnerabilities
- References to security resources

## Manual Scanning

If you prefer to run the ZAP scanner manually instead of through the web interface:

```bash
python zap_scanner.py http://localhost:5000
```

This will run a full scan and save the results to the `static/scan_results` directory.

## Security Notes

- This application is for educational purposes only
- Do not deploy this application in a production environment
- The vulnerabilities are intentional for learning about security issues

## License

This project is for educational purposes only.
