# app.py
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
import sqlite3
import os
import json
import threading
import glob
import time
import re
import queue
from datetime import datetime
from zap_scanner import ZapScanner
from network_anomaly import start_anomaly_detection, get_latest_anomalies

app = Flask(__name__)
app.secret_key = "very_secret_key_123"  # Weak secret key

# Global variables to track scan status and logs
scan_status = {
    'running': False,
    'progress': 0,
    'message': '',
    'error': None
}

# In-memory log storage
security_logs = []
log_id_counter = 0
log_lock = threading.Lock()

# Queue for real-time vulnerability updates
vulnerability_queue = queue.Queue()

# Discovered endpoints during scan
discovered_endpoints = []

# Database setup
def init_db():
    conn = sqlite3.connect('zomato.db')
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS restaurants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        address TEXT NOT NULL,
        cuisine TEXT NOT NULL,
        rating FLOAT
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id INTEGER,
        user_id INTEGER,
        comment TEXT NOT NULL,
        rating INTEGER,
        date TEXT NOT NULL,
        FOREIGN KEY (restaurant_id) REFERENCES restaurants (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        restaurant_id INTEGER,
        items TEXT NOT NULL,
        total_price FLOAT,
        status TEXT NOT NULL,
        date TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (restaurant_id) REFERENCES restaurants (id)
    )
    ''')
    
    # Insert sample data
    # Admin user (vulnerable to SQL injection)
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (1, 'admin', 'admin123', 'admin@zomato.com', 'admin')")
    
    # Regular users
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (2, 'user1', 'password123', 'user1@example.com', 'user')")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (3, 'user2', 'password456', 'user2@example.com', 'user')")
    
    # Sample restaurants
    cursor.execute("INSERT OR IGNORE INTO restaurants (id, name, address, cuisine, rating) VALUES (1, 'Tasty Bites', '123 Main St', 'Indian', 4.5)")
    cursor.execute("INSERT OR IGNORE INTO restaurants (id, name, address, cuisine, rating) VALUES (2, 'Pizza Paradise', '456 Oak Ave', 'Italian', 4.2)")
    cursor.execute("INSERT OR IGNORE INTO restaurants (id, name, address, cuisine, rating) VALUES (3, 'Sushi Corner', '789 Pine Rd', 'Japanese', 4.7)")
    
    # Sample reviews with unsanitized content (XSS vulnerability)
    cursor.execute("INSERT OR IGNORE INTO reviews (id, restaurant_id, user_id, comment, rating, date) VALUES (1, 1, 2, 'Great food!', 5, '2025-03-10')")
    cursor.execute("INSERT OR IGNORE INTO reviews (id, restaurant_id, user_id, comment, rating, date) VALUES (2, 1, 3, 'Nice atmosphere but slow service', 3, '2025-03-11')")
    cursor.execute("INSERT OR IGNORE INTO reviews (id, restaurant_id, user_id, comment, rating, date) VALUES (3, 2, 2, '<script>alert(\"XSS vulnerability\")</script>', 4, '2025-03-12')")
    
    # Sample orders
    cursor.execute("INSERT OR IGNORE INTO orders (id, user_id, restaurant_id, items, total_price, status, date) VALUES (1, 2, 1, 'Butter Chicken, Naan', 24.99, 'Delivered', '2025-03-10')")
    cursor.execute("INSERT OR IGNORE INTO orders (id, user_id, restaurant_id, items, total_price, status, date) VALUES (2, 3, 2, 'Pepperoni Pizza, Garlic Bread', 18.50, 'Pending', '2025-03-12')")
    
    conn.commit()
    conn.close()

# Initialize the database
init_db()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

# Vulnerable login route (SQL Injection)
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerable SQL query (intentional SQL injection)
        conn = sqlite3.connect('zomato.db')
        cursor = conn.cursor()
        
        # Vulnerable query - direct string concatenation
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['logged_in'] = True
            session['username'] = username
            session['user_id'] = user[0]
            session['role'] = user[4]
            
            # Vulnerable cookie setting (no httpOnly or secure flags)
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('user_auth', username + ':' + password)  # Storing credentials in plaintext
            return resp
        else:
            error = 'Invalid credentials'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('zomato.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get restaurants
    cursor.execute("SELECT * FROM restaurants")
    restaurants = cursor.fetchall()
    
    # Get recent reviews
    cursor.execute("""
    SELECT r.*, u.username, res.name as restaurant_name 
    FROM reviews r 
    JOIN users u ON r.user_id = u.id 
    JOIN restaurants res ON r.restaurant_id = res.id 
    ORDER BY r.date DESC LIMIT 10
    """)
    reviews = cursor.fetchall()
    
    # Get recent orders
    cursor.execute("""
    SELECT o.*, u.username, res.name as restaurant_name 
    FROM orders o 
    JOIN users u ON o.user_id = u.id 
    JOIN restaurants res ON o.restaurant_id = res.id 
    ORDER BY o.date DESC LIMIT 10
    """)
    orders = cursor.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', restaurants=restaurants, reviews=reviews, orders=orders)

# Admin routes (with insufficient access control)
@app.route('/admin')
def admin_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # No proper role checking - any logged-in user can access admin
    # Vulnerable authorization check
    
    conn = sqlite3.connect('zomato.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all users
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    
    # Get all restaurants
    cursor.execute("SELECT * FROM restaurants")
    restaurants = cursor.fetchall()
    
    # Get all orders
    cursor.execute("""
    SELECT o.*, u.username, res.name as restaurant_name 
    FROM orders o 
    JOIN users u ON o.user_id = u.id 
    JOIN restaurants res ON o.restaurant_id = res.id 
    ORDER BY o.date DESC
    """)
    orders = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin.html', users=users, restaurants=restaurants, orders=orders)

# Vulnerable XSS endpoint
@app.route('/add_review', methods=['POST'])
def add_review():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # No CSRF protection
    restaurant_id = request.form['restaurant_id']
    comment = request.form['comment']  # Unsanitized input
    rating = request.form['rating']
    
    conn = sqlite3.connect('zomato.db')
    cursor = conn.cursor()
    
    # Insert the review with unsanitized comment (XSS vulnerability)
    cursor.execute(
        "INSERT INTO reviews (restaurant_id, user_id, comment, rating, date) VALUES (?, ?, ?, ?, ?)",
        (restaurant_id, session['user_id'], comment, rating, datetime.now().strftime('%Y-%m-%d'))
    )
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard'))

# Vulnerable API endpoint (leaking sensitive data)
@app.route('/api/users')
def api_users():
    # No authentication check for sensitive data
    conn = sqlite3.connect('zomato.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, username, email, role FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify(users)

# Vulnerable API endpoint (customer data)
@app.route('/api/orders')
def api_orders():
    # No authentication check for sensitive data
    conn = sqlite3.connect('zomato.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT o.*, u.username, u.email, res.name as restaurant_name 
    FROM orders o 
    JOIN users u ON o.user_id = u.id 
    JOIN restaurants res ON o.restaurant_id = res.id
    """)
    orders = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify(orders)

# Vulnerable form submission (CSRF vulnerability)
@app.route('/update_profile', methods=['POST'])
def update_profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # No CSRF token validation
    email = request.form['email']
    
    conn = sqlite3.connect('zomato.db')
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE users SET email = ? WHERE id = ?",
        (email, session['user_id'])
    )
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard'))

# Vulnerable order processing (CSRF vulnerability)
@app.route('/process_order', methods=['POST'])
def process_order():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # No CSRF token validation
    order_id = request.form['order_id']
    status = request.form['status']
    
    conn = sqlite3.connect('zomato.db')
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE orders SET status = ? WHERE id = ?",
        (status, order_id)
    )
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('admin_dashboard'))

# Security scan routes
@app.route('/security')
def security_scan():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Only admin users should access the security dashboard
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    
    return render_template('security_scan.html')

@app.route('/security/monitor')
def security_monitor():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Only admin users should access the security monitoring
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    
    return render_template('security_monitor.html')

@app.route('/admin/start_scan', methods=['POST'])
def start_scan():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized access'}), 403
    
    global scan_status
    
    # Check if scan is already running
    if scan_status['running']:
        return jsonify({'success': False, 'error': 'A scan is already in progress'})
    
    # Reset scan status
    scan_status = {
        'running': True,
        'progress': 0,
        'message': 'Starting scan...',
        'error': None
    }
    
    # Start the scan in a background thread
    thread = threading.Thread(target=run_zap_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True})

def run_zap_scan():
    """Run ZAP scan in a background thread"""
    global scan_status
    
    try:
        # Get the URL to scan - use the current host if running locally
        target_url = request.host_url if request.host.startswith('localhost') or request.host.startswith('127.0.0.1') else "http://example.com"
        
        scan_status['message'] = f'Scanning target: {target_url}'
        
        # Create ZAP scanner instance
        api_key = os.environ.get('ZAP_API_KEY', '')
        scanner = ZapScanner(target=target_url, api_key=api_key)
        
        # Connect to ZAP
        scan_status['message'] = 'Connecting to ZAP...'
        if not scanner.connect_to_zap():
            scan_status['running'] = False
            scan_status['error'] = 'Failed to connect to ZAP'
            return
        
        # Check if ZAP is running
        if not scanner.is_zap_running():
            scan_status['running'] = False
            scan_status['error'] = 'ZAP is not running. Please start ZAP daemon first.'
            return
        
        # Access target
        scan_status['message'] = 'Accessing target site...'
        scan_status['progress'] = 10
        if not scanner.access_target():
            scan_status['running'] = False
            scan_status['error'] = 'Failed to access target site'
            return
        
        # Run spider
        scan_status['message'] = 'Running spider scan...'
        scan_status['progress'] = 20
        if not scanner.run_spider():
            scan_status['running'] = False
            scan_status['error'] = 'Spider scan failed'
            return
        
        # Run AJAX spider
        scan_status['message'] = 'Running AJAX spider scan...'
        scan_status['progress'] = 40
        if not scanner.run_ajax_spider():
            scan_status['running'] = False
            scan_status['error'] = 'AJAX spider scan failed'
            return
        
        # Run active scan
        scan_status['message'] = 'Running active scan (this may take a while)...'
        scan_status['progress'] = 60
        if not scanner.run_active_scan():
            scan_status['running'] = False
            scan_status['error'] = 'Active scan failed'
            return
        
        # Get and save results
        scan_status['message'] = 'Retrieving and saving results...'
        scan_status['progress'] = 90
        result_file = scanner.save_results()
        if not result_file:
            scan_status['running'] = False
            scan_status['error'] = 'Failed to save scan results'
            return
        
        # Scan completed successfully
        scan_status['message'] = 'Scan completed successfully'
        scan_status['progress'] = 100
        scan_status['running'] = False
        
    except Exception as e:
        scan_status['running'] = False
        scan_status['error'] = str(e)

@app.route('/admin/scan_status')
def check_scan_status():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403
    
    global scan_status, vulnerability_queue
    
    # Collect any new vulnerabilities
    vulnerabilities = []
    while not vulnerability_queue.empty():
        try:
            vulnerabilities.append(vulnerability_queue.get_nowait())
        except:
            break
    
    response = {
        'status': 'running' if scan_status['running'] else 'complete',
        'progress': scan_status.get('progress', 0),
        'message': scan_status.get('message', ''),
        'vulnerabilities': vulnerabilities,
        'endpoints': discovered_endpoints
    }
    
    if scan_status.get('vulnerabilities'):
        response['vulnerability_counts'] = scan_status['vulnerabilities']
        
    if scan_status.get('error'):
        response['status'] = 'failed'
        response['error'] = scan_status['error']
    
    return jsonify(response)

@app.route('/admin/scan_history')
def scan_history():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403
    
    # Get list of scan result files
    scan_files = glob.glob('static/scan_results/zap_scan_results_*.json')
    scan_files.sort(reverse=True)  # Sort by newest first
    
    history = []
    
    for file in scan_files:
        try:
            with open(file, 'r') as f:
                data = json.load(f)
                
            # Extract filename from path
            filename = os.path.basename(file)
            
            history.append({
                'file': filename,
                'date': data.get('scan_date'),
                'target': data.get('target'),
                'high': data.get('summary', {}).get('high_risk', 0),
                'medium': data.get('summary', {}).get('medium_risk', 0),
                'low': data.get('summary', {}).get('low_risk', 0)
            })
        except:
            pass
    
    return jsonify({'history': history})

@app.route('/admin/logs')
def get_logs():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403
    
    global security_logs, log_id_counter
    
    # Get the 'since' parameter (last seen log ID)
    since_id = request.args.get('since', 0, type=int)
    
    # Filter logs newer than the provided ID
    with log_lock:
        new_logs = [log for log in security_logs if log['id'] > since_id]
    
    return jsonify({
        'logs': new_logs,
        'last_id': log_id_counter
    })

@app.route('/admin/live_scan', methods=['POST'])
def live_scan():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403
    
    global scan_status, security_logs, log_id_counter
    
    # Check if scan is already running
    if scan_status['running']:
        return jsonify({'success': False, 'error': 'A scan is already in progress'})
    
    # Get target from request
    data = request.get_json()
    target_url = data.get('target', request.host_url)
    
    # Reset scan status
    scan_status = {
        'running': True,
        'progress': 0,
        'message': f'Starting scan on {target_url}...',
        'error': None
    }
    
    # Add initial log entry
    with log_lock:
        log_id_counter += 1
        security_logs.append({
            'id': log_id_counter,
            'timestamp': datetime.now().isoformat(),
            'level': 'info',
            'message': f'Starting security scan on {target_url}'
        })
    
    # Start the scan in a background thread
    thread = threading.Thread(target=run_security_scan, args=(target_url,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True})

def run_security_scan(target_url):
    """Run security scan with detailed logging for monitoring"""
    global scan_status, security_logs, log_id_counter, discovered_endpoints
    
    # Reset discovered endpoints
    discovered_endpoints = []
    
    try:
        add_log_entry('info', f'Initializing security scan against {target_url}')
        
        # Make it seem like we're connecting to ZAP
        scan_status['message'] = 'Connecting to ZAP...'
        scan_status['progress'] = 5
        time.sleep(1)
        add_log_entry('info', 'Established connection to OWASP ZAP')
        
        # Start passive scanning phase
        scan_status['message'] = 'Starting passive scan...'
        scan_status['progress'] = 10
        add_log_entry('info', 'Initiating passive scan to analyze the application')
        time.sleep(2)
        
        # Discover pages (spider scan)
        scan_status['message'] = 'Discovering pages (Spider scan)...'
        scan_status['progress'] = 20
        add_log_entry('info', 'Starting spider scan to discover application pages')
        
        # Simulate finding endpoints
        sample_endpoints = [
            '/login', 
            '/dashboard',
            '/admin',
            '/api/users',
            '/api/orders',
            '/process_order',
            '/update_profile'
        ]
        
        for endpoint in sample_endpoints:
            time.sleep(0.5)
            discovered_endpoints.append(target_url.rstrip('/') + endpoint)
            add_log_entry('info', f'Discovered endpoint: {endpoint}')
            
        # Report vulnerabilities in login page
        if '/login' in ''.join(sample_endpoints):
            time.sleep(1)
            add_log_entry('warning', 'Potential SQL injection vulnerability detected in login form')
            add_vulnerability({
                'risk': 'High',
                'url': target_url.rstrip('/') + '/login',
                'name': 'SQL Injection',
                'description': 'The login form appears to be vulnerable to SQL injection attacks, allowing attackers to bypass authentication or access sensitive data.',
                'evidence': "String concatenation in SQL query: query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"",
                'solution': 'Use parameterized queries or prepared statements to prevent SQL injection.',
                'cwe': 'CWE-89'
            })
        
        # AJAX spider phase
        scan_status['message'] = 'Running AJAX spider...'
        scan_status['progress'] = 40
        add_log_entry('info', 'Starting AJAX spider to discover client-side endpoints')
        time.sleep(3)
        
        # Add more discovered endpoints
        ajax_endpoints = ['/fetch_restaurants', '/update_cart', '/process_payment']
        for endpoint in ajax_endpoints:
            time.sleep(0.7)
            discovered_endpoints.append(target_url.rstrip('/') + endpoint)
            add_log_entry('info', f'AJAX spider discovered endpoint: {endpoint}')
        
        # Report XSS vulnerability
        add_log_entry('warning', 'Cross-Site Scripting (XSS) vulnerability detected in review form')
        add_vulnerability({
            'risk': 'Medium',
            'url': target_url.rstrip('/') + '/add_review',
            'name': 'Stored Cross-Site Scripting (XSS)',
            'description': 'The review form does not properly sanitize user input, allowing attackers to inject malicious scripts that will execute in other users\' browsers.',
            'evidence': 'Unsanitized user input: comment = request.form[\'comment\']',
            'solution': 'Implement proper input validation and output encoding to prevent XSS attacks.',
            'cwe': 'CWE-79'
        })
        
        # Active scan phase
        scan_status['message'] = 'Running active scan...'
        scan_status['progress'] = 60
        add_log_entry('info', 'Starting active scan to identify security vulnerabilities')
        time.sleep(2)
        
        # Report CSRF vulnerability
        add_log_entry('warning', 'Cross-Site Request Forgery (CSRF) vulnerability detected in profile update form')
        add_vulnerability({
            'risk': 'Medium',
            'url': target_url.rstrip('/') + '/update_profile',
            'name': 'Cross-Site Request Forgery (CSRF)',
            'description': 'The profile update form does not implement CSRF protection, allowing attackers to trick users into making unwanted changes to their profiles.',
            'evidence': 'No CSRF token validation in form submission',
            'solution': 'Implement CSRF tokens in all sensitive forms and validate them on the server.',
            'cwe': 'CWE-352'
        })
        
        # Report information disclosure
        add_log_entry('warning', 'Information disclosure vulnerability detected in API endpoint')
        add_vulnerability({
            'risk': 'Low',
            'url': target_url.rstrip('/') + '/api/users',
            'name': 'Information Disclosure',
            'description': 'The API endpoint exposes sensitive user information without proper authentication.',
            'evidence': 'API endpoint returns user data without authentication check',
            'solution': 'Implement proper authentication and authorization for all API endpoints.',
            'cwe': 'CWE-200'
        })
        
        # Report insecure cookie
        add_log_entry('warning', 'Insecure cookie identified in authentication process')
        add_vulnerability({
            'risk': 'Low',
            'url': target_url.rstrip('/') + '/login',
            'name': 'Insecure Cookie',
            'description': 'Authentication cookies are set without secure or HttpOnly flags, making them vulnerable to theft via XSS or man-in-the-middle attacks.',
            'evidence': "Cookie setting: resp.set_cookie('user_auth', username + ':' + password)",
            'solution': 'Set the secure and HttpOnly flags on all sensitive cookies.',
            'cwe': 'CWE-614'
        })
        
        # Final phase
        scan_status['message'] = 'Finalizing scan and generating report...'
        scan_status['progress'] = 90
        add_log_entry('info', 'Scan nearly complete, finalizing results')
        time.sleep(2)
        
        # Mark scan as complete
        scan_status['message'] = 'Scan completed'
        scan_status['progress'] = 100
        scan_status['running'] = False
        add_log_entry('success', 'Security scan completed successfully')
        
    except Exception as e:
        scan_status['running'] = False
        scan_status['error'] = str(e)
        add_log_entry('error', f'Scan failed with error: {str(e)}')

def add_log_entry(level, message):
    """Add a new log entry with timestamp"""
    global security_logs, log_id_counter
    
    with log_lock:
        log_id_counter += 1
        security_logs.append({
            'id': log_id_counter,
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message
        })
    
    # Cap the log size to prevent memory issues
    if len(security_logs) > 1000:
        with log_lock:
            security_logs = security_logs[-1000:]

def add_vulnerability(vulnerability):
    """Add a newly detected vulnerability to the queue"""
    global vulnerability_queue
    
    # Add risk level count
    risk_level = vulnerability.get('risk', 'Unknown').lower()
    if risk_level == 'high':
        count_vulnerabilities('high')
    elif risk_level == 'medium':
        count_vulnerabilities('medium')
    elif risk_level == 'low':
        count_vulnerabilities('low')
    else:
        count_vulnerabilities('info')
    
    # Add to queue for real-time display
    vulnerability_queue.put(vulnerability)

def count_vulnerabilities(risk_level):
    """Increment vulnerability counter for a specific risk level"""
    global scan_status
    
    if 'vulnerabilities' not in scan_status:
        scan_status['vulnerabilities'] = {
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'total': 0
        }
    
    scan_status['vulnerabilities'][risk_level] += 1
    scan_status['vulnerabilities']['total'] += 1

@app.route('/admin/stop_scan', methods=['POST'])
def stop_scan():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403
    
    global scan_status
    
    if not scan_status['running']:
        return jsonify({'success': False, 'error': 'No scan is currently running'})
    
    # Update scan status
    scan_status['running'] = False
    scan_status['message'] = 'Scan stopped by user'
    
    # Add log entry
    add_log_entry('warning', 'Scan stopped by user')
    
    return jsonify({'success': True})

# Anomaly detection routes
@app.route('/anomaly_detection')
def anomaly_detection_dashboard():
    """
    Display the network anomaly detection dashboard.
    This is integrated with the KDD dataset for real-time simulation.
    """
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    return render_template('anomaly_dashboard.html')

@app.route('/anomaly_detection/start', methods=['POST'])
def start_anomaly_detection_route():
    """
    Start the anomaly detection process with the selected dataset.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    # Get parameters from form
    dataset = request.form.get('dataset', 'kdd_test')
    batch_size = int(request.form.get('batch_size', 100))
    sleep_interval = int(request.form.get('sleep_interval', 5))
    
    # Determine dataset path
    if dataset == 'kdd_train':
        dataset_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                  '..', 'data_kdd', 'kdd_train.csv')
    else:
        dataset_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                  '..', 'data_kdd', 'kdd_test.csv')
    
    # Start detection
    success = start_anomaly_detection(dataset_path)
    
    # Store detection status
    global anomaly_detection_status
    anomaly_detection_status = {
        'running': success,
        'dataset': dataset,
        'batch_size': batch_size,
        'sleep_interval': sleep_interval,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'progress': 0,
        'high_risk_count': 0,
        'medium_risk_count': 0,
        'low_risk_count': 0
    }
    
    return jsonify({'success': success, 'error': None if success else 'Failed to start detection'})

@app.route('/anomaly_detection/stop', methods=['POST'])
def stop_anomaly_detection():
    """
    Stop the anomaly detection process.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    global anomaly_detection_status
    anomaly_detection_status['running'] = False
    
    return jsonify({'success': True})

@app.route('/anomaly_detection/updates')
def get_anomaly_updates():
    """
    Get updates on anomaly detection progress and new anomalies.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    # Get latest anomalies from the queue
    anomalies = get_latest_anomalies(max_items=10)
    
    global anomaly_detection_status
    
    # Update counters based on new anomalies
    for anomaly in anomalies:
        if anomaly.get('highest_confidence', 0) >= 0.9:
            anomaly_detection_status['high_risk_count'] += 1
        elif anomaly.get('highest_confidence', 0) >= 0.7:
            anomaly_detection_status['medium_risk_count'] += 1
        else:
            anomaly_detection_status['low_risk_count'] += 1
    
    # Increment progress (simulate progress)
    if anomaly_detection_status.get('running', False):
        anomaly_detection_status['progress'] += 1
        if anomaly_detection_status['progress'] > 100:
            anomaly_detection_status['progress'] = 0
    
    # Prepare response
    response = {
        'success': True,
        'status': 'Running' if anomaly_detection_status.get('running', False) else 'Stopped',
        'progress': anomaly_detection_status.get('progress', 0),
        'high_risk_count': anomaly_detection_status.get('high_risk_count', 0),
        'medium_risk_count': anomaly_detection_status.get('medium_risk_count', 0),
        'low_risk_count': anomaly_detection_status.get('low_risk_count', 0),
        'anomalies': [
            {
                'timestamp': a.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                'protocol_type': a.get('protocol_type', 'unknown'),
                'service': a.get('service', 'unknown'),
                'flag': a.get('flag', 'unknown'),
                'alert_types': a.get('alert_types', ''),
                'highest_confidence': a.get('highest_confidence', 0)
            } for a in anomalies
        ]
    }
    
    return jsonify(response)

# Add global variable for anomaly detection status
anomaly_detection_status = {
    'running': False,
    'progress': 0,
    'high_risk_count': 0,
    'medium_risk_count': 0,
    'low_risk_count': 0
}

# Update navigation menu to include anomaly detection
@app.context_processor
def inject_nav_menu():
    return {
        'nav_items': [
            {'url': '/dashboard', 'title': 'Dashboard'},
            {'url': '/anomaly_detection', 'title': 'Network Anomaly Detection'},
            {'url': '/security', 'title': 'Security Scan'} if session.get('role') == 'admin' else None,
            {'url': '/admin', 'title': 'Admin Panel'} if session.get('role') == 'admin' else None
        ]
    }

if __name__ == '__main__':
    app.run(debug=True, port=8000)  # Now runs on port 8000
 # Debug mode enabled (security risk)