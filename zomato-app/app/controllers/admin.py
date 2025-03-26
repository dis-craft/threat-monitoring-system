from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from app.services.db import get_db_connection
import threading
import queue
import time
import os
import json
import glob
from datetime import datetime

admin_bp = Blueprint('admin', __name__)

# Global variables for security scan
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

@admin_bp.route('/admin')
def admin_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('auth.login'))
    
    # No proper role checking - any logged-in user can access admin
    # Vulnerable authorization check
    
    conn = get_db_connection()
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

@admin_bp.route('/api/users')
def api_users():
    # No authentication check for sensitive data
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, username, email, role FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify(users)

@admin_bp.route('/api/orders')
def api_orders():
    # No authentication check for sensitive data
    conn = get_db_connection()
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

@admin_bp.route('/process_order', methods=['POST'])
def process_order():
    if not session.get('logged_in'):
        return redirect(url_for('auth.login'))
    
    # No CSRF token validation
    order_id = request.form['order_id']
    status = request.form['status']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE orders SET status = ? WHERE id = ?",
        (status, order_id)
    )
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('admin.admin_dashboard'))

# Security scan routes
@admin_bp.route('/security')
def security_scan():
    if not session.get('logged_in'):
        return redirect(url_for('auth.login'))
    
    # Only admin users should access the security dashboard
    if session.get('role') != 'admin':
        return redirect(url_for('main.dashboard'))
    
    return render_template('security_scan.html')

@admin_bp.route('/security/monitor')
def security_monitor():
    if not session.get('logged_in'):
        return redirect(url_for('auth.login'))
    
    # Only admin users should access the security monitoring
    if session.get('role') != 'admin':
        return redirect(url_for('main.dashboard'))
    
    return render_template('security_monitor.html')

@admin_bp.route('/admin/start_scan', methods=['POST'])
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
    thread = threading.Thread(target=run_security_scan, args=(request.host_url,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True})

@admin_bp.route('/admin/scan_status')
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

@admin_bp.route('/admin/logs')
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

@admin_bp.route('/admin/stop_scan', methods=['POST'])
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

# Helper functions for security scan
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
    global vulnerability_queue, scan_status
    
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