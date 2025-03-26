from flask import Blueprint, render_template, request, redirect, url_for, session, make_response
from app.services.db import get_db_connection

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerable SQL query (intentional SQL injection)
        conn = get_db_connection()
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
            resp = make_response(redirect(url_for('main.dashboard')))
            resp.set_cookie('user_auth', username + ':' + password)  # Storing credentials in plaintext
            return resp
        else:
            error = 'Invalid credentials'
    
    return render_template('login.html', error=error)

@auth_bp.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('main.index')) 