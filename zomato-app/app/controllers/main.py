from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from app.services.db import get_db_connection
from datetime import datetime

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('auth.login'))
    
    conn = get_db_connection()
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

@main_bp.route('/add_review', methods=['POST'])
def add_review():
    if not session.get('logged_in'):
        return redirect(url_for('auth.login'))
    
    # No CSRF protection
    restaurant_id = request.form['restaurant_id']
    comment = request.form['comment']  # Unsanitized input
    rating = request.form['rating']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Insert the review with unsanitized comment (XSS vulnerability)
    cursor.execute(
        "INSERT INTO reviews (restaurant_id, user_id, comment, rating, date) VALUES (?, ?, ?, ?, ?)",
        (restaurant_id, session['user_id'], comment, rating, datetime.now().strftime('%Y-%m-%d'))
    )
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('main.dashboard'))

@main_bp.route('/update_profile', methods=['POST'])
def update_profile():
    if not session.get('logged_in'):
        return redirect(url_for('auth.login'))
    
    # No CSRF token validation
    email = request.form['email']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE users SET email = ? WHERE id = ?",
        (email, session['user_id'])
    )
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('main.dashboard')) 