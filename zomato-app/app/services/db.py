import sqlite3
from datetime import datetime

def get_db_connection():
    """Get SQLite database connection."""
    conn = sqlite3.connect('zomato.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with tables and sample data."""
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