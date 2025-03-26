from flask import Flask
import os

def create_app():
    app = Flask(__name__)
    app.secret_key = "very_secret_key_123"  # Weak secret key for demo purposes
    
    # Import controllers
    from app.controllers.auth import auth_bp
    from app.controllers.main import main_bp
    from app.controllers.admin import admin_bp
    from app.controllers.anomaly import anomaly_bp
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(anomaly_bp)
    
    # Initialize database
    from app.services.db import init_db
    init_db()
    
    # Add context processor for navigation menu
    from app.controllers.utils import inject_nav_menu
    app.context_processor(inject_nav_menu)
    
    return app 