
"""
Configuration settings for PhishGuard
"""

import os

class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-in-production'

    # Database settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///phishing.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # MySQL configuration (uncomment for production)
    # SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://username:password@localhost/phishing_db'

    # Email settings (for sending real notifications - optional)
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

    # ML Model settings
    MODEL_PATH = 'models/phishing_model.pkl'
    CONFIDENCE_THRESHOLD = 0.7

    # Simulation settings
    SIMULATION_ENABLED = True
    MAX_CAMPAIGNS_PER_MONTH = 10

    # Security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

    # Feature extraction settings
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.work', '.date']
    URGENT_KEYWORDS = [
        'urgent', 'immediate', 'action required', 'verify now', 'suspend', 
        'limited time', 'act now', 'warning', 'alert', 'critical'
    ]
    SUSPICIOUS_KEYWORDS = [
        'password', 'credit card', 'ssn', 'bank account', 'login', 
        'verify', 'confirm', 'update', 'validate', 'authenticate'
    ]
    POPULAR_DOMAINS = [
        'google', 'microsoft', 'apple', 'amazon', 'paypal', 'facebook', 
        'twitter', 'linkedin', 'instagram', 'netflix', 'spotify'
    ]
