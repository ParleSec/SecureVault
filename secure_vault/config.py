"""
Configuration settings for SecureVault
"""
import os
import secrets
from datetime import timedelta
from pathlib import Path

class Config:
    """Base configuration"""
    # Security settings
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # CSRF protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.getenv("WTF_CSRF_SECRET_KEY", secrets.token_hex(32))
    
    # Session security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    
    # File upload settings
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "./temp_uploads")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # Vault settings
    VAULT_DIR = os.getenv("VAULT_DIR", "./encrypted_vault")
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_DIR = os.getenv("LOG_DIR", "./logs")

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development
    
    # Development specific settings
    TEMPLATES_AUTO_RELOAD = True

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = False
    TESTING = True
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = False
    
    # Use in-memory SQLite for testing
    VAULT_DIR = os.getenv("TEST_VAULT_DIR", "./test_vault")
    
class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Ensure these are set in production
    @classmethod
    def init_app(cls, app):
        assert os.getenv("SECRET_KEY"), "SECRET_KEY must be set in production"
        assert os.getenv("JWT_SECRET_KEY"), "JWT_SECRET_KEY must be set in production"
        
        # Configure production specific settings
        import logging
        from logging.handlers import RotatingFileHandler
        
        # Ensure log directory exists
        os.makedirs(cls.LOG_DIR, exist_ok=True)
        
        # Configure file handler
        file_handler = RotatingFileHandler(
            os.path.join(cls.LOG_DIR, 'secure_vault.log'),
            maxBytes=10485760,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s '
            '[in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('SecureVault startup')

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}