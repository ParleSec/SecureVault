"""
SecureVault application package
"""
import os
from pathlib import Path
from flask import Flask
from dotenv import load_dotenv

# Import after defining config
from secure_vault.config import config

def create_app(config_name=None):
    """
    Application factory for SecureVault
    Creates and configures the Flask application
    """
    # Load environment variables
    load_dotenv()
    
    # Determine configuration to use
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "development")
    
    # Import here to avoid circular imports
    from secure_vault.core.vault import SecureVault
    from secure_vault.web.secure_api import SecureAPI
    
    # Initialize vault
    vault_dir = os.getenv('VAULT_DIR', './encrypted_vault')
    vault = SecureVault(vault_dir)
    
    # Create secure API with the Flask app
    secure_api = SecureAPI(vault)
    app = secure_api.app
    
    # Apply configuration
    app.config.from_object(config[config_name])
    
    # Register error handlers, blueprints, etc.
    register_error_handlers(app)
    
    return app

def register_error_handlers(app):
    """Register custom error handlers"""
    # Add your custom error handlers here
    pass