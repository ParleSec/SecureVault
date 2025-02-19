"""
WSGI application entry point for SecureVault with HTTPS support
"""
import os
import logging
from pathlib import Path
from secure_vault import create_app
from secure_vault.web.https_config import ensure_valid_cert_exists, create_ssl_context
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('securevault.log')
    ]
)
logger = logging.getLogger('securevault')

# Load environment variables
load_dotenv()

def get_ssl_config():
    """Get SSL configuration from environment or generate self-signed cert"""
    ssl_cert = os.getenv('SSL_CERT_PATH')
    ssl_key = os.getenv('SSL_KEY_PATH')
    
    if ssl_cert and ssl_key and os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        logger.info(f"Using provided SSL certificate: {ssl_cert}")
        return ssl_cert, ssl_key
    else:
        logger.info("Generating self-signed SSL certificate")
        return ensure_valid_cert_exists()

# Create the Flask application
app = create_app()

if __name__ == "__main__":
    # Get configuration
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    
    # Get SSL configuration
    cert_path, key_path = get_ssl_config()
    
    # Set up SSL context
    try:
        ssl_context = create_ssl_context(cert_path, key_path)
        logger.info(f"HTTPS enabled with certificate: {cert_path}")
        
        # Run the application with HTTPS
        app.run(
            host=host,
            port=port,
            ssl_context=ssl_context,
            debug=debug
        )
    except Exception as e:
        logger.error(f"Failed to configure HTTPS: {e}")
        logger.warning("Falling back to HTTP (not secure for production)")
        app.run(host=host, port=port, debug=debug)