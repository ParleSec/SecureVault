"""
SecureVault API Server
Run this script to start the secure API server.
"""

import os
from pathlib import Path
from secure_vault.core.vault import SecureVault
from secure_vault.web.secure_api import SecureAPI
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('securevault_api')

def main():
    # Configure vault directory
    vault_dir = os.getenv('VAULT_DIR', './encrypted_vault')
    
    # Initialize the secure vault
    vault = SecureVault(vault_dir)
    
    # Create and run the secure API
    api = SecureAPI(vault)
    
    # Configure server
    host = os.getenv('HOST', 'localhost')
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    
    # Start server with HTTPS
    try:
        logger.info(f"Starting API server on {host}:{port}")
        api.run(
            host=host,
            port=port,
            ssl_context='adhoc',  # Use auto-generated cert for development
            debug=debug
        )
    except Exception as e:
        logger.error(f"Failed to start API server: {e}")
        raise

if __name__ == '__main__':
    main()