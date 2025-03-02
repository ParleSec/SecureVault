"""
SecureVault API Server
Run this script to start the secure API server.
"""

import os
import sys
from pathlib import Path
from secure_vault.core.vault import SecureVault
from secure_vault.web.secure_api import SecureAPI
import logging
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('securevault_api')

def main():
    # Process command-line arguments
    parser = argparse.ArgumentParser(description='Start the SecureVault API server')
    
    # Add the --api-server flag to make it compatible with main.py calls
    parser.add_argument('--api-server', action='store_true', help='Flag to indicate API server mode')
    
    # Add other configuration arguments
    parser.add_argument('--vault-dir', help='Path to the vault directory')
    parser.add_argument('--host', help='Host address to bind the server to')
    parser.add_argument('--port', type=int, help='Port to bind the server to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--user-db', help='Path to the user database')
    parser.add_argument('--master-password', help='Master password for vault encryption')
    
    # Parse known args to handle unknown args gracefully (in case other flags are added in the future)
    args, _ = parser.parse_known_args()
    
    # Configure vault directory
    vault_dir = args.vault_dir or os.getenv('VAULT_DIR', './encrypted_vault')
    
    # Get master password from args or environment
    master_password = args.master_password or os.getenv('VAULT_MASTER_PASSWORD')
    
    # Initialize the secure vault
    vault = SecureVault(vault_dir, master_password)
    
    # Get user database path
    user_db_path = args.user_db or os.getenv('USER_DB_PATH', './secure_vault_data/users/users.db')
    
    # Create and run the secure API
    api = SecureAPI(vault, user_db_path)
    
    # Configure server
    host = args.host or os.getenv('HOST', 'localhost')
    port = args.port or int(os.getenv('PORT', 5000))
    debug = args.debug or os.getenv('DEBUG', 'False').lower() == 'true'
    
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