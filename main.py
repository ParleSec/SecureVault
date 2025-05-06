# main.py
import sys
import os
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('securevault.log')
    ]
)
logger = logging.getLogger('main')

def setup_environment():
    '''Set up environment for both GUI and API mode'''
    try:
        # Get application base directory
        if getattr(sys, 'frozen', False):
            # Running as PyInstaller bundle
            base_dir = Path(os.path.dirname(sys.executable))
        else:
            # Running as script
            base_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        
        logger.info(f"Application base directory: {base_dir}")
        
        # Create required directories
        for dirname in ['logs', 'certs', 'encrypted_vault', 'secure_vault_data/users', 'temp_uploads']:
            dir_path = base_dir / dirname
            os.makedirs(dir_path, exist_ok=True)
        
        # Set environment variables
        os.environ['VAULT_DIR'] = str(base_dir / 'encrypted_vault')
        os.environ['USER_DB_PATH'] = str(base_dir / 'secure_vault_data/users/users.db')
        os.environ['LOG_DIR'] = str(base_dir / 'logs')
        
        # Add application directory to path
        if str(base_dir) not in sys.path:
            sys.path.insert(0, str(base_dir))
        
        return True
    
    except Exception as e:
        logger.error(f"Environment setup failed: {e}")
        return False

def run_gui():
    '''Start the SecureVault GUI.'''
    try:
        from secure_vault_gui import SecureVaultGUI
        gui_app = SecureVaultGUI()
        gui_app.run()
    except Exception as e:
        logger.error(f"Failed to start GUI: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

def run_api_server():
    '''Start the API server from run_api.py.'''
    try:
        logger.info("Running API server mode")
        from secure_vault.web.run_api import main as run_api_main
        run_api_main()
    except Exception as e:
        logger.error(f"Failed to start API server: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    # Set up environment
    setup_environment()
    
    # Check if running in API server mode
    if "--api-server" in sys.argv or os.environ.get('SECUREVAULT_API_MODE') == 'true':
        run_api_server()
    else:
        run_gui()
