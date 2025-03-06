# main.py
import sys
import logging
import os
from pathlib import Path
from dotenv import load_dotenv

env_path = Path('.') / '.env'
load_result = load_dotenv(dotenv_path=env_path)
if load_result:
    logging.info(f"Loaded environment variables from {env_path}")
else:
    logging.warning(f"Could not load environment variables from {env_path}")

# Import your GUI and API server code
from secure_vault_gui import SecureVaultGUI
from secure_vault.web.run_api import main as run_api_main

def check_master_password():
    """Verify master password is properly set"""
    if not os.getenv('VAULT_MASTER_PASSWORD'):
        print("WARNING: VAULT_MASTER_PASSWORD environment variable not set!")
        print("You will need to provide a master password when using encryption functions.")
        print("For production use, set this environment variable securely.")

check_master_password()

def run_gui():
    """Start the SecureVault GUI."""
    gui_app = SecureVaultGUI()
    gui_app.run()

def run_api_server():
    """Start the API server from run_api.py."""
    logging.info("Running API server mode via main.py")
    run_api_main()

if __name__ == "__main__":
    if "--api-server" in sys.argv:
        run_api_server()
    else:
        run_gui()
