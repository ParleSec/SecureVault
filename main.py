# main.py
import sys
import logging

# Import your GUI and API server code
from secure_vault_gui import SecureVaultGUI
from secure_vault.web.run_api import main as run_api_main

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
