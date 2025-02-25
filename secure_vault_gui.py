"""
SecureVault GUI
A secure file encryption application with integrated API server management.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import requests
import os
import json
import urllib3
from pathlib import Path
import base64
import platform
import sys
import subprocess
import signal
import time
import logging
from datetime import datetime, timezone
import atexit

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('securevault_gui.log')
    ]
)
logger = logging.getLogger('securevault_gui')


FALLBACK_RUN_API_SCRIPT = r'''
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
'''


import sys
import os
import subprocess
import platform
import time
import atexit
import logging
from pathlib import Path

class APIServerManager:
    """
    Manages the SecureVault API server process.
    Launches the same executable with the '--api-server' flag.
    """
    def __init__(self, host='localhost', port=5000):
            self.host = host
            self.port = port
            self.api_url = f"https://{host}:{port}/api"
            self.server_process = None
            self.logger = logging.getLogger('api_server_manager')

    def start_server(self) -> bool:
        if self.is_server_running():
            self.logger.info("API server already running")
            return True

        try:
            self.logger.info("Starting API server using '--api-server' flag")

            # The command calls main.py with the --api-server argument
            cmd = [sys.executable, "main.py", "--api-server"]

            env = os.environ.copy()
            env.update({
                'HOST': self.host,
                'PORT': str(self.port),
                'FLASK_ENV': 'development'
            })

            self.server_process = subprocess.Popen(cmd, env=env)
            atexit.register(self.stop_server)

            # Wait up to 10 seconds
            for _ in range(10):
                if self.is_server_running():
                    self.logger.info("API server started successfully")
                    return True
                time.sleep(1)

            self.logger.error("API server failed to start")
            self.stop_server()
            return False

        except Exception as e:
            self.logger.error(f"Failed to start API server: {e}")
            return False

    def _setup_logging(self):
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def is_server_running(self) -> bool:
        try:
            import requests
            response = requests.get(f"{self.api_url}/files", verify=False, timeout=2)
            # A 401 response indicates the server is up (authentication required)
            return response.status_code == 401
        except Exception:
            return False

    def stop_server(self):
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
                self.logger.info("API server stopped")
            except Exception as e:
                self.logger.error(f"Error stopping API server: {e}")
                self.server_process.kill()
            finally:
                self.server_process = None

class SecureVaultGUI:
    """Main GUI class for SecureVault"""
    def __init__(self):
        """Initialize the GUI"""
        # Create the main window first
        self.window = tk.Tk()
        self.window.withdraw()  # Hide main window initially
        
        # Create loading window as a Toplevel
        self.loading_window = self._create_loading_window()
        self.loading_window.update()
        
        # Initialize server first
        success = self.initialize_server()
        
        # Close loading window
        try:
            self.loading_window.destroy()
        except:
            pass  # Window might already be destroyed
        
        if not success:
            self.window.destroy()
            sys.exit(1)

        # Configure main window
        self.window.title("SecureVault")
        self.window.geometry("900x600")
        self.window.minsize(800, 500)
        
        # Disable SSL warnings for development
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # API configuration
        self.api_url = "https://localhost:5000/api"
        self.verify_ssl = False
        self.token = None
        
        # Initialize session
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.session.headers.update({
            'Origin': 'https://localhost:5000',
            'Referer': 'https://localhost:5000/',
            'User-Agent': 'SecureVaultGUI/1.0'
        })
        
        # Set up theme
        self.setup_theme()
        
        # Create UI elements
        self.create_widgets()
        
        # Center main window
        self.center_window(self.window)
        
        # Setup auto-refresh
        self._setup_auto_refresh()
        
        # Show the main window
        self.window.deiconify()
        
        # Check server and login
        self.check_server_connection()

    def initialize_server(self):
        """Initialize and check API server"""
        try:
            self.api_manager = APIServerManager()
            if not self.api_manager.is_server_running():
                if not self.api_manager.start_server():
                    messagebox.showerror(
                        "Error",
                        "Failed to start the API server.\nPlease check the logs for details."
                    )
                    return False
            return True
        except Exception as e:
            logger.error(f"Failed to initialize server: {e}")
            messagebox.showerror(
                "Error",
                f"Failed to initialize server: {str(e)}\nPlease check the logs for details."
            )
            return False

    def _create_loading_window(self):
        """Create and return loading window"""
        loading_window = tk.Toplevel(self.window)
        loading_window.title("Starting SecureVault")
        loading_window.geometry("300x100")
        loading_window.transient(self.window)
        loading_window.grab_set()
        
        self.center_window(loading_window)
        
        loading_label = ttk.Label(loading_window, text="Starting SecureVault...\nInitializing server...")
        loading_label.pack(pady=20)
        
        progress = ttk.Progressbar(loading_window, mode='indeterminate')
        progress.pack(fill='x', padx=20)
        progress.start()
        
        return loading_window

    def setup_theme(self):
        """Set up GUI theme and styles"""
        self.colors = {
            'primary': '#2c3e50',
            'secondary': '#34495e',
            'accent': '#3498db',
            'success': '#2ecc71',
            'warning': '#f1c40f',
            'error': '#e74c3c',
            'background': '#f5f6fa',
            'text': '#2c3e50'
        }

        style = ttk.Style()
        style.configure('TButton', padding=5, font=('Helvetica', 10))
        style.configure('Primary.TButton', background=self.colors['primary'])
        style.configure('Success.TButton', background=self.colors['success'])
        style.configure('Warning.TButton', background=self.colors['warning'])
        style.configure('TFrame', background=self.colors['background'])
        style.configure('TLabel', background=self.colors['background'], foreground=self.colors['text'])
        style.configure('TNotebook', background=self.colors['background'])
        style.configure('TNotebook.Tab', padding=[10, 5])

    def _setup_auto_refresh(self):
        """Set up automatic refresh of file list"""
        def auto_refresh():
            if hasattr(self, 'token') and self.token:
                self.refresh_file_list()
            self.window.after(30000, auto_refresh)
        
        self._auto_refresh_id = self.window.after(30000, auto_refresh)

    def center_window(self, window):
        """Center a window on the screen"""
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        window.geometry(f'{width}x{height}+{x}+{y}')

    def create_widgets(self):
        """Create all GUI widgets"""
        # Create main frame
        self.main_frame = ttk.Frame(self.window, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create tabbed interface
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.files_tab = ttk.Frame(self.notebook, padding="10")
        self.settings_tab = ttk.Frame(self.notebook, padding="10")
        self.logs_tab = ttk.Frame(self.notebook, padding="10")
        
        self.notebook.add(self.files_tab, text="Files")
        self.notebook.add(self.settings_tab, text="Settings")
        self.notebook.add(self.logs_tab, text="Logs")
        
        # Create login frame
        self.login_frame = ttk.Frame(self.window, padding="20")
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
        # Set up each tab
        self.setup_files_tab()
        self.setup_settings_tab()
        self.setup_logs_tab()
        self.setup_login_frame()
        
        # Initially hide main frame
        self.main_frame.pack_forget()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(
            self.window, 
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_files_tab(self):
        """Set up the files tab with file operations"""
        # Split into left (file list) and right (details) panes
        self.files_paned = ttk.PanedWindow(self.files_tab, orient=tk.HORIZONTAL)
        self.files_paned.pack(fill=tk.BOTH, expand=True)
        
        # Left panel (file list)
        left_frame = ttk.LabelFrame(self.files_paned, text="Encrypted Files", padding="5")
        self.files_paned.add(left_frame, weight=1)
        
        # File listbox with scrollbar
        self.file_listbox = tk.Listbox(
            left_frame, 
            width=40,
            activestyle='dotbox',
            selectmode=tk.SINGLE,
            bg=self.colors['background'],
            fg=self.colors['text']
        )
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.file_listbox.bind('<<ListboxSelect>>', self.on_file_select)
        
        scrollbar = ttk.Scrollbar(
            left_frame,
            orient=tk.VERTICAL,
            command=self.file_listbox.yview
        )
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_listbox.configure(yscrollcommand=scrollbar.set)
        
        # Right panel (file details and actions)
        right_frame = ttk.Frame(self.files_paned)
        self.files_paned.add(right_frame, weight=2)
        
        # Details section
        self.details_frame = ttk.LabelFrame(right_frame, text="File Details", padding="10")
        self.details_frame.pack(fill=tk.X, pady=5)
        
        # File details
        self.filename_var = tk.StringVar()
        self.size_var = tk.StringVar()
        self.modified_var = tk.StringVar()
        
        ttk.Label(self.details_frame, text="Filename:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Label(self.details_frame, textvariable=self.filename_var).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(self.details_frame, text="Size:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Label(self.details_frame, textvariable=self.size_var).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(self.details_frame, text="Modified:").grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Label(self.details_frame, textvariable=self.modified_var).grid(row=2, column=1, sticky=tk.W, pady=2)
        
        # Actions section
        actions_frame = ttk.LabelFrame(right_frame, text="Actions", padding="10")
        actions_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Encrypt section
        encrypt_frame = ttk.LabelFrame(actions_frame, text="Encrypt File", padding="10")
        encrypt_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            encrypt_frame,
            text="Select File to Encrypt",
            command=self.encrypt_file,
            style='Primary.TButton'
        ).pack(pady=5)
        
        # Decrypt section
        decrypt_frame = ttk.LabelFrame(actions_frame, text="Decrypt Selected File", padding="10")
        decrypt_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            decrypt_frame,
            text="Decrypt File",
            command=self.decrypt_file,
            style='Success.TButton'
        ).pack(pady=5)
        
        # Delete section
        delete_frame = ttk.LabelFrame(actions_frame, text="Delete Selected File", padding="10")
        delete_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            delete_frame,
            text="Delete File",
            command=self.delete_file,
            style='Warning.TButton'
        ).pack(pady=5)
        
        # Refresh button
        ttk.Button(
            actions_frame,
            text="Refresh File List",
            command=self.refresh_file_list
        ).pack(pady=20)

    def setup_settings_tab(self):
        """Set up the settings tab"""
        # Server settings
        server_frame = ttk.LabelFrame(self.settings_tab, text="Server Settings", padding="10")
        server_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(server_frame, text="API URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.server_url_var = tk.StringVar(value=self.api_url)
        ttk.Entry(
            server_frame,
            textvariable=self.server_url_var,
            width=40
        ).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # SSL verification
        self.verify_ssl_var = tk.BooleanVar(value=self.verify_ssl)
        ttk.Checkbutton(
            server_frame,
            text="Verify SSL Certificate",
            variable=self.verify_ssl_var,
            command=self.update_ssl_settings
        ).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Button(
            server_frame,
            text="Test Connection",
            command=self.check_server_connection
        ).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Security settings
        security_frame = ttk.LabelFrame(self.settings_tab, text="Security Settings", padding="10")
        security_frame.pack(fill=tk.X, pady=10)
        
        # Auto-logout timer
        ttk.Label(security_frame, text="Auto-logout after inactivity (minutes):").grid(
            row=0, column=0, sticky=tk.W, pady=5
        )
        self.auto_logout_var = tk.IntVar(value=30)
        ttk.Spinbox(
            security_frame,
            from_=5,
            to=120,
            textvariable=self.auto_logout_var,
            width=5
        ).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Remember credentials
        self.remember_creds_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            security_frame,
            text="Remember username",
            variable=self.remember_creds_var
        ).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Save settings button
        ttk.Button(
            self.settings_tab,
            text="Save Settings",
            command=self.save_settings,
            style='Primary.TButton'
        ).pack(pady=20)

    def setup_logs_tab(self):
        """Set up the logs tab"""
        # Log viewer
        self.log_text = scrolledtext.ScrolledText(
            self.logs_tab,
            height=25,
            bg=self.colors['background'],
            fg=self.colors['text']
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)
        self.log_text.config(state=tk.DISABLED)
        
        # Controls frame
        controls_frame = ttk.Frame(self.logs_tab)
        controls_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            controls_frame,
            text="Refresh Logs",
            command=self.refresh_logs
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            controls_frame,
            text="Clear Logs",
            command=self.clear_logs
        ).pack(side=tk.LEFT, padx=5)
        
        # Include server logs checkbox
        self.include_server_logs_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            controls_frame,
            text="Include server logs",
            variable=self.include_server_logs_var
        ).pack(side=tk.RIGHT, padx=5)

    def setup_login_frame(self):
        """Set up the login frame"""
        # Title
        title_label = ttk.Label(
            self.login_frame,
            text="SecureVault Login",
            font=("Arial", 16, "bold")
        )
        title_label.pack(pady=20)
        
        # Login form
        login_form = ttk.Frame(self.login_frame)
        login_form.pack(pady=20)
        
        ttk.Label(login_form, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=10)
        self.username_var = tk.StringVar()
        ttk.Entry(
            login_form,
            textvariable=self.username_var,
            width=30
        ).grid(row=0, column=1, sticky=tk.W, pady=10)
        
        ttk.Label(login_form, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.password_var = tk.StringVar()
        ttk.Entry(
            login_form,
            textvariable=self.password_var,
            show="*",
            width=30
        ).grid(row=1, column=1, sticky=tk.W, pady=10)
        
        # Login button
        ttk.Button(
            self.login_frame,
            text="Login",
            command=self.login,
            style='Primary.TButton'
        ).pack(pady=20)
        
        # Status message
        self.login_status_var = tk.StringVar()
        ttk.Label(
            self.login_frame,
            textvariable=self.login_status_var,
            foreground=self.colors['error']
        ).pack(pady=10)

    def check_server_connection(self):
        """Check if the server is reachable and HTTPS is working"""
        self.log_message("Checking server connection...")
        self.status_var.set("Checking server connection...")
        
        def check_connection():
            # Define update functions in the outer scope
            def update_gui(message, level="INFO", show_error=False):
                if not hasattr(self, 'window') or not self.window.winfo_exists():
                    return
                try:
                    self.log_message(message, level)
                    if level in ["ERROR", "WARNING"]:
                        self.status_var.set(message)
                    if show_error:
                        messagebox.showerror("Connection Error", message)
                except Exception as e:
                    logger.error(f"Error updating GUI: {e}")

            try:
                response = self.session.get(f"{self.api_url}/files", timeout=5)
                
                if response.status_code == 200:
                    msg = f"Server connection successful: {response.status_code}"
                    self.window.after(0, lambda: update_gui(msg,"INFO"))
                    return True
                else:
                    msg = f"Unexpected response: {response.status_code}"
                    self.window.after(0, lambda: update_gui(msg, "WARNING"))
                    return True
                    
            except requests.exceptions.SSLError:
                msg = "SSL certificate verification failed. Using self-signed certificate?"
                self.window.after(0, lambda: update_gui(msg, "WARNING"))
                return True
                
            except requests.exceptions.ConnectionError:
                msg = f"Cannot connect to server at {self.api_url}.\nIs the server running?"
                self.window.after(0, lambda: update_gui(msg, "ERROR", True))
                return False
                
            except Exception as e:
                msg = f"Connection error: {str(e)}"
                self.window.after(0, lambda: update_gui(msg, "ERROR", True))
                return False
        
        # Run in thread
        threading.Thread(target=check_connection, daemon=True).start()

    def login(self):
        """Login to the API server"""
        username = self.username_var.get()
        password = self.password_var.get()
        
        if not username or not password:
            self.login_status_var.set("Username and password are required")
            return
        
        self.status_var.set("Logging in...")
        self.login_status_var.set("Authenticating...")
        
        def perform_login():
            try:
                response = self.session.post(
                    f"{self.api_url}/auth",
                    auth=(username, password)
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self.token = data.get('token')
                    if self.token:
                        self.session.headers.update({"Authorization": f"Bearer {self.token}"})
                        self.log_message(f"User {username} logged in successfully", "INFO")
                        
                        # Switch to main interface
                        self.window.after(0, self.show_main_interface)
                    else:
                        self.login_status_var.set("Invalid response from server")
                        self.log_message("Login failed: Invalid response from server", "ERROR")
                else:
                    self.login_status_var.set(f"Login failed: {response.status_code}")
                    self.log_message(f"Login failed: {response.status_code} - {response.text}", "ERROR")
                    
            except Exception as e:
                self.login_status_var.set(f"Login error: {str(e)}")
                self.log_message(f"Login error: {str(e)}", "ERROR")
        
        # Run in thread to avoid freezing UI
        threading.Thread(target=perform_login).start()

    def show_main_interface(self):
        """Show the main interface after successful login"""
        self.login_frame.pack_forget()
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.status_var.set("Logged in successfully")
        
        # Load initial data
        self.refresh_file_list()

    def refresh_file_list(self):
        """Get list of files from the server"""
        self.status_var.set("Refreshing file list...")
        self.file_listbox.delete(0, tk.END)
        
        def fetch_files():
            try:
                response = self.session.get(f"{self.api_url}/files")
                
                if response.status_code == 200:
                    files = response.json()
                    
                    # Update UI in main thread
                    def update_ui():
                        if not files:
                            self.file_listbox.insert(tk.END, "(No files found)")
                            self.status_var.set("No files found in vault")
                        else:
                            for file in files:
                                self.file_listbox.insert(tk.END, file['name'])
                            self.status_var.set(f"Found {len(files)} files")
                            
                    self.window.after(0, update_ui)
                    self.log_message(f"Retrieved {len(files)} files from server", "INFO")
                    
                elif response.status_code == 401:
                    self.log_message("Session expired. Please login again", "WARNING")
                    self.status_var.set("Authentication required")
                    self.window.after(0, self.logout)
                    
                else:
                    self.log_message(f"Failed to get files: {response.status_code} - {response.text}", "ERROR")
                    self.status_var.set("Failed to get file list")
                    
            except Exception as e:
                self.log_message(f"Error retrieving files: {str(e)}", "ERROR")
                self.status_var.set("Error retrieving files")
        
        # Run in thread to avoid freezing UI
        threading.Thread(target=fetch_files).start()

    def on_file_select(self, event):
        """Handle file selection from listbox"""
        selection = self.file_listbox.curselection()
        if not selection:
            return
            
        file_name = self.file_listbox.get(selection[0])
        if file_name == "(No files found)":
            return
            
        # Find file details from API
        def fetch_file_details():
            try:
                response = self.session.get(f"{self.api_url}/files")
                
                if response.status_code == 200:
                    files = response.json()
                    selected_file = next((f for f in files if f['name'] == file_name), None)
                    
                    if selected_file:
                        # Update UI in main thread
                        def update_details():
                            self.filename_var.set(selected_file['name'])
                            
                            # Format size
                            size_bytes = selected_file['size']
                            if size_bytes < 1024:
                                size_str = f"{size_bytes} bytes"
                            elif size_bytes < 1024 * 1024:
                                size_str = f"{size_bytes/1024:.1f} KB"
                            else:
                                size_str = f"{size_bytes/(1024*1024):.1f} MB"
                            self.size_var.set(size_str)
                            
                            # Format date
                            try:
                                modified = datetime.fromisoformat(selected_file['modified'])
                                modified_str = modified.strftime("%Y-%m-%d %H:%M:%S")
                            except:
                                modified_str = selected_file['modified']
                            self.modified_var.set(modified_str)
                            
                        self.window.after(0, update_details)
                
            except Exception as e:
                self.log_message(f"Error retrieving file details: {str(e)}", "ERROR")
        
        # Run in thread
        threading.Thread(target=fetch_file_details).start()

    def encrypt_file(self):
        """Select and encrypt a file"""
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if not file_path:
            return
            
        # Get password
        password = self.password_dialog("Enter encryption password")
        if not password:
            return
            
        self.status_var.set("Encrypting file...")
        file_name = os.path.basename(file_path)
        
        def perform_encryption():
            try:
                with open(file_path, 'rb') as f:
                    files = {'file': (file_name, f)}
                    data = {'password': password}
                    
                    response = self.session.post(
                        f"{self.api_url}/files",
                        files=files,
                        data=data
                    )
                    
                if response.status_code == 200:
                    result = response.json()
                    
                    # Update UI in main thread
                    def update_after_encrypt():
                        self.refresh_file_list()
                        messagebox.showinfo("Success", f"File encrypted successfully: {result.get('file', '')}")
                        self.status_var.set("File encrypted successfully")
                        self.log_message(f"Encrypted file: {file_name}", "INFO")
                        
                    self.window.after(0, update_after_encrypt)
                    
                else:
                    error_msg = f"Encryption failed: {response.status_code}"
                    self.log_message(f"{error_msg} - {response.text}", "ERROR")
                    self.window.after(0, lambda: messagebox.showerror("Error", error_msg))
                    self.status_var.set("Encryption failed")
                    
            except Exception as e:
                error_msg = f"Encryption error: {str(e)}"
                self.log_message(error_msg, "ERROR")
                self.window.after(0, lambda: messagebox.showerror("Error", error_msg))
                self.status_var.set("Encryption error")
        
        # Run in thread
        threading.Thread(target=perform_encryption).start()

    def decrypt_file(self):
        """Decrypt the selected file"""
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file to decrypt")
            return
            
        file_name = self.file_listbox.get(selection[0])
        if file_name == "(No files found)":
            return
            
        # Get password
        password = self.password_dialog("Enter decryption password")
        if not password:
            return
            
        # Get save location
        output_path = filedialog.asksaveasfilename(
            title="Save Decrypted File",
            initialfile=file_name.replace('.vault', '')
        )
        if not output_path:
            return
            
        self.status_var.set("Decrypting file...")
        
        def perform_decryption():
            try:
                response = self.session.post(
                    f"{self.api_url}/files/{file_name}",
                    data={'password': password},
                    stream=True
                )
                
                if response.status_code == 200:
                    # Save the decrypted content
                    with open(output_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    
                    # Update UI in main thread
                    def update_after_decrypt():
                        messagebox.showinfo("Success", "File decrypted successfully!")
                        self.status_var.set("File decrypted successfully")
                        self.log_message(f"Decrypted file: {file_name}", "INFO")
                        
                    self.window.after(0, update_after_decrypt)
                    
                else:
                    error_msg = f"Decryption failed: {response.status_code}"
                    self.log_message(f"{error_msg} - {response.text}", "ERROR")
                    self.window.after(0, lambda: messagebox.showerror("Error", error_msg))
                    self.status_var.set("Decryption failed")
                    
            except Exception as e:
                error_msg = f"Decryption error: {str(e)}"
                self.log_message(error_msg, "ERROR")
                self.window.after(0, lambda: messagebox.showerror("Error", error_msg))
                self.status_var.set("Decryption error")
        
        # Run in thread
        threading.Thread(target=perform_decryption).start()

    def delete_file(self):
        """Delete the selected file"""
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file to delete")
            return
            
        file_name = self.file_listbox.get(selection[0])
        if file_name == "(No files found)":
            return
            
        # Confirm deletion
        if not messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete {file_name}?\nThis cannot be undone."
        ):
            return
            
        self.status_var.set("Deleting file...")
        
        def perform_deletion():
            try:
                response = self.session.delete(f"{self.api_url}/files/{file_name}")
                
                if response.status_code == 200:
                    # Update UI in main thread
                    def update_after_delete():
                        self.refresh_file_list()
                        messagebox.showinfo("Success", "File deleted successfully!")
                        self.status_var.set("File deleted successfully")
                        self.log_message(f"Deleted file: {file_name}", "INFO")
                        
                    self.window.after(0, update_after_delete)
                    
                else:
                    error_msg = f"Deletion failed: {response.status_code}"
                    self.log_message(f"{error_msg} - {response.text}", "ERROR")
                    self.window.after(0, lambda: messagebox.showerror("Error", error_msg))
                    self.status_var.set("Deletion failed")
                    
            except Exception as e:
                error_msg = f"Deletion error: {str(e)}"
                self.log_message(error_msg, "ERROR")
                self.window.after(0, lambda: messagebox.showerror("Error", error_msg))
                self.status_var.set("Deletion error")
        
        # Run in thread
        threading.Thread(target=perform_deletion).start()

    def update_ssl_settings(self):
        """Update SSL verification settings"""
        self.verify_ssl = self.verify_ssl_var.get()
        self.session.verify = self.verify_ssl
        
        if self.verify_ssl:
            self.log_message("SSL certificate verification enabled", "INFO")
        else:
            self.log_message("SSL certificate verification disabled", "WARNING")

    def save_settings(self):
        """Save settings"""
        # Update API URL
        new_url = self.server_url_var.get()
        if new_url != self.api_url:
            self.api_url = new_url
            self.log_message(f"API URL changed to: {self.api_url}", "INFO")
        
        # Update SSL verification
        self.update_ssl_settings()
        
        # Save other settings as needed
        messagebox.showinfo("Settings", "Settings saved successfully!")

    def log_message(self, message: str, level: str = "INFO"):
        """Add a message to the log with timestamp"""
        if not hasattr(self, 'log_text') or not self.window.winfo_exists():
            logger.log(getattr(logging, level), message)
            return
            
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] [{level}] {message}\n"
            
            # Add to log text widget
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, log_entry)
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
            
            # Update status bar for important messages
            if level in ["ERROR", "WARNING"]:
                self.status_var.set(message)
                
        except Exception as e:
            logger.error(f"Failed to log message to GUI: {e}")
            logger.log(getattr(logging, level), message)

    def refresh_logs(self):
        """Refresh logs from server"""
        self.log_message("Logs refreshed", "INFO")
        # In a full implementation, this would fetch logs from the server API

    def clear_logs(self):
        """Clear the log display"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.log_message("Logs cleared", "INFO")

    def logout(self):
        """Log out and revoke token"""
        if not self.token:
            self.show_login_screen()
            return
            
        def perform_logout():
            try:
                response = self.session.post(f"{self.api_url}/auth/revoke")
                
                # Clear token regardless of response
                self.token = None
                self.session.headers.pop('Authorization', None)
                
                # Log result
                if response.status_code == 200:
                    self.log_message("Logged out successfully", "INFO")
                else:
                    self.log_message(f"Logout issue: {response.status_code} - {response.text}", "WARNING")
                
            except Exception as e:
                self.log_message(f"Logout error: {e}", "ERROR")
            finally:
                # Switch to login screen
                self.window.after(0, self.show_login_screen)
        
        # Run in thread
        threading.Thread(target=perform_logout).start()

    def show_login_screen(self):
        """Show the login screen"""
        self.main_frame.pack_forget()
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        self.password_var.set("")  # Clear password
        self.login_status_var.set("")
        self.status_var.set("Please login")

    def password_dialog(self, prompt: str) -> str:
        """Show password dialog and return the entered password"""
        dialog = tk.Toplevel(self.window)
        dialog.title(prompt)
        dialog.geometry("300x150")
        dialog.transient(self.window)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        self.center_window(dialog)
        
        ttk.Label(dialog, text=prompt).pack(pady=10)
        
        # Password entry
        password_var = tk.StringVar()
        password_entry = ttk.Entry(dialog, show="*", textvariable=password_var, width=30)
        password_entry.pack(pady=10)
        password_entry.focus()
        
        result = [None]  # Use list to store result
        
        def on_ok():
            result[0] = password_var.get()
            dialog.destroy()
            
        def on_cancel():
            dialog.destroy()
        
        # Button frame
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, pady=10)   
        ttk.Button(button_frame, text="OK", command=on_ok, style='Primary.TButton').pack(side=tk.LEFT, padx=20)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=20)
        
        # Bind Enter key to OK button
        dialog.bind('<Return>', lambda event: on_ok())
        dialog.bind('<Escape>', lambda event: on_cancel())
        
        # Wait for dialog to close
        dialog.wait_window()
        return result[0]

    def create_menu(self):
        """Create application menu"""
        menubar = tk.Menu(self.window)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Encrypt File", command=self.encrypt_file)
        file_menu.add_command(label="Refresh Files", command=self.refresh_file_list)
        file_menu.add_separator()
        file_menu.add_command(label="Logout", command=self.logout)
        file_menu.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Check for Updates", command=self.check_updates)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.window.config(menu=menubar)

    def show_about(self):
        """Show about dialog"""
        about_text = """
        SecureVault GUI
        Version 1.0
        
        A secure file encryption application using
        AES-256-GCM authenticated encryption and
        HTTPS for secure communication.
        
        © 2025 SecureVault
        """
        messagebox.showinfo("About SecureVault", about_text)

    def check_updates(self):
        """Check for application updates"""
        self.log_message("Checking for updates...", "INFO")
        self.status_var.set("Checking for updates...")
        
        # Simulated update check
        self.window.after(1500, lambda: self.status_var.set("No updates available"))
        self.window.after(1500, lambda: messagebox.showinfo("Updates", 
            "You are using the latest version."))

    def run(self):
        """Run the application"""
        try:
            self.create_menu()
            self.window.protocol("WM_DELETE_WINDOW", self.on_close)
            self.window.mainloop()
        except Exception as e:
            logger.error(f"Error running application: {e}")
            try:
                self.window.destroy()
            except:
                pass

    def on_close(self):
        """Handle window close event"""
        try:
            if messagebox.askyesno("Confirm Exit", "Are you sure you want to exit?"):
                # Stop auto-refresh
                if hasattr(self, '_auto_refresh_id'):
                    self.window.after_cancel(self._auto_refresh_id)

                # Stop any running operations
                if self.token:
                    try:
                        self.session.post(f"{self.api_url}/auth/revoke")
                    except:
                        pass  # Ignore errors during shutdown

                # Stop API server
                if hasattr(self, 'api_manager'):
                    self.api_manager.stop_server()

                # Clean up and destroy window
                self.window.quit()
                self.window.destroy()
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            self.window.destroy()

def main():
    """Main entry point"""
    try:
        app = SecureVaultGUI()
        app.run()
    except Exception as e:
        logger.error("Fatal error:", exc_info=True)
        messagebox.showerror(
            "Error",
            f"Fatal error: {str(e)}\nPlease check the logs for details."
        )
        sys.exit(1)

if __name__ == "__main__":
    main()