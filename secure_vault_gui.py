"""
SecureVault GUI
A secure file encryption application with integrated API server management.
"""

import sys
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
import subprocess
import signal
import time
import logging
from datetime import datetime, timezone
import secrets
import atexit
import http.cookiejar
from pathlib import Path
from dotenv import load_dotenv
sys.path.append(str(Path(__file__).parent))  # Add the current directory to Python path
from secure_vault.users.login_manager import LoginManager

# Load environment variables
env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

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
Secure API implementation with enhanced security measures.
Provides endpoints for authentication, file listing, encryption,
decryption, and deletion.
"""
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
    """Initialize the GUI"""
    def __init__(self):
        # Create the main window first
        self.window = tk.Tk()
        self.window.withdraw()  # Hide main window initially
        
        # Initialize login manager with user-writable location
        if sys.platform == 'win32':
            base_dir = Path(os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))) / "SecureVault"
        else:
            base_dir = Path(os.path.expanduser('~')) / ".securevault"
        
        # Create base directory
        base_dir.mkdir(parents=True, exist_ok=True)
        
        # Create data directories under user directory
        self.data_dir = base_dir / "secure_vault_data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        users_dir = self.data_dir / "users"
        users_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize login manager with user-writable database
        self.login_manager = LoginManager(str(users_dir / "users.db"))
        
        # For user session tracking
        self.username = None
        self.last_activity_time = time.time()
        self.session_timeout = 30 * 60  # 30 minutes in seconds
        
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
        
        self.session.cookies.set_policy(http.cookiejar.DefaultCookiePolicy(rfc2965=True))
        # Set up theme
        self.setup_theme()
        
        # Create UI elements
        self.create_widgets()
        
        # Center main window
        self.center_window(self.window)
        
        # Setup auto-refresh
        self._setup_auto_refresh()
        
        # Check server and login
        self.check_server_connection()

        # Setup session monitoring
        self._setup_session_monitoring()
        
        # Show the main window
        self.window.deiconify()
        
        # Show login dialog instead of the original login screen
        self.login_manager.show_login_dialog(self.window, self.on_login_success)

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
        
        # File listbox with scrollbar - CHANGED TO MULTIPLE SELECTION
        self.file_listbox = tk.Listbox(
            left_frame, 
            width=40,
            activestyle='dotbox',
            selectmode=tk.EXTENDED,  # Changed from SINGLE to EXTENDED
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
        
        # Add a label to indicate multiple selection
        selection_hint = ttk.Label(
            left_frame, 
            text="Ctrl+click or Shift+click to select multiple files",
            font=("Arial", 8),
            foreground="#666666"
        )
        selection_hint.pack(side=tk.BOTTOM, fill=tk.X, pady=(5, 0))
        
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
        
        # Selection info (NEW)
        self.selection_info_var = tk.StringVar()
        self.selection_info_label = ttk.Label(
            right_frame,
            textvariable=self.selection_info_var,
            font=("Arial", 9, "italic"),
            foreground="#666666"
        )
        self.selection_info_label.pack(fill=tk.X, pady=(0, 5))
        
        # Actions section
        actions_frame = ttk.LabelFrame(right_frame, text="Actions", padding="10")
        actions_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Encrypt section
        encrypt_frame = ttk.LabelFrame(actions_frame, text="Encrypt File", padding="10")
        encrypt_frame.pack(fill=tk.X, pady=10)
        
        self.encrypt_button = ttk.Button(
            encrypt_frame,
            text="Select File to Encrypt",
            command=self.encrypt_file,
            style='Primary.TButton'
        )
        self.encrypt_button.pack(pady=5)
        
        # Decrypt section
        decrypt_frame = ttk.LabelFrame(actions_frame, text="Decrypt Selected File", padding="10")
        decrypt_frame.pack(fill=tk.X, pady=10)
        
        self.decrypt_button = ttk.Button(
            decrypt_frame,
            text="Decrypt File",
            command=self.decrypt_file,
            style='Success.TButton'
        )
        self.decrypt_button.pack(pady=5)
        
        # Delete section
        delete_frame = ttk.LabelFrame(actions_frame, text="Delete Selected File(s)", padding="10")  # Updated label
        delete_frame.pack(fill=tk.X, pady=10)
        
        self.delete_button = ttk.Button(
            delete_frame,
            text="Delete File(s)",  # Updated label
            command=self.delete_file,
            style='Warning.TButton'
        )
        self.delete_button.pack(pady=5)
        
        # Refresh button
        self.refresh_button = ttk.Button(
            actions_frame,
            text="Refresh File List",
            command=self.refresh_file_list
        )
        self.refresh_button.pack(pady=20)

    def setup_settings_tab(self):
        """Set up the settings tab"""
        # Server settings
        server_frame = ttk.LabelFrame(self.settings_tab, text="Server Settings", padding="10")
        server_frame.pack(fill=tk.X, pady=10)
        
        # Use a grid layout for server settings
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
        
        # Use a consistent geometry manager - grid layout for security settings
        security_grid = ttk.Frame(security_frame)
        security_grid.pack(fill=tk.X, expand=True)
        
        # Auto-logout timer
        ttk.Label(security_grid, text="Auto-logout after inactivity (minutes):").grid(
            row=0, column=0, sticky=tk.W, pady=5
        )
        self.auto_logout_var = tk.IntVar(value=30)
        ttk.Spinbox(
            security_grid,
            from_=5,
            to=120,
            textvariable=self.auto_logout_var,
            width=5
        ).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Remember credentials
        self.remember_creds_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            security_grid,
            text="Remember username",
            variable=self.remember_creds_var
        ).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # User settings - only show when logged in
        if hasattr(self, 'username') and self.username:
            user_frame = ttk.LabelFrame(security_frame, text="User Account", padding="10")
            user_frame.pack(fill=tk.X, pady=10)
            
            # Use pack for the user account section
            ttk.Label(user_frame, text=f"Logged in as: {self.username}").pack(anchor=tk.W, pady=5)
            
            ttk.Button(
                user_frame,
                text="Change Password",
                command=self.show_change_password_dialog
            ).pack(pady=5)
        
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
        """Set up the login frame (used as a fallback only)"""
        # Title
        title_label = ttk.Label(
            self.login_frame,
            text="SecureVault Login",
            font=("Arial", 16, "bold")
        )
        title_label.pack(pady=20)
        
        # Message about using the custom login dialog
        message_label = ttk.Label(
            self.login_frame,
            text="Please use the secure login dialog.\nIf it doesn't appear, click the button below.",
            justify=tk.CENTER
        )
        message_label.pack(pady=20)
        
        # Button to show login dialog
        ttk.Button(
            self.login_frame,
            text="Show Login Dialog",
            command=lambda: self.login_manager.show_login_dialog(self.window, self.on_login_success),
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
            def update_gui_status(message, level="INFO", show_error=False):
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
                    self.window.after(0, lambda: update_gui_status(msg, "INFO"))
                    return True
                else:
                    msg = f"Unexpected response: {response.status_code}"
                    self.window.after(0, lambda: update_gui_status(msg, "WARNING"))
                    return True
                    
            except requests.exceptions.SSLError:
                msg = "SSL certificate verification failed. Using self-signed certificate?"
                self.window.after(0, lambda: update_gui_status(msg, "WARNING"))
                return True
                    
            except requests.exceptions.ConnectionError:
                msg = f"Cannot connect to server at {self.api_url}.\nIs the server running?"
                self.window.after(0, lambda: update_gui_status(msg, "ERROR", True))
                return False
                    
            except Exception as e:
                msg = f"Connection error: {str(e)}"
                self.window.after(0, lambda: update_gui_status(msg, "ERROR", True))
                return False
        
        # Run in thread
        threading.Thread(target=check_connection, daemon=True).start()

    def _setup_session_monitoring(self):
        """Monitor user session and implement timeout"""
        def check_session():
            if self.token:  # Only check if logged in
                if time.time() - self.last_activity_time > self.session_timeout:
                    self.log_message("Session timeout - logging out", "INFO")
                    self.window.after(0, self.logout)
            self.window.after(60000, check_session)  # Check every minute
        
        self.window.after(60000, check_session)

    def _update_activity_time(self):
        """Update the last activity timestamp"""
        self.last_activity_time = time.time()
        # Also refresh the login manager session
        if hasattr(self, 'login_manager'):
            self.login_manager.refresh_session()

    def on_login_success(self, user_info):
        """Handle successful login."""
        self.username = user_info["username"]
        self.log_message(f"User {self.username} authenticated locally", "INFO")
        
        # Store the password for possible later use
        self.password = user_info.get("password")
        
        # Update last activity time
        self._update_activity_time()
        
        # After local authentication, get token from API server using the actual password
        if self.password:
            self.login_with_api(self.password)
        else:
            self.log_message("No password available for API authentication", "ERROR")
            self.login_status_var.set("Authentication error: No password available")
            self.login_manager.show_login_dialog(self.window, self.on_login_success)

    def diagnose_crypto_system(self):
        """Diagnostic function to verify crypto system health"""
        self.log_message("Running crypto system diagnostics...", "INFO")
        
        # Test if API server is running
        if not self.api_manager.is_server_running():
            self.log_message("API server is not running - crypto operations will fail", "ERROR")
            return False
        
    def on_login_success(self, user_info):
        """Handle successful login."""
        self.username = user_info["username"]
        self.log_message(f"User {self.username} authenticated locally", "INFO")
        
        # Store the password for possible later use
        self.password = user_info.get("password")
        
        # Update last activity time
        self._update_activity_time()
        
        # After local authentication, get token from API server using the actual password
        if self.password:
            self.login_with_api(self.password)
            
            # ADDED: Run crypto diagnostic after successful login
            self.window.after(3000, self.diagnose_crypto_system)  # Run diagnostic after 3 seconds
        else:
            self.log_message("No password available for API authentication", "ERROR")
            self.login_status_var.set("Authentication error: No password available")
            self.login_manager.show_login_dialog(self.window, self.on_login_success)
        
        # Check if crypto keys are consistent
        try:
            # Create a small test file
            test_data = b"SecureVault Test Data"
            test_file = Path("./svtest_temp.bin")
            with open(test_file, "wb") as f:
                f.write(test_data)
            
            # Test password 
            test_password = "testpassword123"
            
            # Try to encrypt and then decrypt the test file
            self.log_message("Testing encryption/decryption cycle...", "INFO")
            
            # Make encryption request
            with open(test_file, 'rb') as f:
                files = {'file': ("svtest_temp.bin", f)}
                data = {'password': test_password}
                
                response = self.session.post(
                    f"{self.api_url}/files",
                    files=files,
                    data=data
                )
            
            if response.status_code != 200:
                self.log_message(f"Encryption test failed: {response.status_code}", "ERROR")
                os.unlink(test_file)
                return False
            
            encrypted_filename = response.json().get('file')
            self.log_message(f"Test file encrypted as: {encrypted_filename}", "INFO")
            
            # Try to decrypt it
            decryption_response = self.session.post(
                f"{self.api_url}/files/{encrypted_filename}",
                data={'password': test_password}
            )
            
            if decryption_response.status_code != 200:
                self.log_message("Decryption test failed - crypto system is broken", "ERROR")
                os.unlink(test_file)
                return False
            
            # Verify decrypted content
            decrypted_data = decryption_response.content
            if decrypted_data == test_data:
                self.log_message("Crypto system functioning correctly!", "INFO")
                result = True
            else:
                self.log_message(f"Decryption produced incorrect data: expected {test_data}, got {decrypted_data[:20]}...", "ERROR")
                result = False
            
            # Clean up
            os.unlink(test_file)
            self.session.delete(f"{self.api_url}/files/{encrypted_filename}")
            
            return result
            
        except Exception as e:
            self.log_message(f"Crypto diagnostic failed: {e}", "ERROR")
            # Try to clean up
            if test_file.exists():
                os.unlink(test_file)
            return False

    def get_csrf_token(self):
        """Get CSRF token from session cookies with enhanced debugging"""
        all_cookies = [f"{c.name}: {c.value[:10]}..." if len(c.value) > 10 else f"{c.name}: {c.value}" for c in self.session.cookies]
        self.log_message(f"Current cookies: {all_cookies}", "DEBUG")
        
        for cookie in self.session.cookies:
            if cookie.name == 'csrf_token':
                return cookie.value
        
        self.log_message("CSRF token not found in cookies", "WARNING")
        return None

    def fetch_csrf_token(self):
        """Fetch a CSRF token from the API server"""
        if not hasattr(self, 'token') or not self.token:
            self.log_message("Cannot fetch CSRF token: Not authenticated", "WARNING")
            return False
            
        try:
            self.log_message("Fetching CSRF token from server", "INFO")
            # Make sure to include the Authorization header
            headers = {"Authorization": f"Bearer {self.token}"}
            
            # Request a fresh CSRF token
            response = self.session.get(
                f"{self.api_url}/csrf-token", 
                headers=headers,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                # Print all cookies for debugging
                self.log_message(f"Cookies after fetch: {[c.name for c in self.session.cookies]}", "DEBUG")
                
                # The token is automatically set as a cookie
                csrf_token = None
                for cookie in self.session.cookies:
                    if cookie.name == 'csrf_token':
                        csrf_token = cookie.value
                        self.log_message(f"CSRF token obtained successfully: {csrf_token[:10] if len(csrf_token) > 10 else csrf_token}", "INFO")
                        return True
                
                # If we didn't find a csrf_token cookie
                self.log_message("CSRF token not found in cookies", "WARNING")
                return False
            else:
                self.log_message(f"Failed to fetch CSRF token: {response.status_code} - {response.text}", "WARNING")
                return False
        except Exception as e:
            self.log_message(f"Error fetching CSRF token: {e}", "ERROR")
            return False

    def add_csrf_to_request(self, method, url, **kwargs):
        """Helper to add CSRF token to requests and handle errors"""
        # Only add CSRF for non-GET methods
        if method.upper() not in ['GET', 'HEAD', 'OPTIONS']:
            # Get CSRF token from cookies
            csrf_token = None
            for cookie in self.session.cookies:
                if cookie.name == 'csrf_token':
                    csrf_token = cookie.value
                    break
            
            # Log token for debugging
            if csrf_token:
                self.log_message(f"Using CSRF token for {url} (token present: {csrf_token is not None})", "DEBUG")
            else:
                self.log_message(f"No CSRF token found for {url}", "WARNING")
                
                # Try to fetch a token if we don't have one
                if hasattr(self, 'token') and self.token:
                    self.log_message("Attempting to fetch CSRF token", "INFO")
                    response = self.session.get(f"{self.api_url}/csrf-token", headers={"Authorization": f"Bearer {self.token}"})
                    self.log_message(f"CSRF token fetch response: {response.status_code}", "DEBUG")
                    
                    # Check if we got a token
                    for cookie in self.session.cookies:
                        if cookie.name == 'csrf_token':
                            csrf_token = cookie.value
                            self.log_message(f"New CSRF token: {csrf_token[:5]}...{csrf_token[-5:] if len(csrf_token) > 10 else ''}", "INFO")
                            break
            
            # Add token to headers if we have one
            if csrf_token:
                headers = kwargs.get('headers', {})
                headers['X-CSRFToken'] = csrf_token
                kwargs['headers'] = headers
        
        # Make the request
        return getattr(self.session, method.lower())(url, **kwargs)

    def login_with_api(self, api_key=None):
        """Login to the API server with current credentials."""
        self.status_var.set("Logging in to API...")
        
        # Store api_key in a container that can be accessed from the nested function
        auth_data = {'api_key': api_key}
        
        def perform_login():
            try:
                # Use API key if provided, otherwise generate a new one
                if not auth_data['api_key']:
                    import secrets
                    auth_data['api_key'] = f"sk_securevault_{secrets.token_hex(16)}"
                
                # Step 1: First get a CSRF token by making a GET request
                self.log_message("Getting CSRF token from server...", "INFO")
                
                # Clear existing cookies to start fresh
                self.session.cookies.clear()
                
                try:
                    # Make a GET request to get CSRF cookie
                    self.session.get(
                        f"{self.api_url}/files", 
                        timeout=5,
                        verify=False
                    )
                    
                    # Extract CSRF token from cookies
                    csrf_token = None
                    for cookie in self.session.cookies:
                        if 'csrf' in cookie.name.lower():
                            csrf_token = cookie.value
                            self.log_message(f"Found CSRF token in cookie: {cookie.name}", "INFO")
                            break
                    
                    if not csrf_token:
                        self.log_message("No CSRF token found in cookies", "WARNING")
                except Exception as e:
                    self.log_message(f"Error getting CSRF token: {e}", "WARNING")
                    csrf_token = None
                
                # Step 2: Make the auth request with the CSRF token
                self.log_message("Attempting API authentication with CSRF token...", "INFO")
                
                headers = {
                    'X-CSRFToken': csrf_token if csrf_token else '',
                    'X-Requested-With': 'XMLHttpRequest',  # This helps identify AJAX requests
                    'Referer': 'https://localhost:5000/',  # Required for CSRF validation
                    'Origin': 'https://localhost:5000'  # Required for CSRF validation
                }
                
                # Create form data with CSRF token
                form_data = {
                    'username': self.username,
                    'password': auth_data['api_key']
                }
                
                # Add CSRF token to form data if available
                if csrf_token:
                    form_data['csrf_token'] = csrf_token
                
                # Make the auth request with proper CSRF handling
                response = self.session.post(
                    f"{self.api_url}/auth",
                    data=form_data,
                    headers=headers,
                    verify=False,
                    auth=(self.username, auth_data['api_key'])  # Include as both auth and form data
                )
                
                # Handle the response
                if response.status_code == 200:
                    data = response.json()
                    self.token = data.get('token')
                    if self.token:
                        self.session.headers.update({"Authorization": f"Bearer {self.token}"})
                        self.log_message(f"User {self.username} logged in to API successfully", "INFO")
                        
                        # After successful login, fetch a CSRF token for future requests
                        self.log_message("Fetching initial CSRF token after login", "INFO")
                        if not self.fetch_csrf_token():
                            self.log_message("Warning: Could not obtain CSRF token after login", "WARNING")
                        
                        # Switch to main interface
                        self.window.after(0, self.show_main_interface)
                    else:
                        self.login_status_var.set("Invalid response from server")
                        self.log_message("API login failed: Invalid response from server", "ERROR")
                        self.window.after(0, lambda: self.login_manager.show_login_dialog(self.window, self.on_login_success))
                else:
                    # Log detailed error information for debugging
                    self.log_message(f"API login failed: {response.status_code}", "ERROR")
                    self.log_message(f"Response text: {response.text}", "ERROR")
                    self.log_message(f"CSRF token used: {csrf_token}", "INFO")
                    self.log_message(f"Headers sent: {headers}", "INFO")
                    
                    # Extract error message if available
                    error_msg = f"API login failed: {response.status_code}"
                    try:
                        error_details = response.json().get('error', '')
                        if error_details:
                            error_msg += f" - {error_details}"
                    except:
                        pass
                    
                    self.login_status_var.set(error_msg)
                    self.window.after(0, lambda: self.login_manager.show_login_dialog(self.window, self.on_login_success))
                    
            except Exception as e:
                self.login_status_var.set(f"API login error: {str(e)}")
                self.log_message(f"API login error: {str(e)}", "ERROR")
                self.window.after(0, lambda: self.login_manager.show_login_dialog(self.window, self.on_login_success))
        
        # Run in thread to avoid freezing UI
        threading.Thread(target=perform_login).start()

    def login(self):
        """Legacy login method - redirects to the secure login dialog"""
        self.login_manager.show_login_dialog(self.window, self.on_login_success)


    def show_change_password_dialog(self):
        """Show dialog to change user password"""
        if not hasattr(self, 'username') or not self.username:
            messagebox.showwarning("Error", "You must be logged in to change your password.")
            return
            
        self.login_manager.show_change_password_dialog(
            self.window, 
            self.username,
            lambda: messagebox.showinfo("Password Changed", "Your password has been changed successfully.")
        )



    def show_main_interface(self):
        """Show the main interface after successful login"""
        self.login_frame.pack_forget()
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.status_var.set("Logged in successfully")
        
        # Load initial data
        self.refresh_file_list()

    def refresh_file_list(self):
        """Get list of files from the server"""
        self._update_activity_time()
        self.status_var.set("Refreshing file list...")
        self.file_listbox.delete(0, tk.END)
        
        # Reset UI state
        self.filename_var.set("")
        self.size_var.set("")
        self.modified_var.set("")
        self.selection_info_var.set("")
        
        # Disable action buttons until a file is selected
        self.decrypt_button.config(state=tk.DISABLED)
        self.delete_button.config(state=tk.DISABLED)
        
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
        self._update_activity_time()
        selection = self.file_listbox.curselection()
        
        # Clear details if no selection
        if not selection:
            self.filename_var.set("")
            self.size_var.set("")
            self.modified_var.set("")
            self.selection_info_var.set("")
            
            # Disable action buttons that require selection
            self.decrypt_button.config(state=tk.DISABLED)
            self.delete_button.config(state=tk.DISABLED)
            return
        
        # Store selection count for easier access
        selection_count = len(selection)
        
        # Update buttons and info based on selection count
        if selection_count > 1:
            # Multiple files selected - only allow deletion
            self.decrypt_button.config(state=tk.DISABLED)
            self.delete_button.config(state=tk.NORMAL)
            
            # Update selection info
            self.selection_info_var.set(f"{selection_count} files selected. Only deletion is available for multiple files.")
            
            # Clear details panel
            self.filename_var.set("")
            self.size_var.set("")
            self.modified_var.set("")
            
            # Update status
            self.status_var.set(f"{selection_count} files selected")
            return
        
        # Single file selected - enable all actions
        file_name = self.file_listbox.get(selection[0])
        if file_name == "(No files found)":
            self.decrypt_button.config(state=tk.DISABLED)
            self.delete_button.config(state=tk.DISABLED)
            self.selection_info_var.set("")
            return
        
        # Enable buttons for single file
        self.decrypt_button.config(state=tk.NORMAL)
        self.delete_button.config(state=tk.NORMAL)
        self.selection_info_var.set("")
        
        # Find file details from API (existing code)
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
        """Select and encrypt a file with CSRF protection"""
        self._update_activity_time()
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
                # Get CSRF token
                csrf_token = self.get_csrf_token()
                
                # Prepare headers with CSRF token
                headers = {}
                if csrf_token:
                    headers['X-CSRFToken'] = csrf_token
                
                with open(file_path, 'rb') as f:
                    files = {'file': (file_name, f)}
                    data = {'password': password}
                    
                    response = self.session.post(
                        f"{self.api_url}/files",
                        files=files,
                        data=data,
                        headers=headers  # Include CSRF token
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
                    
                elif response.status_code == 400 and "CSRF" in response.text:
                    # Handle CSRF error by fetching a new token and retrying
                    self.log_message("CSRF validation failed, refreshing token and retrying", "WARNING")
                    
                    if self.fetch_csrf_token():
                        # Retry with new token
                        csrf_token = self.get_csrf_token()
                        if csrf_token:
                            headers['X-CSRFToken'] = csrf_token
                            
                            with open(file_path, 'rb') as f:
                                files = {'file': (file_name, f)}
                                data = {'password': password}
                                
                                response = self.session.post(
                                    f"{self.api_url}/files",
                                    files=files,
                                    data=data,
                                    headers=headers
                                )
                            
                            if response.status_code == 200:
                                result = response.json()
                                
                                # Update UI in main thread after retry
                                def update_after_encrypt():
                                    self.refresh_file_list()
                                    messagebox.showinfo("Success", f"File encrypted successfully: {result.get('file', '')}")
                                    self.status_var.set("File encrypted successfully")
                                    self.log_message(f"Encrypted file: {file_name}", "INFO")
                                    
                                self.window.after(0, update_after_encrypt)
                                return
                    
                    # If we get here, retry failed
                    error_msg = "CSRF token validation failed"
                    self.log_message(error_msg, "ERROR")
                    self.window.after(0, lambda: messagebox.showerror("Error", error_msg))
                    self.status_var.set("Encryption failed - CSRF error")
                    
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
        """Decrypt the selected file with improved binary handling."""
        self._update_activity_time()
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
        
        # Define thread function to handle decryption
        def perform_decryption_thread(self_ref, file_name, password, output_path):
            try:
                # Get CSRF token
                csrf_token = self_ref.get_csrf_token()
                
                # Prepare headers
                headers = {
                    'Authorization': f'Bearer {self_ref.token}',
                    'Accept': 'application/octet-stream'  # Request binary data
                }
                
                if csrf_token:
                    headers['X-CSRFToken'] = csrf_token
                
                # Make request to the API with streaming enabled for better binary handling
                response = self_ref.session.post(
                    f"{self_ref.api_url}/files/{file_name}",
                    data={'password': password},
                    headers=headers,
                    stream=True  # Use streaming to handle large files and preserve binary integrity
                )
                
                if response.status_code == 200:
                    # Save streaming content directly to file in binary mode
                    with open(output_path, 'wb') as f:
                        # Process data in chunks to avoid memory issues with large files
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:  # Filter out keep-alive chunks
                                f.write(chunk)
                                f.flush()  # Ensure data is written immediately
                    
                    def update_ui():
                        messagebox.showinfo("Success", "File decrypted successfully!")
                        self_ref.status_var.set("File decrypted successfully")
                        self_ref.log_message(f"Decrypted file: {file_name}", "INFO")
                    
                    self_ref.window.after(0, update_ui)
                    
                elif response.status_code == 400:
                    # Handle validation/decryption errors
                    try:
                        error_data = response.json()
                        error_msg = error_data.get('error', 'Decryption failed')
                    except:
                        error_msg = f"Decryption failed (Status: {response.status_code})"
                    
                    def show_error():
                        messagebox.showerror("Error", error_msg)
                        self_ref.status_var.set("Decryption failed")
                    
                    self_ref.window.after(0, show_error)
                    self_ref.log_message(f"Decryption error: {error_msg}", "ERROR")
                    
                elif response.status_code == 401:
                    # Authentication error
                    def show_auth_error():
                        messagebox.showerror(
                            "Authentication Error",
                            "Your session has expired. Please log in again."
                        )
                        self_ref.logout()
                    
                    self_ref.window.after(0, show_auth_error)
                    self_ref.log_message("Authentication failed: session expired", "ERROR")
                    
                else:
                    # Other server error
                    def show_server_error():
                        messagebox.showerror(
                            "Server Error",
                            f"The server returned an unexpected status: {response.status_code}"
                        )
                        self_ref.status_var.set("Decryption failed - server error")
                    
                    self_ref.window.after(0, show_server_error)
                    self_ref.log_message(f"Server error: {response.status_code}", "ERROR")
                    
            except Exception as e:
                # Handle network or other errors
                def show_exception():
                    messagebox.showerror("Error", f"Decryption error: {str(e)}")
                    self_ref.status_var.set("Decryption failed")
                
                self_ref.window.after(0, show_exception)
                self_ref.log_message(f"Decryption exception: {e}", "ERROR")
        
        # Start thread with proper parameters
        threading.Thread(
            target=perform_decryption_thread,
            args=(self, file_name, password, output_path),
            daemon=True
        ).start()

    def delete_file(self):
        """Delete selected file(s) with password confirmation and CSRF protection"""
        self._update_activity_time()
        
        # Check if any files are selected
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select file(s) to delete")
            return
        
        # Get all selected file names
        selected_files = [self.file_listbox.get(idx) for idx in selection]
        
        # Filter out any "(No files found)" entries
        selected_files = [f for f in selected_files if f != "(No files found)"]
        
        if not selected_files:
            return
        
        # Prepare confirmation message based on number of files
        if len(selected_files) == 1:
            confirm_msg = f"Are you sure you want to delete {selected_files[0]}?\nThis cannot be undone."
        else:
            confirm_msg = f"Are you sure you want to delete these {len(selected_files)} files?\n\n"
            # Show up to 5 filenames to avoid huge dialogs
            for i, file in enumerate(selected_files[:5]):
                confirm_msg += f"• {file}\n"
            if len(selected_files) > 5:
                confirm_msg += f"• ... and {len(selected_files) - 5} more\n"
            confirm_msg += "\nThis action cannot be undone."
        
        # First confirmation dialog
        if not messagebox.askyesno(
            "Confirm Delete",
            confirm_msg
        ):
            return
        
        # Password confirmation dialog - with message depending on number of files
        if len(selected_files) == 1:
            prompt = f"Enter your password to confirm deletion of {selected_files[0]}"
        else:
            prompt = f"Enter your password to confirm deletion of {len(selected_files)} files"
        
        password = self.secure_password_dialog(
            prompt, 
            "Secure Delete Confirmation"
        )
        
        # If the user cancels or doesn't provide a password, abort deletion
        if not password:
            self.log_message("File deletion canceled: No password provided", "INFO")
            return
        
        # Verify the password before proceeding
        success, _ = self.login_manager.authenticate(self.username, password)
        if not success:
            messagebox.showerror(
                "Authentication Failed", 
                "Incorrect password. For security reasons, file deletion requires your password."
            )
            self.log_message("File deletion denied: Invalid password", "WARNING")
            return
        
        # Password verified, proceed with deletion
        self.status_var.set(f"Deleting {len(selected_files)} file(s)...")
        self.log_message(f"Delete operation authorized for {len(selected_files)} file(s)", "INFO")
        
        # Create a progress dialog for multiple files
        if len(selected_files) > 1:
            progress_dialog = tk.Toplevel(self.window)
            progress_dialog.title("Deleting Files")
            progress_dialog.geometry("400x150")
            progress_dialog.transient(self.window)
            progress_dialog.grab_set()
            progress_dialog.resizable(False, False)
            self.center_window(progress_dialog)
            
            ttk.Label(
                progress_dialog, 
                text=f"Deleting {len(selected_files)} files...", 
                font=("Arial", 10, "bold")
            ).pack(pady=(20, 10))
            
            progress_var = tk.DoubleVar()
            progress_bar = ttk.Progressbar(
                progress_dialog, 
                orient=tk.HORIZONTAL, 
                length=350, 
                variable=progress_var,
                maximum=len(selected_files)
            )
            progress_bar.pack(pady=10, padx=20)
            
            status_var = tk.StringVar(value="Starting...")
            status_label = ttk.Label(progress_dialog, textvariable=status_var)
            status_label.pack(pady=10)
        else:
            progress_dialog = None
            progress_var = None
            status_var = None
        
        def perform_deletion():
            success_count = 0
            failed_files = []
            
            try:
                for i, file_name in enumerate(selected_files):
                    try:
                        # Update progress dialog if it exists
                        if progress_dialog and progress_dialog.winfo_exists():
                            progress_var.set(i)
                            status_var.set(f"Deleting: {file_name}")
                            progress_dialog.update()
                        
                        # Use the helper method to handle CSRF tokens
                        response = self.add_csrf_to_request(
                            'DELETE',
                            f"{self.api_url}/files/{file_name}"
                        )
                        
                        if response.status_code == 200:
                            success_count += 1
                            self.log_message(f"Deleted file: {file_name}", "INFO")
                        else:
                            failed_files.append((file_name, f"Status code: {response.status_code}"))
                            self.log_message(f"Failed to delete {file_name}: {response.status_code} - {response.text}", "ERROR")
                    
                    except Exception as e:
                        failed_files.append((file_name, str(e)))
                        self.log_message(f"Error deleting {file_name}: {e}", "ERROR")
                
                # Close progress dialog if it exists and is still open
                if progress_dialog and progress_dialog.winfo_exists():
                    progress_dialog.destroy()
                
                # Update UI in main thread with results
                def update_after_delete():
                    self.refresh_file_list()
                    
                    if failed_files:
                        # Some files failed - show detailed error
                        error_message = f"Successfully deleted {success_count} file(s), but {len(failed_files)} file(s) failed:\n\n"
                        for name, error in failed_files[:5]:  # Show up to 5 errors
                            error_message += f"• {name}: {error}\n"
                        if len(failed_files) > 5:
                            error_message += f"• ... and {len(failed_files) - 5} more\n"
                        
                        messagebox.showerror("Partial Success", error_message)
                        self.status_var.set(f"Deleted {success_count}/{len(selected_files)} files")
                        
                    elif success_count == len(selected_files):
                        # All files deleted successfully
                        if len(selected_files) == 1:
                            messagebox.showinfo("Success", "File deleted successfully!")
                        else:
                            messagebox.showinfo("Success", f"All {len(selected_files)} files deleted successfully!")
                        
                        self.status_var.set(f"Successfully deleted {success_count} file(s)")
                    
                self.window.after(0, update_after_delete)
                    
            except Exception as e:
                # Handle any unexpected errors
                if progress_dialog and progress_dialog.winfo_exists():
                    progress_dialog.destroy()
                    
                error_msg = f"Deletion error: {str(e)}"
                self.log_message(error_msg, "ERROR")
                self.window.after(0, lambda: messagebox.showerror("Error", error_msg))
                self.status_var.set("Deletion error")
        
        # Run in thread to avoid freezing UI
        threading.Thread(target=perform_deletion).start()


    def secure_password_dialog(self, prompt: str, title: str = "Password Required") -> str:
        """
        Show a secure password entry dialog with tight security focus.
        
        Args:
            prompt: The message to display
            title: The dialog title
            
        Returns:
            str: The entered password or None if canceled
        """
        dialog = tk.Toplevel(self.window)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.transient(self.window)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Set security icon
        try:
            dialog.iconbitmap('resources/security.ico')
            pass
        except:
            pass  # Icon failed to load, continue anyway
        
        # Center dialog
        self.center_window(dialog)
        
        # Security icon or warning symbol
        frame = ttk.Frame(dialog, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Add red security warning text at top
        security_label = ttk.Label(
            frame, 
            text="⚠️ SECURITY VERIFICATION REQUIRED", 
            foreground="#e74c3c",
            font=("Arial", 10, "bold")
        )
        security_label.pack(pady=(5, 15))
        
        # Add prompt
        message_label = ttk.Label(frame, text=prompt, wraplength=350, justify=tk.CENTER)
        message_label.pack(pady=5)
        
        # Password entry
        password_frame = ttk.Frame(frame)
        password_frame.pack(pady=10, fill=tk.X)
        
        ttk.Label(password_frame, text="Password:").pack(side=tk.LEFT, padx=(30, 5))
        password_var = tk.StringVar()
        password_entry = ttk.Entry(password_frame, show="●", textvariable=password_var, width=25)
        password_entry.pack(side=tk.LEFT, padx=5)
        
        result = [None]  # Use list to store result
        
        def on_ok():
            result[0] = password_var.get()
            dialog.destroy()
            
        def on_cancel():
            dialog.destroy()
        
        # Button frame
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            button_frame, 
            text="Cancel", 
            command=on_cancel
        ).pack(side=tk.RIGHT, padx=10)
        
        # Bind Enter key to OK button
        dialog.bind('<Return>', lambda event: on_ok())
        dialog.bind('<Escape>', lambda event: on_cancel())
        
        # Set focus to the password entry
        password_entry.focus_set()
        
        # Wait for dialog to close
        dialog.wait_window()
        return result[0]

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
                # Use the helper method for CSRF handling
                response = self.add_csrf_to_request(
                    'POST',
                    f"{self.api_url}/auth/revoke"
                )
                
                # Log the response for debugging
                self.log_message(f"Logout response: {response.status_code} - {response.text}", "INFO")
                
                # Clear token regardless of response
                self.token = None
                self.session.headers.pop('Authorization', None)
                
                # Clear local user session
                self.login_manager.logout()
                self.username = None
                
            except Exception as e:
                self.log_message(f"Logout error: {e}", "ERROR")
            finally:
                # Switch to login screen
                self.window.after(0, self.show_login_screen)
        
        # Run in thread
        threading.Thread(target=perform_logout).start()

    def show_login_screen(self):
        """Show the login screen"""
        # Clear current session data
        self.token = None
        if hasattr(self, 'session') and hasattr(self.session, 'headers'):
            self.session.headers.pop('Authorization', None)
        
        # Clear main frame
        self.main_frame.pack_forget()
        
        # Update login status
        self.login_status_var.set("")
        self.status_var.set("Please login")
        
        # Show login dialog
        self.login_manager.logout()
        self.login_manager.show_login_dialog(self.window, self.on_login_success)

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