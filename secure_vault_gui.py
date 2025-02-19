import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import requests
import os
import json
import urllib3
from pathlib import Path
import base64
from datetime import datetime

# Disable SSL warnings for development with self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecureVaultGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("SecureVault")
        self.window.geometry("900x600")
        self.window.minsize(800, 500)
        
        # API configuration
        self.api_url = "https://localhost:5000/api"
        self.verify_ssl = False  # Set to True in production with valid certificates
        self.token = None
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        
        # Add headers to handle CSRF protection
        self.session.headers.update({
            'Origin': 'https://localhost:5000',
            'Referer': 'https://localhost:5000/',
            'User-Agent': 'SecureVaultGUI/1.0'
        })
        
        # Create UI elements
        self.create_widgets()
        
        # Check server and login
        self.check_server_connection()
    
    def create_widgets(self):
        # Create main frame
        self.main_frame = ttk.Frame(self.window, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create tabbed interface
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Tab 1: Files
        self.files_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.files_tab, text="Files")
        
        # Tab 2: Settings
        self.settings_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.settings_tab, text="Settings")
        
        # Tab 3: Logs
        self.logs_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.logs_tab, text="Logs")
        
        # Create login frame (initially visible)
        self.login_frame = ttk.Frame(self.window, padding="20")
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
        # Set up each tab
        self.setup_files_tab()
        self.setup_settings_tab()
        self.setup_logs_tab()
        self.setup_login_frame()
        
        # Initially hide main frame until logged in
        self.main_frame.pack_forget()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.window, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_files_tab(self):
        # Split into left (file list) and right (details) panes
        self.files_paned = ttk.PanedWindow(self.files_tab, orient=tk.HORIZONTAL)
        self.files_paned.pack(fill=tk.BOTH, expand=True)
        
        # Left panel (file list)
        left_frame = ttk.LabelFrame(self.files_paned, text="Encrypted Files", padding="5")
        self.files_paned.add(left_frame, weight=1)
        
        # File listbox with scrollbar
        self.file_listbox = tk.Listbox(left_frame, width=40, activestyle='dotbox')
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.file_listbox.bind('<<ListboxSelect>>', self.on_file_select)
        
        scrollbar = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.file_listbox.yview)
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
        
        ttk.Button(encrypt_frame, text="Select File to Encrypt", 
                   command=self.encrypt_file).pack(pady=5)
        
        # Decrypt section
        decrypt_frame = ttk.LabelFrame(actions_frame, text="Decrypt Selected File", padding="10")
        decrypt_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(decrypt_frame, text="Decrypt File", 
                   command=self.decrypt_file).pack(pady=5)
        
        # Delete section
        delete_frame = ttk.LabelFrame(actions_frame, text="Delete Selected File", padding="10")
        delete_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(delete_frame, text="Delete File", 
                   command=self.delete_file).pack(pady=5)
        
        # Refresh button
        ttk.Button(actions_frame, text="Refresh File List", 
                  command=self.refresh_file_list).pack(pady=20)
    
    def setup_settings_tab(self):
        # Server settings
        server_frame = ttk.LabelFrame(self.settings_tab, text="Server Settings", padding="10")
        server_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(server_frame, text="API URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.server_url_var = tk.StringVar(value=self.api_url)
        ttk.Entry(server_frame, textvariable=self.server_url_var, width=40).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # SSL verification
        self.verify_ssl_var = tk.BooleanVar(value=self.verify_ssl)
        ttk.Checkbutton(server_frame, text="Verify SSL Certificate", 
                       variable=self.verify_ssl_var,
                       command=self.update_ssl_settings).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Button(server_frame, text="Test Connection", 
                  command=self.check_server_connection).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Security settings
        security_frame = ttk.LabelFrame(self.settings_tab, text="Security Settings", padding="10")
        security_frame.pack(fill=tk.X, pady=10)
        
        # Auto-logout timer
        ttk.Label(security_frame, text="Auto-logout after inactivity (minutes):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.auto_logout_var = tk.IntVar(value=30)
        ttk.Spinbox(security_frame, from_=5, to=120, textvariable=self.auto_logout_var, width=5).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Remember credentials
        self.remember_creds_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(security_frame, text="Remember username", 
                       variable=self.remember_creds_var).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Save settings button
        ttk.Button(self.settings_tab, text="Save Settings", 
                  command=self.save_settings).pack(pady=20)
    
    def setup_logs_tab(self):
        # Log viewer
        self.log_text = scrolledtext.ScrolledText(self.logs_tab, height=25)
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)
        self.log_text.config(state=tk.DISABLED)
        
        # Controls frame
        controls_frame = ttk.Frame(self.logs_tab)
        controls_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(controls_frame, text="Refresh Logs", 
                  command=self.refresh_logs).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(controls_frame, text="Clear Logs", 
                  command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        
        # Include server logs checkbox
        self.include_server_logs_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(controls_frame, text="Include server logs", 
                       variable=self.include_server_logs_var).pack(side=tk.RIGHT, padx=5)
    
    def setup_login_frame(self):
        # Title
        title_label = ttk.Label(self.login_frame, text="SecureVault Login", font=("Arial", 16, "bold"))
        title_label.pack(pady=20)
        
        # Login form
        login_form = ttk.Frame(self.login_frame)
        login_form.pack(pady=20)
        
        ttk.Label(login_form, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=10)
        self.username_var = tk.StringVar()
        ttk.Entry(login_form, textvariable=self.username_var, width=30).grid(row=0, column=1, sticky=tk.W, pady=10)
        
        ttk.Label(login_form, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.password_var = tk.StringVar()
        ttk.Entry(login_form, textvariable=self.password_var, show="*", width=30).grid(row=1, column=1, sticky=tk.W, pady=10)
        
        # Login button
        ttk.Button(self.login_frame, text="Login", 
                  command=self.login).pack(pady=20)
        
        # Status message
        self.login_status_var = tk.StringVar()
        ttk.Label(self.login_frame, textvariable=self.login_status_var, foreground="red").pack(pady=10)
    
    def log_message(self, message, level="INFO"):
        """Add a message to the log with timestamp"""
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
    
    def check_server_connection(self):
        """Check if the server is reachable and HTTPS is working"""
        self.log_message("Checking server connection...")
        self.status_var.set("Checking server connection...")
        
        def check_connection():
            try:
                response = self.session.get(f"{self.api_url}/files", timeout=5)
                
                # Returned 401 means server is up but we're not authenticated (expected)
                if response.status_code == 401:
                    self.log_message("Server connection successful", "INFO")
                    self.status_var.set("Server connected. Please login.")
                    return True
                else:
                    self.log_message(f"Unexpected response: {response.status_code}", "WARNING")
                    self.status_var.set(f"Server returned {response.status_code}")
                    return False
                    
            except requests.exceptions.SSLError:
                self.log_message("SSL certificate verification failed. Using self-signed certificate?", "WARNING")
                self.status_var.set("SSL verification failed - using self-signed cert")
                return True  # Continue anyway for development
                
            except requests.exceptions.ConnectionError:
                self.log_message("Cannot connect to server. Is it running?", "ERROR")
                self.status_var.set("Server connection failed")
                messagebox.showerror("Connection Error", 
                                     f"Cannot connect to server at {self.api_url}.\nIs the server running?")
                return False
                
            except Exception as e:
                self.log_message(f"Connection error: {str(e)}", "ERROR")
                self.status_var.set("Connection error")
                return False
        
        # Run in thread to avoid freezing UI
        threading.Thread(target=check_connection).start()
    
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
                    stream=True  # Important for large files
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
        if not messagebox.askyesno("Confirm Delete", 
                                  f"Are you sure you want to delete {file_name}?\nThis cannot be undone."):
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
                self.log_message(f"Logout error: {str(e)}", "ERROR")
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
    
    def password_dialog(self, prompt):
        """Show password dialog and return the entered password"""
        dialog = tk.Toplevel(self.window)
        dialog.title(prompt)
        dialog.geometry("300x150")
        dialog.transient(self.window)
        dialog.grab_set()
        dialog.resizable(False, False)
        
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
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=20)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=20)
        
        # Bind Enter key to OK button
        dialog.bind('<Return>', lambda event: on_ok())
        dialog.bind('<Escape>', lambda event: on_cancel())
        
        # Wait for dialog to close
        dialog.wait_window()
        return result[0]
    
    def run(self):
        """Run the application"""
        # Set up menu
        self.create_menu()
        
        # Set up window close handler
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Start the main loop
        self.window.mainloop()
    
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
    
    def on_close(self):
        """Handle window close event"""
        if messagebox.askyesno("Confirm Exit", "Are you sure you want to exit?"):
            # Logout if token exists
            if self.token:
                try:
                    self.session.post(f"{self.api_url}/auth/revoke")
                except:
                    pass  # Ignore errors during exit
            
            self.window.destroy()
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
        SecureVault GUI
        Version 1.0
        
        A secure file encryption application using
        AES-256-GCM authenticated encryption and
        HTTPS for secure communication.
        
        © 2025 Mason Parle
        """
        messagebox.showinfo("About SecureVault", about_text)
    
    def check_updates(self):
        """Check for application updates"""
        self.log_message("Checking for updates...", "INFO")
        self.status_var.set("Checking for updates...")
        
        # Simulate update check
        self.window.after(1500, lambda: self.status_var.set("No updates available"))
        self.window.after(1500, lambda: messagebox.showinfo("Updates", "You are using the latest version."))

if __name__ == "__main__":
    app = SecureVaultGUI()
    app.run()