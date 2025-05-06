"""
Login manager for SecureVault GUI integration
"""

import logging
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import os
import time
from typing import Callable, Optional, Dict, Any, Tuple

from secure_vault.users.user_manager import UserManager

logger = logging.getLogger(__name__)

class LoginManager:
    """
    Manages the login process and integration with the GUI.
    """
    
    def __init__(self, db_path: str, session_timeout_minutes: int = 30):
        """
        Initialize the login manager.
        
        Args:
            db_path: Path to the user database
            session_timeout_minutes: Session timeout in minutes
        """
        self.user_manager = UserManager(db_path)
        self.current_user = None
        self.session_start_time = None
        self.session_timeout = session_timeout_minutes * 60  # Convert to seconds
        
    def authenticate(self, username: str, password: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Authenticate a user.
        
        Args:
            username: The username to authenticate
            password: The password to verify
            
        Returns:
            Tuple of (success, user_info or error)
        """
        success, user_info = self.user_manager.authenticate(username, password)
        if success:
            self.current_user = user_info
            self.session_start_time = time.time()
        return success, user_info
    
    def setup_first_user(self, window, on_success: Optional[Callable] = None):
        """Show setup dialog for first user using a simpler layout"""
        if self.user_manager.has_any_users():
            return False
            
        # Create a simple dialog with reliable sizing
        setup_dialog = tk.Toplevel(window)
        setup_dialog.title("SecureVault Initial Setup")
        setup_dialog.geometry("450x550")  # Larger size
        setup_dialog.transient(window)
        setup_dialog.grab_set()
        
        # Add a scrollable canvas to ensure everything fits
        canvas = tk.Canvas(setup_dialog)
        scrollbar = ttk.Scrollbar(setup_dialog, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Setup form - all in a single scrollable frame
        ttk.Label(scrollable_frame, text="Welcome to SecureVault!", 
                font=("Arial", 14, "bold")).pack(pady=10, padx=20)
        ttk.Label(scrollable_frame, text="Create your admin account to get started").pack(pady=5)
        
        form_frame = ttk.Frame(scrollable_frame, padding=10)
        form_frame.pack(pady=10, padx=20, fill=tk.X)
        
        # Form fields using pack for more reliable layout
        field_frame = ttk.Frame(form_frame)
        field_frame.pack(fill=tk.X, pady=5)
        ttk.Label(field_frame, text="Username:").pack(anchor=tk.W)
        username_var = tk.StringVar()
        ttk.Entry(field_frame, textvariable=username_var, width=40).pack(fill=tk.X, pady=2)
        
        field_frame = ttk.Frame(form_frame)
        field_frame.pack(fill=tk.X, pady=5)
        ttk.Label(field_frame, text="Password:").pack(anchor=tk.W)
        password_var = tk.StringVar()
        ttk.Entry(field_frame, textvariable=password_var, show="*", width=40).pack(fill=tk.X, pady=2)
        
        field_frame = ttk.Frame(form_frame)
        field_frame.pack(fill=tk.X, pady=5)
        ttk.Label(field_frame, text="Confirm Password:").pack(anchor=tk.W)
        confirm_var = tk.StringVar()
        ttk.Entry(field_frame, textvariable=confirm_var, show="*", width=40).pack(fill=tk.X, pady=2)
        
        field_frame = ttk.Frame(form_frame)
        field_frame.pack(fill=tk.X, pady=5)
        ttk.Label(field_frame, text="Email (optional):").pack(anchor=tk.W)
        email_var = tk.StringVar()
        ttk.Entry(field_frame, textvariable=email_var, width=40).pack(fill=tk.X, pady=2)
        
        # Password requirements
        requirements_frame = ttk.LabelFrame(scrollable_frame, text="Password Requirements", padding=5)
        requirements_frame.pack(fill=tk.X, padx=20, pady=5)
        
        requirements_text = (
            "• At least 10 characters long\n"
            "• At least one uppercase letter\n"
            "• At least one lowercase letter\n"
            "• At least one digit\n"
            "• At least one special character"
        )
        ttk.Label(requirements_frame, text=requirements_text, justify=tk.LEFT).pack(anchor=tk.W)
        
        # Error message display
        error_var = tk.StringVar()
        error_label = ttk.Label(scrollable_frame, textvariable=error_var, foreground="red")
        error_label.pack(pady=5)
        
        def create_admin():
            username = username_var.get().strip()
            password = password_var.get()
            confirm = confirm_var.get()
            email = email_var.get().strip()
            
            # Validate input
            if not username:
                error_var.set("Username is required")
                return
                
            if len(username) < 3:
                error_var.set("Username must be at least 3 characters")
                return
                
            if not password:
                error_var.set("Password is required")
                return
                
            if password != confirm:
                error_var.set("Passwords do not match")
                return
                
            # Create the user
            success = self.user_manager.create_user(username, password, email)
            
            if success:
                messagebox.showinfo(
                    "Setup Complete", 
                    "Admin account created successfully! You can now login."
                )
                setup_dialog.destroy()
                if on_success:
                    on_success()
            else:
                error_var.set("Failed to create user. Check password requirements.")
        
        # Create button with plenty of padding and visibility
        ttk.Button(
            scrollable_frame, 
            text="Create Admin Account", 
            command=create_admin,
            width=30  # Extra wide button for visibility
        ).pack(pady=30)  # Plenty of padding
        
        return True
    
    def show_login_dialog(self, window, on_success: Optional[Callable] = None):
        """
        Show login dialog.
        
        Args:
            window: Parent tkinter window
            on_success: Callback function to call after successful login
        """
        # Check if we need to set up first user
        if self.setup_first_user(window, lambda: self.show_login_dialog(window, on_success)):
            return
            
        # Create login dialog
        login_dialog = tk.Toplevel(window)
        login_dialog.title("SecureVault Login")
        login_dialog.geometry("350x200")
        login_dialog.transient(window)
        login_dialog.grab_set()
        login_dialog.resizable(False, False)
        
        # Center dialog
        self._center_window(login_dialog, window)
        
        # Login form
        tk.Label(login_dialog, text="SecureVault Login", font=("Arial", 14, "bold")).pack(pady=10)
        
        form_frame = ttk.Frame(login_dialog, padding=10)
        form_frame.pack(pady=5)
        
        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        username_var = tk.StringVar()
        username_entry = ttk.Entry(form_frame, textvariable=username_var, width=25)
        username_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(form_frame, textvariable=password_var, show="*", width=25)
        password_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Error message display
        error_var = tk.StringVar()
        error_label = ttk.Label(login_dialog, textvariable=error_var, foreground="red")
        error_label.pack(pady=5)
        
        def do_login():
            username = username_var.get().strip()
            password = password_var.get()
            
            if not username or not password:
                error_var.set("Username and password are required")
                return
                
            success, result = self.authenticate(username, password)
            
            if success:
                # Add the actual password to the result for API authentication
                result["password"] = password
                login_dialog.destroy()
                if on_success:
                    on_success(result)
            else:
                error_var.set(result.get("error", "Authentication failed"))
        
        # Login button
        button_frame = ttk.Frame(login_dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(
            button_frame,
            text="Login",
            command=do_login,
            width=10
        ).pack()
        
        # Focus username field
        username_entry.focus_set()
        
        # Bind Enter key to login function
        login_dialog.bind('<Return>', lambda event: do_login())
    
    def show_change_password_dialog(self, window, username: str, on_success: Optional[Callable] = None):
        """
        Show change password dialog.
        
        Args:
            window: Parent tkinter window
            username: Username of the user
            on_success: Callback function to call after successful password change
        """
        dialog = tk.Toplevel(window)
        dialog.title("Change Password")
        dialog.geometry("400x250")
        dialog.transient(window)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        self._center_window(dialog, window)
        
        tk.Label(dialog, text="Change Password", font=("Arial", 12, "bold")).pack(pady=10)
        
        form_frame = ttk.Frame(dialog, padding=10)
        form_frame.pack(pady=5, padx=20, fill=tk.BOTH)
        
        ttk.Label(form_frame, text="Current Password:").grid(row=0, column=0, sticky=tk.W, pady=5)
        current_var = tk.StringVar()
        current_entry = ttk.Entry(form_frame, textvariable=current_var, show="*", width=25)
        current_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(form_frame, text="New Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        new_var = tk.StringVar()
        new_entry = ttk.Entry(form_frame, textvariable=new_var, show="*", width=25)
        new_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(form_frame, text="Confirm New Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        confirm_var = tk.StringVar()
        confirm_entry = ttk.Entry(form_frame, textvariable=confirm_var, show="*", width=25)
        confirm_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Error message display
        error_var = tk.StringVar()
        error_label = ttk.Label(dialog, textvariable=error_var, foreground="red")
        error_label.pack(pady=5)
        
        def do_change_password():
            current = current_var.get()
            new_password = new_var.get()
            confirm = confirm_var.get()
            
            # Validate input
            if not current:
                error_var.set("Current password is required")
                return
                
            if not new_password:
                error_var.set("New password is required")
                return
                
            if new_password != confirm:
                error_var.set("New passwords do not match")
                return
                
            # Change password
            success = self.user_manager.change_password(
                username, current, new_password
            )
            
            if success:
                messagebox.showinfo(
                    "Password Changed", 
                    "Your password has been changed successfully"
                )
                dialog.destroy()
                if on_success:
                    on_success()
            else:
                error_var.set("Failed to change password. Incorrect current password or invalid new password.")
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(
            button_frame,
            text="Change Password",
            command=do_change_password,
            width=15
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Cancel",
            command=dialog.destroy,
            width=10
        ).pack(side=tk.LEFT, padx=5)
        
        # Focus current password field
        current_entry.focus_set()
    
    def is_session_valid(self) -> bool:
        """Check if the current session is valid."""
        if not self.current_user or not self.session_start_time:
            return False
            
        # Check session timeout
        elapsed = time.time() - self.session_start_time
        return elapsed < self.session_timeout
    
    def refresh_session(self):
        """Refresh the session timeout."""
        if self.current_user:
            self.session_start_time = time.time()
    
    def logout(self):
        """Clear current user session."""
        self.current_user = None
        self.session_start_time = None
    
    def get_current_username(self) -> Optional[str]:
        """Get the current username."""
        if self.current_user:
            return self.current_user.get("username")
        return None
    
    def get_api_key(self) -> Optional[str]:
        """Get the API key for the current user."""
        if self.current_user:
            return self.current_user.get("api_key")
        return None
        
    def _center_window(self, window, parent=None):
        """Center a window on the screen or parent."""
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        
        if parent:
            x = parent.winfo_rootx() + (parent.winfo_width() - width) // 2
            y = parent.winfo_rooty() + (parent.winfo_height() - height) // 2
        else:
            x = (window.winfo_screenwidth() - width) // 2
            y = (window.winfo_screenheight() - height) // 2
            
        window.geometry(f"{width}x{height}+{x}+{y}")