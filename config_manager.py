"""
SecureVault Configuration Manager
Handles loading, saving, and managing application configuration
"""

import os
import json
import logging
from pathlib import Path
import platform
import appdirs

class ConfigManager:
    """Manages SecureVault configuration settings"""
    
    # Default configuration values
    DEFAULT_CONFIG = {
        # Data storage locations
        "vault_dir": None,  # Will be set to default in __init__
        "data_dir": None,   # Will be set to default in __init__
        "logs_dir": None,   # Will be set to default in __init__
        
        # Server settings
        "api_host": "localhost",
        "api_port": 5000,
        "verify_ssl": False,
        
        # Security settings
        "session_timeout": 30,  # minutes
        "password_timeout": 5,   # minutes
        "auto_lock": True,
        
        # UI preferences
        "theme": "system",  # system, light, dark
        "remember_username": False,
        "last_username": "",
        
        # Installation settings
        "first_run": True,
        "installation_complete": False,
        "version": "1.0.0"
    }
    
    def __init__(self, app_name="SecureVault", portable_mode=False):
        """
        Initialize the configuration manager
        
        Args:
            app_name: Application name for config folders
            portable_mode: If True, store config relative to executable
        """
        self.app_name = app_name
        self.portable_mode = portable_mode
        self.logger = logging.getLogger('config_manager')
        
        # Determine the base directories for configuration and data
        if portable_mode or self._is_running_as_executable():
            # Portable mode - store everything relative to executable
            self.base_dir = self._get_executable_dir()
            self.config_file = os.path.join(self.base_dir, "securevault.conf")
        else:
            # Standard installation - use system appropriate directories
            self.base_dir = appdirs.user_data_dir(app_name)
            self.config_file = os.path.join(self.base_dir, "config.json")
        
        # Create base directory if it doesn't exist
        os.makedirs(self.base_dir, exist_ok=True)
        
        # Set default data directories
        self.DEFAULT_CONFIG["vault_dir"] = os.path.join(self.base_dir, "vault")
        self.DEFAULT_CONFIG["data_dir"] = os.path.join(self.base_dir, "data")
        self.DEFAULT_CONFIG["logs_dir"] = os.path.join(self.base_dir, "logs")
        
        # Load configuration
        self.config = self._load_config()
    
    def _is_running_as_executable(self):
        """Check if running as a packaged executable"""
        return getattr(os, 'frozen', False)
    
    def _get_executable_dir(self):
        """Get the directory of the executable or script"""
        if self._is_running_as_executable():
            # Running as packaged executable
            return os.path.dirname(os.path.abspath(sys.executable))
        else:
            # Running as script
            return os.path.dirname(os.path.abspath(__file__))
    
    def _get_user_dirs(self):
        """Get appropriate directories for the current OS"""
        system = platform.system()
        
        if system == "Windows":
            return {
                "documents": os.path.join(os.path.expanduser("~"), "Documents"),
                "appdata": os.path.join(os.path.expanduser("~"), "AppData", "Local"),
                "desktop": os.path.join(os.path.expanduser("~"), "Desktop")
            }
        elif system == "Darwin":  # macOS
            return {
                "documents": os.path.join(os.path.expanduser("~"), "Documents"),
                "appdata": os.path.join(os.path.expanduser("~"), "Library", "Application Support"),
                "desktop": os.path.join(os.path.expanduser("~"), "Desktop")
            }
        else:  # Linux and others
            return {
                "documents": os.path.join(os.path.expanduser("~"), "Documents"),
                "appdata": os.path.join(os.path.expanduser("~"), ".local", "share"),
                "desktop": os.path.join(os.path.expanduser("~"), "Desktop")
            }
    
    def _load_config(self):
        """Load configuration from file or use defaults"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                
                # Merge with defaults to ensure all keys exist
                merged_config = self.DEFAULT_CONFIG.copy()
                merged_config.update(config)
                self.logger.info(f"Configuration loaded from {self.config_file}")
                return merged_config
                
            except Exception as e:
                self.logger.error(f"Error loading configuration: {e}")
                # Return a fresh copy of the defaults
                return self.DEFAULT_CONFIG.copy()
        else:
            self.logger.info("No configuration file found, using defaults")
            return self.DEFAULT_CONFIG.copy()
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
                
            self.logger.info(f"Configuration saved to {self.config_file}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
            return False
    
    def get(self, key, default=None):
        """Get a configuration value"""
        return self.config.get(key, default)
    
    def set(self, key, value):
        """Set a configuration value"""
        self.config[key] = value
        return self.save_config()
    
    def update(self, settings_dict):
        """Update multiple configuration values at once"""
        self.config.update(settings_dict)
        return self.save_config()
    
    def reset(self):
        """Reset configuration to defaults"""
        self.config = self.DEFAULT_CONFIG.copy()
        return self.save_config()
    
    def ensure_directories(self):
        """Ensure all configured directories exist"""
        directories = [
            self.config["vault_dir"],
            self.config["data_dir"],
            self.config["logs_dir"],
            # Subdirectories
            os.path.join(self.config["data_dir"], "users"),
            os.path.join(self.config["logs_dir"], "security")
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
                self.logger.info(f"Ensured directory exists: {directory}")
            except Exception as e:
                self.logger.error(f"Failed to create directory {directory}: {e}")
                return False
        
        return True
    
    def get_data_locations(self):
        """Get a dictionary of all data storage locations"""
        return {
            "base_dir": self.base_dir,
            "config_file": self.config_file,
            "vault_dir": self.config["vault_dir"],
            "data_dir": self.config["data_dir"],
            "logs_dir": self.config["logs_dir"],
            "users_db": os.path.join(self.config["data_dir"], "users", "users.db")
        }
    
    def get_suggested_locations(self):
        """Get suggested locations for data storage based on OS"""
        user_dirs = self._get_user_dirs()
        app_folder = self.app_name
        
        return {
            "default": self.base_dir,
            "documents": os.path.join(user_dirs["documents"], app_folder),
            "appdata": os.path.join(user_dirs["appdata"], app_folder),
            "desktop": os.path.join(user_dirs["desktop"], app_folder),
            "custom": None  # Placeholder for user-selected location
        }
    
    def migrate_data(self, old_locations, new_locations):
        """Migrate data from old locations to new ones"""
        import shutil
        
        # Map of old to new locations
        migration_map = {
            old_locations["vault_dir"]: new_locations["vault_dir"],
            old_locations["data_dir"]: new_locations["data_dir"],
            old_locations["logs_dir"]: new_locations["logs_dir"]
        }
        
        # Perform migration
        for old_path, new_path in migration_map.items():
            if old_path == new_path:
                continue  # Skip if locations are the same
                
            if not os.path.exists(old_path):
                continue  # Skip if source doesn't exist
                
            try:
                # Create destination directory
                os.makedirs(os.path.dirname(new_path), exist_ok=True)
                
                # Copy files if old location exists
                if os.path.exists(old_path):
                    if os.path.isdir(old_path):
                        # Copy directory contents
                        if not os.path.exists(new_path):
                            shutil.copytree(old_path, new_path)
                        else:
                            # Destination exists, copy files individually
                            for item in os.listdir(old_path):
                                src_item = os.path.join(old_path, item)
                                dst_item = os.path.join(new_path, item)
                                if os.path.isdir(src_item):
                                    if not os.path.exists(dst_item):
                                        shutil.copytree(src_item, dst_item)
                                else:
                                    shutil.copy2(src_item, dst_item)
                    else:
                        # Copy single file
                        shutil.copy2(old_path, new_path)
                        
                self.logger.info(f"Migrated data from {old_path} to {new_path}")
                
            except Exception as e:
                self.logger.error(f"Failed to migrate from {old_path} to {new_path}: {e}")
                return False
        
        return True

# Import at module level to avoid circular imports
import sys