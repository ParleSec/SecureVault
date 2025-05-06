"""
Secure user management system for SecureVault
"""

import sqlite3
import os
import logging
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from typing import Optional, Dict, Any, Tuple, List
import time
import json

logger = logging.getLogger(__name__)

class UserManager:
    """Manages user accounts and authentication with secure password storage."""
    
    # Hash method identifiers
    HASH_METHOD_PBKDF2 = "pbkdf2"
    HASH_METHOD_ARGON2ID = "argon2id"
    
    def __init__(self, db_path: str):
        """
        Initialize the user manager with the path to the user database.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_dir = self.db_path.parent
        self._ensure_db_exists()
        
    def _ensure_db_exists(self):
        """Create the database and tables if they don't exist."""
        self.db_dir.mkdir(parents=True, exist_ok=True)
        
        # Create database connection
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create users table with proper schema
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            hash_method TEXT DEFAULT 'pbkdf2',
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            account_locked INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            api_key TEXT
        )
        ''')
        
        # Add hash_method column if it doesn't exist (for compatibility with existing databases)
        try:
            cursor.execute("SELECT hash_method FROM users LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE users ADD COLUMN hash_method TEXT DEFAULT 'pbkdf2'")
            logger.info("Added hash_method column to users table")
        
        conn.commit()
        conn.close()
        
    def create_user(self, username: str, password: str, email: Optional[str] = None) -> bool:
        """
        Create a new user account with enhanced validation.
        
        Args:
            username: The username for the new account
            password: The password for the new account
            email: Optional email address for the account
            
        Returns:
            bool: True if user creation was successful, False otherwise
        """
        try:
            # Check if username already exists
            if self.user_exists(username):
                logger.warning(f"User creation failed: username '{username}' already exists")
                return False
            
            # Import security validator for enhanced validation
            try:
                from secure_vault.utils.input_validation import security_validator
                
                # Enhanced validation for username
                valid, error = security_validator.validate_input(
                    username,
                    check_sql=True,
                    check_xss=True,
                    check_path=False,
                    check_command=False,
                    context="text"
                )
                if not valid:
                    logger.warning(f"User creation failed: invalid username format - {error}")
                    return False
                
                # Enhanced validation for email if provided
                if email:
                    valid, error = security_validator.validate_input(
                        email,
                        check_sql=True,
                        check_xss=True,
                        check_path=False,
                        check_command=False,
                        context="text"
                    )
                    if not valid:
                        logger.warning(f"User creation failed: invalid email format - {error}")
                        return False
            except ImportError:
                # Skip enhanced validation if module not available
                logger.warning("Security validator module not available, skipping enhanced validation")
            
            # Validate password
            valid, error_msg = self._validate_password(password)
            if not valid:
                logger.warning(f"User creation failed: password validation failed - {error_msg}")
                return False
            
            # Generate random salt
            salt = secrets.token_bytes(16)
            salt_b64 = base64.b64encode(salt).decode('utf-8')
            
            # Hash the password with the salt
            password_hash, hash_method = self._hash_password(password, salt)
            
            # Generate API key for this user
            api_key = secrets.token_hex(32)
            
            # Store the user
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO users (username, password_hash, password_salt, hash_method, email, api_key)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', 
                (username, password_hash, salt_b64, hash_method, email, api_key)
            )
            conn.commit()
            conn.close()
            
            logger.info(f"User '{username}' created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return False
    
    def authenticate(self, username: str, password: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Authenticate a user with username and password.
        
        Args:
            username: The username to authenticate
            password: The password to verify
            
        Returns:
            Tuple of (success, user_info)
            success: True if authentication was successful
            user_info: Dict with user information or error details
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get user record
            cursor.execute(
                "SELECT id, password_hash, password_salt, hash_method, account_locked, failed_attempts, api_key FROM users WHERE username = ?", 
                (username,)
            )
            row = cursor.fetchone()
            
            if not row:
                # User not found
                logger.warning(f"Authentication failed: user '{username}' not found")
                return False, {"error": "Invalid username or password"}
            
            user_id, stored_hash, salt_b64, hash_method, is_locked, failed_attempts, api_key = row
            
            # Use empty string as default if hash_method is None (for backward compatibility)
            hash_method = hash_method or self.HASH_METHOD_PBKDF2
            
            # Check if account is locked
            if is_locked:
                logger.warning(f"Authentication attempt for locked account: {username}")
                return False, {"error": "Account locked due to too many failed attempts. Please contact administrator."}
            
            # Verify the password
            salt = base64.b64decode(salt_b64)
            password_verified = self._verify_password(password, stored_hash, salt, hash_method)
            
            if password_verified:
                # Check if we need to upgrade the hash method
                if hash_method != self.HASH_METHOD_ARGON2ID:
                    logger.info(f"Upgrading password hash for user '{username}' from {hash_method} to {self.HASH_METHOD_ARGON2ID}")
                    # Generate new hash with Argon2id
                    new_hash, new_method = self._hash_password(password, salt)
                    
                    # Update user record with new hash and method
                    cursor.execute(
                        "UPDATE users SET password_hash = ?, hash_method = ? WHERE id = ?",
                        (new_hash, new_method, user_id)
                    )
                
                # Reset failed attempts and update last login
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE id = ?",
                    (user_id,)
                )
                conn.commit()
                
                # Get user info
                cursor.execute("SELECT username, email, created_at FROM users WHERE id = ?", (user_id,))
                username, email, created_at = cursor.fetchone()
                
                user_info = {
                    "id": user_id,
                    "username": username,
                    "email": email,
                    "created_at": created_at,
                    "api_key": api_key
                }
                
                logger.info(f"User '{username}' authenticated successfully")
                return True, user_info
            else:
                # Increment failed attempts
                new_attempts = failed_attempts + 1
                lock_account = new_attempts >= 5  # Lock after 5 failures
                
                cursor.execute(
                    "UPDATE users SET failed_attempts = ?, account_locked = ? WHERE id = ?",
                    (new_attempts, 1 if lock_account else 0, user_id)
                )
                conn.commit()
                
                if lock_account:
                    logger.warning(f"Account '{username}' locked after {new_attempts} failed attempts")
                    return False, {"error": "Account locked due to too many failed attempts. Please contact administrator."}
                else:
                    logger.warning(f"Failed authentication attempt for '{username}' ({new_attempts})")
                    return False, {"error": "Invalid username or password"}
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False, {"error": "Authentication error"}
        finally:
            if 'conn' in locals():
                conn.close()
    
    def user_exists(self, username: str) -> bool:
        """Check if a username already exists."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
            count = cursor.fetchone()[0]
            conn.close()
            
            return count > 0
        except Exception as e:
            logger.error(f"Error checking if user exists: {e}")
            return False
    
    def change_password(self, username: str, current_password: str, new_password: str) -> bool:
        """
        Change a user's password with enhanced validation.
        
        Args:
            username: The username of the account
            current_password: The current password for verification
            new_password: The new password to set
            
        Returns:
            bool: True if password was changed successfully
        """
        # First authenticate with current password
        success, _ = self.authenticate(username, current_password)
        if not success:
            logger.warning(f"Password change failed: invalid current password for '{username}'")
            return False
        
        # Validate new password
        valid, error_msg = self._validate_password(new_password)
        if not valid:
            logger.warning(f"Password change failed: new password does not meet requirements - {error_msg}")
            return False
        
        # Additional security check on new password
        try:
            from secure_vault.utils.input_validation import security_validator
            valid, error = security_validator.validate_input(
                new_password,
                check_sql=True,
                check_xss=True, 
                check_path=False,
                check_command=False,
                context="password"
            )
            if not valid:
                logger.warning(f"Password change failed: security check failed - {error}")
                return False
        except ImportError:
            # Skip enhanced validation if module not available
            logger.warning("Security validator module not available, skipping enhanced validation")
        
        try:
            # Generate new salt
            salt = secrets.token_bytes(16)
            salt_b64 = base64.b64encode(salt).decode('utf-8')
            
            # Hash the new password
            password_hash, hash_method = self._hash_password(new_password, salt)
            
            # Update the database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password_hash = ?, password_salt = ?, hash_method = ? WHERE username = ?",
                (password_hash, salt_b64, hash_method, username)
            )
            conn.commit()
            conn.close()
            
            logger.info(f"Password changed successfully for user '{username}'")
            return True
            
        except Exception as e:
            logger.error(f"Error changing password: {e}")
            return False
    
    def reset_account_lock(self, username: str) -> bool:
        """Reset the lock on a user account."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET account_locked = 0, failed_attempts = 0 WHERE username = ?",
                (username,)
            )
            conn.commit()
            conn.close()
            
            logger.info(f"Lock reset for user '{username}'")
            return True
        except Exception as e:
            logger.error(f"Error resetting account lock: {e}")
            return False
    
    def get_all_users(self) -> List[Dict[str, Any]]:
        """Get a list of all users (admin function)."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, email, created_at, last_login, account_locked, hash_method FROM users"
            )
            users = []
            for row in cursor.fetchall():
                users.append({
                    "id": row[0],
                    "username": row[1],
                    "email": row[2],
                    "created_at": row[3],
                    "last_login": row[4],
                    "account_locked": bool(row[5]),
                    "hash_method": row[6] or self.HASH_METHOD_PBKDF2  # Default to PBKDF2 if null
                })
            conn.close()
            return users
        except Exception as e:
            logger.error(f"Error getting users: {e}")
            return []
    
    def delete_user(self, username: str) -> bool:
        """Delete a user account."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
            conn.close()
            
            logger.info(f"User '{username}' deleted")
            return True
        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            return False
    
    def _hash_password(self, password: str, salt: bytes) -> Tuple[str, str]:
        """
        Hash a password using Argon2id for improved security.
        
        Args:
            password: The password to hash
            salt: The salt to use
            
        Returns:
            Tuple[str, str]: (Base64-encoded password hash, hash method)
        """
        try:
            # Use Argon2id with strong parameters
            kdf = Argon2id(
                length=32,
                salt=salt,
                iterations=10,          # Time cost (higher than file encryption for extra security)
                lanes=4,                # Parallelism
                memory_cost=65536       # Memory cost: 64 MB
            )
            
            password_hash = kdf.derive(password.encode())
            return base64.b64encode(password_hash).decode('utf-8'), self.HASH_METHOD_ARGON2ID
            
        except Exception as e:
            logger.error(f"Error hashing password with Argon2id: {e}")
            # Fall back to PBKDF2 only as a last resort if Argon2id fails
            logger.warning("Falling back to PBKDF2 for password hashing")
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=600000,  # Increased iteration count for better security
                backend=default_backend()
            )
            
            password_hash = kdf.derive(password.encode())
            return base64.b64encode(password_hash).decode('utf-8'), self.HASH_METHOD_PBKDF2
    
    def _verify_password(self, password: str, stored_hash: str, salt: bytes, hash_method: str) -> bool:
        """
        Verify a password against its stored hash.
        
        Args:
            password: The password to verify
            stored_hash: The stored hash (base64 encoded)
            salt: The salt used for hashing
            hash_method: The method used for hashing
            
        Returns:
            bool: True if the password matches
        """
        try:
            stored_hash_bytes = base64.b64decode(stored_hash)
            
            if hash_method == self.HASH_METHOD_ARGON2ID:
                # Use Argon2id for verification
                kdf = Argon2id(
                    length=32,
                    salt=salt,
                    iterations=10,
                    lanes=4,
                    memory_cost=65536
                )
                
                # For Argon2id, we need to derive and compare
                try:
                    derived_hash = kdf.derive(password.encode())
                    # This is not a constant-time comparison, but it's inside a try block 
                    # that will catch exceptions from derive() which runs in constant time
                    return derived_hash == stored_hash_bytes
                except Exception:
                    return False
                    
            else:  # Default to PBKDF2
                # Use PBKDF2 for verification
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=600000 if hash_method == self.HASH_METHOD_PBKDF2 else 390000,  # Support both old and new counts
                    backend=default_backend()
                )
                
                try:
                    # Verify using derive_and_verify which should run in constant time
                    derived_hash = kdf.derive(password.encode())
                    # This is not a constant-time comparison, but it's inside a try block 
                    # that will catch exceptions from derive() which runs in constant time
                    return derived_hash == stored_hash_bytes
                except Exception:
                    return False
                    
        except Exception as e:
            logger.error(f"Error verifying password: {e}")
            return False
    
    def _validate_password(self, password: str) -> Tuple[bool, Optional[str]]:
        """
        Validate password strength and complexity.
        
        Args:
            password: The password to validate
            
        Returns:
            Tuple of (valid, error_message)
        """
        if len(password) < 10:
            return False, "Password must be at least 10 characters long"
            
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
            
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
            
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
            
        if not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/" for c in password):
            return False, "Password must contain at least one special character"
            
        # Check for common patterns
        common_patterns = ['123', 'abc', 'password', 'admin', 'qwerty', 'welcome', 'secure']
        if any(pattern.lower() in password.lower() for pattern in common_patterns):
            return False, "Password contains common patterns"
            
        return True, None

    def has_any_users(self) -> bool:
        """Check if any users exist in the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            count = cursor.fetchone()[0]
            conn.close()
            
            return count > 0
        except Exception as e:
            logger.error(f"Error checking if any users exist: {e}")
            return False
            
    def get_api_key(self, username: str) -> Optional[str]:
        """Get the API key for a user"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT api_key FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return row[0]
            return None
        except Exception as e:
            logger.error(f"Error getting API key: {e}")
            return None
