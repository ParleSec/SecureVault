"""
Script to unlock a SecureVault account.
Run this script from the command line with the username as an argument.
"""

import sys
from pathlib import Path
from secure_vault.users.user_manager import UserManager

def unlock_account(username):
    # Path to the user database
    data_dir = Path("./secure_vault_data")
    users_dir = data_dir / "users"
    db_path = users_dir / "users.db"
    
    # Check if database exists
    if not db_path.exists():
        print(f"Error: User database not found at {db_path}")
        return False
    
    # Create user manager and unlock account
    user_manager = UserManager(str(db_path))
    
    # Check if user exists
    if not user_manager.user_exists(username):
        print(f"Error: User '{username}' not found")
        return False
    
    # Reset the lock
    success = user_manager.reset_account_lock(username)
    
    if success:
        print(f"Account '{username}' has been successfully unlocked!")
        return True
    else:
        print(f"Error: Failed to unlock account '{username}'")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python unlock_account.py <username>")
        sys.exit(1)
    
    username = sys.argv[1]
    if unlock_account(username):
        sys.exit(0)
    else:
        sys.exit(1)