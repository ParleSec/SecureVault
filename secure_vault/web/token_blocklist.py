"""
TokenBlocklist - Persistent revoked token storage for SecureVault
"""
import sqlite3
import logging
from datetime import datetime, timezone
from typing import Optional
import json
import functools

logger = logging.getLogger(__name__)

# Create a global blocklist for tokens
_global_token_blocklist = set()

class TokenBlocklist:
    """
    Manages a persistent blocklist of revoked JWT tokens.
    Tokens are stored in an SQLite database to ensure they remain
    revoked even if the server restarts.
    """
    def __init__(self, db_path: str):
        """
        Initialize the token blocklist with the path to the database.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._ensure_table_exists()
        self._load_tokens_into_memory()
        
    def _ensure_table_exists(self):
        """Create the revoked_tokens table if it doesn't exist."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create the revoked_tokens table with appropriate schema
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                jti TEXT UNIQUE NOT NULL,
                token_signature TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                metadata TEXT
            )
            ''')
            
            # Create an index for faster lookups
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_token_signature ON revoked_tokens (token_signature)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_expires_at ON revoked_tokens (expires_at)')
            
            conn.commit()
            conn.close()
            logger.info("Token blocklist table initialized")
            
        except Exception as e:
            logger.error(f"Failed to create token blocklist table: {e}")
            raise
    
    def _load_tokens_into_memory(self):
        """Load all token signatures from the database into memory for faster checking"""
        global _global_token_blocklist
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT token_signature FROM revoked_tokens")
            signatures = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            # Update the global set
            _global_token_blocklist = set(signatures)
            logger.info(f"Loaded {len(_global_token_blocklist)} revoked tokens into memory")
        except Exception as e:
            logger.error(f"Failed to load tokens into memory: {e}")
    
    def add_token(self, token: str, payload: dict) -> bool:
        """
        Add a token to the blocklist.
        
        Args:
            token: The JWT token to revoke
            payload: The decoded token payload containing expiration data
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get token parts
            token_parts = token.split('.')
            if len(token_parts) != 3:
                logger.error("Invalid token format")
                return False
            
            # Token signature is the third part
            token_signature = token_parts[2]
            
            # Extract necessary info from payload
            jti = payload.get('jti')
            user_id = str(payload.get('sub', ''))
            expires_at = datetime.fromtimestamp(payload.get('exp', 0), tz=timezone.utc)
            
            # Additional metadata for audit/debugging
            metadata = json.dumps({
                'username': payload.get('username', ''),
                'revoked_by': user_id  # Same as subject (self-revocation)
            })
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO revoked_tokens (jti, token_signature, user_id, expires_at, metadata)
                VALUES (?, ?, ?, ?, ?)
                ''', 
                (jti, token_signature, user_id, expires_at.isoformat(), metadata)
            )
            conn.commit()
            conn.close()
            
            # Add to in-memory set
            global _global_token_blocklist
            _global_token_blocklist.add(token_signature)
            
            logger.info(f"Token revoked for user {user_id}")
            return True
            
        except sqlite3.IntegrityError:
            # Token already revoked
            logger.warning(f"Token already revoked (duplicate)")
            return True  # Still counts as success
            
        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            return False
    
    def is_revoked(self, token: str) -> bool:
        """
        Check if a token is revoked.
        
        Args:
            token: The JWT token to check
            
        Returns:
            bool: True if the token is revoked, False otherwise
        """
        try:
            # Get token signature (third part)
            token_parts = token.split('.')
            if len(token_parts) != 3:
                return False
            
            token_signature = token_parts[2]
            
            # First check the in-memory set (fast)
            global _global_token_blocklist
            if token_signature in _global_token_blocklist:
                return True
            
            # Double-check the database (more reliable but slower)
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM revoked_tokens WHERE token_signature = ?", 
                (token_signature,)
            )
            count = cursor.fetchone()[0]
            conn.close()
            
            # If found in database but not in memory, update memory
            if count > 0 and token_signature not in _global_token_blocklist:
                _global_token_blocklist.add(token_signature)
            
            return count > 0
            
        except Exception as e:
            logger.error(f"Error checking token revocation status: {e}")
            # Fail closed for security
            return True
    
    def cleanup_expired_tokens(self) -> int:
        """
        Remove expired tokens from the blocklist.
        
        Returns:
            int: Number of tokens removed
        """
        try:
            now = datetime.now(timezone.utc).isoformat()
            
            # Get the signatures that will be removed
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # First get the signatures to remove
            cursor.execute(
                "SELECT token_signature FROM revoked_tokens WHERE expires_at < ?", 
                (now,)
            )
            expired_signatures = [row[0] for row in cursor.fetchall()]
            
            # Then delete them
            cursor.execute(
                "DELETE FROM revoked_tokens WHERE expires_at < ?", 
                (now,)
            )
            removed_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            # Update in-memory set
            global _global_token_blocklist
            _global_token_blocklist -= set(expired_signatures)
            
            if removed_count > 0:
                logger.info(f"Removed {removed_count} expired tokens from blocklist")
            
            return removed_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired tokens: {e}")
            return 0

# Create simplified functions that don't rely on instance methods
def is_token_revoked(token: str) -> bool:
    """Global function to check if a token is revoked"""
    try:
        # Get token signature (third part)
        token_parts = token.split('.')
        if len(token_parts) != 3:
            return False
        
        token_signature = token_parts[2]
        
        # Check the in-memory set
        return token_signature in _global_token_blocklist
    except Exception as e:
        logger.error(f"Error in global token check: {e}")
        return True  # Fail closed