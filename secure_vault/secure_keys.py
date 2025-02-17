"""
Secure key management utilities
"""

import os
from pathlib import Path
import json
import logging
from typing import Optional, Tuple
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import base64
from .secure_memory import SecureString, SecureBytes, ProtectedMemory
from .secure_files import SecureFile

logger = logging.getLogger(__name__)

class KeyEncryption:
    """
    Handles encryption of sensitive keys
    """
    def __init__(self, master_password: str):
        self._master_key = self._derive_master_key(master_password)
        self._fernet = Fernet(self._master_key)

    def _derive_master_key(self, password: str) -> bytes:
        """Derive master key from password"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_key(self, key_data: bytes) -> bytes:
        """Encrypt a key"""
        return self._fernet.encrypt(key_data)

    def decrypt_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt a key"""
        return self._fernet.decrypt(encrypted_key)

    def __del__(self):
        # Secure cleanup
        if hasattr(self, '_master_key'):
            self._master_key = os.urandom(len(self._master_key))
            del self._master_key

class SecureKeyStorage:
    """
    Manages secure storage of cryptographic keys
    """
    def __init__(self, storage_path: Path, master_password: str):
        self.storage_path = Path(storage_path)
        self._key_encryption = KeyEncryption(master_password)
        self._keys = {}
        self._load_keys()

    def _load_keys(self):
        """Load encrypted keys from storage"""
        if not self.storage_path.exists():
            return

        with SecureFile(self.storage_path) as f:
            try:
                data = json.load(f)
                for key_id, encrypted_key in data.items():
                    self._keys[key_id] = base64.b64decode(encrypted_key)
            except Exception as e:
                logger.error(f"Failed to load keys: {e}")

    def _save_keys(self):
        """Save encrypted keys to storage"""
        data = {
            key_id: base64.b64encode(encrypted_key).decode()
            for key_id, encrypted_key in self._keys.items()
        }
        
        with SecureFile(self.storage_path) as f:
            json.dump(data, f)

    def store_key(self, key_id: str, key_data: bytes) -> bool:
        """Store a key securely"""
        try:
            encrypted_key = self._key_encryption.encrypt_key(key_data)
            self._keys[key_id] = encrypted_key
            self._save_keys()
            return True
        except Exception as e:
            logger.error(f"Failed to store key: {e}")
            return False

    def retrieve_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve a key"""
        try:
            encrypted_key = self._keys.get(key_id)
            if not encrypted_key:
                return None
            return self._key_encryption.decrypt_key(encrypted_key)
        except Exception as e:
            logger.error(f"Failed to retrieve key: {e}")
            return None

    def delete_key(self, key_id: str) -> bool:
        """Securely delete a key"""
        try:
            if key_id in self._keys:
                del self._keys[key_id]
                self._save_keys()
            return True
        except Exception as e:
            logger.error(f"Failed to delete key: {e}")
            return False

class KeyRotation:
    """
    Handles key rotation and lifecycle
    """
    def __init__(self, storage: SecureKeyStorage, rotation_period: timedelta = timedelta(days=30)):
        self.storage = storage
        self.rotation_period = rotation_period

    def create_key_pair(self) -> Tuple[bytes, bytes]:
        """Create a new key pair"""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=cryptography.hazmat.primitives.serialization.Encoding.Raw,
            format=cryptography.hazmat.primitives.serialization.PrivateFormat.Raw,
            encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=cryptography.hazmat.primitives.serialization.Encoding.Raw,
            format=cryptography.hazmat.primitives.serialization.PublicFormat.Raw
        )
        
        return private_bytes, public_bytes

    def rotate_keys(self):
        """Perform key rotation"""
        try:
            # Generate new keys
            private_key, public_key = self.create_key_pair()
            
            # Generate unique key ID
            key_id = datetime.utcnow().isoformat()
            
            # Store new keys
            self.storage.store_key(f"{key_id}_private", private_key)
            self.storage.store_key(f"{key_id}_public", public_key)
            
            # Mark as active
            self.storage.store_key("active_key_id", key_id.encode())
            
            logger.info("Key rotation completed successfully")
            return True
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
            return False

    def get_active_keys(self) -> Tuple[Optional[bytes], Optional[bytes]]:
        """Get currently active keys"""
        try:
            active_key_id = self.storage.retrieve_key("active_key_id")
            if not active_key_id:
                return None, None
                
            key_id = active_key_id.decode()
            private_key = self.storage.retrieve_key(f"{key_id}_private")
            public_key = self.storage.retrieve_key(f"{key_id}_public")
            
            return private_key, public_key
        except Exception as e:
            logger.error(f"Failed to retrieve active keys: {e}")
            return None, None

    def cleanup_old_keys(self):
        """Remove expired keys"""
        try:
            active_key_id = self.storage.retrieve_key("active_key_id")
            if not active_key_id:
                return
                
            current_key_date = datetime.fromisoformat(active_key_id.decode())
            
            # Find and remove old keys
            for key_id in list(self.storage._keys.keys()):
                if not (key_id.endswith('_private') or key_id.endswith('_public')):
                    continue
                    
                try:
                    key_date = datetime.fromisoformat(key_id.split('_')[0])
                    if current_key_date - key_date > self.rotation_period:
                        self.storage.delete_key(key_id)
                except ValueError:
                    continue
                    
            logger.info("Old keys cleaned up successfully")
        except Exception as e:
            logger.error(f"Failed to cleanup old keys: {e}")

class SecureKeyManager:
    """
    High-level interface for key management
    """
    def __init__(self, storage_path: Path, master_password: str):
        self.storage = SecureKeyStorage(storage_path, master_password)
        self.rotation = KeyRotation(self.storage)
        self._initialize_keys()

    def _initialize_keys(self):
        """Initialize key set if needed"""
        active_keys = self.rotation.get_active_keys()
        if not active_keys[0]:  # No active private key
            self.rotation.rotate_keys()

    def get_signing_key(self) -> Optional[Ed25519PrivateKey]:
        """Get current signing key"""
        private_bytes, _ = self.rotation.get_active_keys()
        if not private_bytes:
            return None
            
        return Ed25519PrivateKey.from_private_bytes(private_bytes)

    def rotate_if_needed(self) -> bool:
        """Rotate keys if rotation period has elapsed"""
        try:
            active_key_id = self.storage.retrieve_key("active_key_id")
            if not active_key_id:
                return self.rotation.rotate_keys()
                
            key_date = datetime.fromisoformat(active_key_id.decode())
            if datetime.utcnow() - key_date > self.rotation.rotation_period:
                return self.rotation.rotate_keys()
                
            return True
        except Exception as e:
            logger.error(f"Failed to check key rotation: {e}")
            return False

    def cleanup(self):
        """Cleanup and secure deletion of old keys"""
        self.rotation.cleanup_old_keys()

    def __del__(self):
        """Ensure secure cleanup"""
        self.cleanup()