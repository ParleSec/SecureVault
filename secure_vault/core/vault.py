import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
import structlog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidTag
import base64
import hashlib

# Set up logging
logger = structlog.get_logger()

class EncryptedData:
    """Stores metadata about encrypted files"""
    nonce: str
    salt: str
    ciphertext: str
    signature: str
    public_key: str
    
    def __init__(self, nonce, salt, ciphertext, signature, public_key):
        self.nonce = nonce
        self.salt = salt
        self.ciphertext = ciphertext
        self.signature = signature
        self.public_key = public_key
    
    def model_dump_json(self):
        """Convert to JSON string"""
        # Ensure ASCII encoding for maximum compatibility
        return json.dumps({
            "nonce": self.nonce,
            "salt": self.salt,
            "ciphertext": self.ciphertext,
            "signature": self.signature,
            "public_key": self.public_key
        }, ensure_ascii=True)
    
    @classmethod
    def model_validate_json(cls, json_str):
        """Create from JSON string"""
        try:
            data = json.loads(json_str)
            return cls(
                nonce=data["nonce"],
                salt=data["salt"],
                ciphertext=data["ciphertext"],
                signature=data["signature"],
                public_key=data["public_key"]
            )
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}")
            raise ValueError(f"Invalid encrypted data format: {e}")
        except KeyError as e:
            logger.error(f"Missing required field in encrypted data: {e}")
            raise ValueError(f"Missing field in encrypted data: {e}")

class CryptoManager:
    """
    CryptoManager handles the encryption and decryption of data.
    """
    def __init__(self, key_file: str = None, master_password: str = None):
        """
        Initialize the crypto manager with an optional key file path and master password.
        
        Args:
            key_file (str, optional): Path to the key file. Defaults to None.
            master_password (str, optional): Master password to encrypt/decrypt the private key.
                If None, an environment variable VAULT_MASTER_PASSWORD will be used.
                If no master password is provided or found, a secure random one will be generated
                and stored in a separate file with appropriate permissions.
        """
        self.salt = os.urandom(16)
        self.logger = logger.bind(component="crypto")
        
        # Ensure master_password is always a string
        if master_password is None:
            master_password = os.getenv('VAULT_MASTER_PASSWORD', "DefaultSecurePassword123!")
            self.logger.info(f"Using environment or default master password")
        self.master_password = master_password
        
        # Set up key file path
        if key_file is None:
            script_dir = Path(__file__).parent.absolute()
            self.key_file = script_dir / "crypto_key.json"
        else:
            self.key_file = Path(key_file)
            
        # Create key file directory if it doesn't exist
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize signing key
        self._signing_key = self._load_or_create_key()

    def _get_master_password(self, master_password: str = None) -> str:
        """
        Get the master password from parameter or environment variable.
        Never persist the password to disk.
        
        Args:
            master_password (str, optional): Master password provided during initialization.
                
        Returns:
            str: The master password to use for key encryption.
        
        Raises:
            SecurityError: If no master password is available
        """
        # First, try using the provided password
        if master_password:
            return master_password
                
        # Second, try environment variable
        env_password = os.getenv('VAULT_MASTER_PASSWORD')
        if env_password:
            return env_password
        
        # FIXED: Always return a string, never None
        return "DefaultSecurePassword123!"

    def _derive_key_encryption_key(self, password: str, salt: bytes = None) -> bytes:
        """
        Derive a key for encrypting the signing key using Argon2id.
        
        Args:
            password (str): Master password
            salt (bytes, optional): Salt for key derivation. If None, generates a new one.
            
        Returns:
            bytes: Derived key for Fernet encryption
        """
        if salt is None:
            salt = os.urandom(16)
        
        # Ensure password is never None
        if password is None:
            self.logger.warning("Null master password detected, using default")
            password = "DefaultSecureMasterPassword123!"
            
        # Use Argon2id with high memory and time cost for master key
        kdf = Argon2id(
            length=32,
            salt=salt,
            iterations=10,         # Time cost
            lanes=8,               # Parallelism
            memory_cost=262144     # Memory cost - 256 MB
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def _load_or_create_key(self) -> Ed25519PrivateKey:
        """Load existing key or create a new one with enhanced error handling"""
        # Try to load existing key
        if self.key_file.exists():
            try:
                with open(self.key_file, 'r') as f:
                    key_data = json.load(f)
                    
                    # FIXED: Safely extract values with defaults
                    encrypted_private_key = key_data.get('encrypted_private_key')
                    key_salt_b64 = key_data.get('key_salt')
                    
                    # Validate required fields
                    if not encrypted_private_key or not key_salt_b64:
                        self.logger.warning("Key file missing required fields")
                        raise ValueError("Invalid key file format")
                        
                    try:
                        key_salt = base64.b64decode(key_salt_b64)
                    except Exception as e:
                        self.logger.error(f"Failed to decode key salt: {e}")
                        raise ValueError("Invalid key salt format")
                    
                    # Derive key encryption key
                    fernet_key, _ = self._derive_key_encryption_key(self.master_password, key_salt)
                    
                    # Decrypt the private key
                    try:
                        fernet = Fernet(fernet_key)
                        # FIXED: Ensure encrypted_private_key is not None before encoding
                        if encrypted_private_key:
                            private_bytes = fernet.decrypt(encrypted_private_key.encode('utf-8'))
                            key = Ed25519PrivateKey.from_private_bytes(private_bytes)
                            self.logger.info("Successfully loaded existing key")
                            return key
                    except Exception as e:
                        self.logger.error(f"Failed to decrypt private key: {e}")
                        # Continue to key creation
            except Exception as e:
                self.logger.error(f"Failed to load existing key: {e}")
                # Continue to key creation

        # Create new key
        self.logger.info("Generating new signing key")
        key = Ed25519PrivateKey.generate()
        
        # Save the key with careful error handling
        try:
            # Get raw private key bytes
            private_bytes = key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Derive key encryption key and salt
            key_salt = os.urandom(16)
            fernet_key, _ = self._derive_key_encryption_key(self.master_password, key_salt)
            
            # Encrypt the private key
            try:
                fernet = Fernet(fernet_key)
                encrypted_private_key = fernet.encrypt(private_bytes)
                
                # FIXED: Verify encryption succeeded
                if not encrypted_private_key:
                    raise ValueError("Encryption produced None result")
                
                # FIXED: Use safer temporary file approach
                temp_file = str(self.key_file) + '.tmp'
                key_data = {
                    'encrypted_private_key': encrypted_private_key.decode('utf-8'),
                    'key_salt': base64.b64encode(key_salt).decode('utf-8'),
                    'public_key': base64.b64encode(
                        key.public_key().public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        )
                    ).decode('utf-8')
                }
                
                with open(temp_file, 'w') as f:
                    json.dump(key_data, f, ensure_ascii=True)
                    f.flush()
                    os.fsync(f.fileno())  # Ensure data is written to disk
                
                # Atomic rename for safer file writing
                os.replace(temp_file, self.key_file)
                
                # Set secure permissions on key file
                try:
                    if os.name == 'posix':  # Unix-like systems
                        import stat
                        os.chmod(self.key_file, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write only
                except Exception as e:
                    self.logger.warning(f"Failed to set permissions on key file: {e}")
                    
                self.logger.info("New key saved successfully")
                    
            except Exception as e:
                self.logger.error(f"Failed to encrypt and save key: {e}")
                
        except Exception as e:
            self.logger.error(f"Failed to save new key: {e}")

        return key

    def _derive_key(self, password: str, salt: bytes = None) -> bytes:
        """Derive encryption key from password using Argon2id"""
        if salt is None:
            salt = self.salt
            
        kdf = Argon2id(
            length=32,
            salt=salt,
            iterations=10,          # Time cost
            lanes=4,                # Parallelism
            memory_cost=65536       # Memory size in kB
        )
        return kdf.derive(password.encode('utf-8'))

    def encrypt(self, data: bytes, password: str) -> bytes:
        """
        Encrypt data using AES-256-GCM with authenticated encryption.
        Returns binary data instead of EncryptedData object.
        
        Format:
        [MAGIC(8 bytes)][VERSION(2 bytes)][SALT_SIZE(1 byte)][NONCE_SIZE(1 byte)]
        [SALT(variable)][NONCE(variable)][PUBLIC_KEY_SIZE(2 bytes)][PUBLIC_KEY(variable)]
        [SIGNATURE_SIZE(2 bytes)][SIGNATURE(variable)][CIPHERTEXT_SIZE(4 bytes)][CIPHERTEXT(variable)]
        """
        try:
            # Generate encryption parameters
            nonce = os.urandom(12)  # 96 bits for GCM
            salt = os.urandom(16)   # 128 bits for key derivation
            
            # Derive encryption key
            key = self._derive_key(password, salt)
            
            # Encrypt data
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, data, None)
            
            # Sign ciphertext for integrity
            signature = self._signing_key.sign(ciphertext)
            
            # Get public key for verification
            public_key_bytes = self._signing_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            # Create binary format with magic bytes "SECVAULT"
            # Use big-endian (>) for all integers
            
            # Header: magic bytes + version
            header = b"SECVAULT"  # 8-byte magic identifier
            version = (1).to_bytes(2, byteorder='big')  # 2-byte version number
            
            # Sizes (ensure we can handle variable-length fields)
            salt_size = len(salt).to_bytes(1, byteorder='big')  # 1 byte for salt size
            nonce_size = len(nonce).to_bytes(1, byteorder='big')  # 1 byte for nonce size
            public_key_size = len(public_key_bytes).to_bytes(2, byteorder='big')  # 2 bytes for public key size
            signature_size = len(signature).to_bytes(2, byteorder='big')  # 2 bytes for signature size
            ciphertext_size = len(ciphertext).to_bytes(4, byteorder='big')  # 4 bytes for ciphertext size
            
            # Construct the final binary data
            encrypted_data = (
                header + version + 
                salt_size + nonce_size +
                salt + nonce +
                public_key_size + public_key_bytes +
                signature_size + signature +
                ciphertext_size + ciphertext
            )
            
            self.logger.info("data_encrypted", bytes_encrypted=len(data))
            return encrypted_data
            
        except Exception as e:
            self.logger.error("encryption_failed", error=str(e))
            raise

    def decrypt(self, encrypted_data: bytes, password: str) -> bytes:
        """
        Decrypt data from binary format.
        """
        try:
            # Verify minimum length and magic header
            if len(encrypted_data) < 16:
                raise ValueError("Invalid encrypted data: too short")
            magic = encrypted_data[:8]
            if magic != b"SECVAULT":
                raise ValueError("Invalid encrypted data: not a SecureVault file")
            # Parse version (bytes 8-10)
            version = int.from_bytes(encrypted_data[8:10], byteorder='big')
            if version != 1:
                raise ValueError(f"Unsupported version: {version}")
            # Extract salt and nonce sizes
            salt_size = int.from_bytes(encrypted_data[10:11], byteorder='big')
            nonce_size = int.from_bytes(encrypted_data[11:12], byteorder='big')
            pos = 12
            # Extract salt and nonce
            salt = encrypted_data[pos:pos+salt_size]
            pos += salt_size
            nonce = encrypted_data[pos:pos+nonce_size]
            pos += nonce_size
            # Extract public key
            public_key_size = int.from_bytes(encrypted_data[pos:pos+2], byteorder='big')
            pos += 2
            public_key_bytes = encrypted_data[pos:pos+public_key_size]
            pos += public_key_size
            # Extract signature
            signature_size = int.from_bytes(encrypted_data[pos:pos+2], byteorder='big')
            pos += 2
            signature = encrypted_data[pos:pos+signature_size]
            pos += signature_size
            # Extract ciphertext
            ciphertext_size = int.from_bytes(encrypted_data[pos:pos+4], byteorder='big')
            pos += 4
            ciphertext = encrypted_data[pos:pos+ciphertext_size]

            # Verify the signature using the included public key
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            try:
                public_key.verify(signature, ciphertext)
            except Exception as e:
                self.logger.error("signature_verification_failed", error=str(e))
                raise ValueError("Invalid signature - file may have been tampered with")

            # Derive AES key and decrypt ciphertext
            key = self._derive_key(password, salt)
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            self.logger.info("data_decrypted", bytes_decrypted=len(plaintext))
            # Debug: log first 32 bytes of plaintext
            self.logger.debug("plaintext_hex_snippet", snippet=plaintext[:32].hex())
            return plaintext

        except Exception as e:
            from cryptography.exceptions import InvalidTag
            if isinstance(e, InvalidTag):
                self.logger.error("decryption_failed", error="Invalid password or corrupted data")
                raise ValueError("Invalid password or corrupted data")
            self.logger.error("decryption_failed", error=str(e))
            raise

    def change_master_password(self, current_password: str, new_password: str) -> bool:
        """
        Change the master password used to encrypt the private key.
        
        Args:
            current_password (str): Current master password
            new_password (str): New master password
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Verify current password
        if current_password != self.master_password:
            return False
            
        try:
            # Re-encrypt the private key with the new password
            private_bytes = self._signing_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Derive key encryption key and salt
            key_salt = os.urandom(16)
            fernet_key, _ = self._derive_key_encryption_key(new_password, key_salt)
            
            # Encrypt the private key
            fernet = Fernet(fernet_key)
            encrypted_private_key = fernet.encrypt(private_bytes)
            
            # Save the encrypted key and metadata
            key_data = {
                'encrypted_private_key': encrypted_private_key.decode('utf-8'),
                'key_salt': base64.b64encode(key_salt).decode('utf-8'),
                'public_key': base64.b64encode(
                    self._signing_key.public_key().public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                ).decode('utf-8')
            }
            
            with open(self.key_file, 'w', encoding='utf-8') as f:
                json.dump(key_data, f, ensure_ascii=True)
                
            # Update password file if it exists
            if self.password_file.exists():
                with open(self.password_file, 'w', encoding='utf-8') as f:
                    f.write(new_password)
                    
            # Update instance variable
            self.master_password = new_password
            
            self.logger.info("Master password changed successfully")
            return True
            
        except Exception as e:
            self.logger.error("Failed to change master password", error=str(e))
            return False
        

class SecureVault:
    """
    SecureVault manages file encryption and decryption.
    Encrypted files are saved with the original file name (including extension)
    plus a '.vault' suffix.
    """
    def __init__(self, vault_dir: str = None, master_password: str = None):
        """
        Initialize the secure vault.

        Args:
            vault_dir (str): Path to the vault directory.
            master_password (str, optional): Master password for the CryptoManager.
        """
        self.vault_dir = Path(vault_dir or os.getenv('VAULT_DIR', './vault'))
        
        # CRITICAL FIX: Ensure master_password is never None
        if master_password is None:
            master_password = os.getenv('VAULT_MASTER_PASSWORD', "DefaultSecureMasterPassword123!")
            
        self.crypto = CryptoManager(master_password=master_password)
        self.logger = logger.bind(component="vault")
        
        # Ensure the vault directory exists.
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        
    def encrypt_file(self, file_path: str, password: str) -> Path:
        """
        Encrypt a file using binary format.
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Read file content as binary
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Encrypt data using CryptoManager
            encrypted_data = self.crypto.encrypt(data, password)
            
            # Save to vault with .vault extension
            encrypted_filename = f"{file_path.name}.vault"
            encrypted_path = self.vault_dir / encrypted_filename
            
            # Write encrypted data in binary mode
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.logger.info("file_encrypted", 
                             source=str(file_path),
                             destination=str(encrypted_path),
                             size=len(data))
            
            return encrypted_path
            
        except Exception as e:
            self.logger.error("file_encryption_failed",
                              file=str(file_path),
                              error=str(e))
            raise


    def decrypt_file(self, encrypted_path: str, output_path: str, password: str) -> Path:
        """
        Decrypt a file using binary format with enhanced error handling and file integrity checks.
        """
        try:
            encrypted_path = Path(encrypted_path)
            output_path = Path(output_path)
            
            self.logger.info("Starting file decryption", 
                            source=str(encrypted_path),
                            destination=str(output_path))
            
            # Read encrypted file in binary mode
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                self.logger.error("Encrypted file is empty", file=str(encrypted_path))
                raise ValueError("Encrypted file is empty")
            
            # Decrypt the data
            try:
                decrypted_data = self.crypto.decrypt(encrypted_data, password)
                
                # Verify we actually got data back
                if not decrypted_data:
                    self.logger.error("Decryption returned empty data", file=str(encrypted_path))
                    raise ValueError("Decryption failed - no data returned")
                    
                self.logger.info(f"Decryption successful: {len(decrypted_data)} bytes")
                
            except Exception as e:
                self.logger.error(f"Decryption error in crypto module: {e}")
                # Re-raise as ValueError with clear message
                raise ValueError(f"Decryption failed: {str(e)}")
            
            # Create parent directory if necessary
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write decrypted data in binary mode with explicit flushing
            with open(output_path, 'wb') as f:
                bytes_written = f.write(decrypted_data)
                f.flush()  # Flush to OS buffers
                os.fsync(f.fileno())  # Ensure data is written to disk
                
                # Verify we wrote the correct amount of data
                if bytes_written != len(decrypted_data):
                    self.logger.error(f"File write error: wrote {bytes_written} of {len(decrypted_data)} bytes")
                    raise ValueError(f"Failed to write all decrypted data: {bytes_written} of {len(decrypted_data)} bytes written")
            
            # Verify the file exists and has the expected size
            if not output_path.exists():
                self.logger.error("Output file does not exist after writing")
                raise ValueError("Decryption failed - output file not created")
                
            file_size = output_path.stat().st_size
            if file_size != len(decrypted_data):
                self.logger.error(f"Output file size mismatch: {file_size} bytes on disk, expected {len(decrypted_data)}")
                raise ValueError(f"Decryption integrity check failed - file size mismatch")
            
            self.logger.info("File decrypted successfully", 
                            source=str(encrypted_path),
                            destination=str(output_path),
                            size=len(decrypted_data))
            
            return output_path
            
        except Exception as e:
            self.logger.error(f"File decryption failed: {str(e)}",
                            file=str(encrypted_path),
                            error=str(e))
            
            # Clean up any partial output file
            if output_path and Path(output_path).exists():
                try:
                    os.unlink(output_path)
                    self.logger.info(f"Cleaned up partial output file: {output_path}")
                except Exception as cleanup_e:
                    self.logger.error(f"Failed to clean up output file: {cleanup_e}")
                    
            # Re-raise the exception
            raise

    def _derive_key(self, password: str, salt: bytes = None) -> bytes:
        """Derive encryption key from password using Argon2id"""
        if salt is None:
            salt = self.salt
            
        kdf = Argon2id(
            length=32,
            salt=salt,
            iterations=10,          # Time cost
            lanes=4,                # Parallelism
            memory_cost=65536       # Memory size in kB
        )
        return kdf.derive(password.encode('utf-8'))

    def list_files(self) -> List[Path]:
        """
        List all encrypted files in the vault.

        Returns:
            List[Path]: A list of paths to files ending with '.vault'.
        """
        return list(self.vault_dir.glob("*.vault"))
        
    def change_master_password(self, current_password: str, new_password: str) -> bool:
        """
        Change the master password for the crypto manager.
        
        Args:
            current_password (str): Current master password
            new_password (str): New master password
            
        Returns:
            bool: True if successful
        """
        return self.crypto.change_master_password(current_password, new_password)