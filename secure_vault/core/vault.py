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
        return json.dumps({
            "nonce": self.nonce,
            "salt": self.salt,
            "ciphertext": self.ciphertext,
            "signature": self.signature,
            "public_key": self.public_key
        })
    
    @classmethod
    def model_validate_json(cls, json_str):
        """Create from JSON string"""
        data = json.loads(json_str)
        return cls(
            nonce=data["nonce"],
            salt=data["salt"],
            ciphertext=data["ciphertext"],
            signature=data["signature"],
            public_key=data["public_key"]
        )

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
        
        # Set up key file path
        if key_file is None:
            # Use script directory for key file
            script_dir = Path(__file__).parent.absolute()
            self.key_file = script_dir / "crypto_key.json"
            self.password_file = script_dir / ".master_password"
        else:
            self.key_file = Path(key_file)
            self.password_file = Path(key_file).parent / ".master_password"
            
        # Create key file directory if it doesn't exist
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Get or generate master password
        self.master_password = self._get_master_password(master_password)
        
        # Initialize signing key
        self._signing_key = self._load_or_create_key()

    def _get_master_password(self, master_password: str = None) -> str:
        """
        Get the master password from parameter, environment variable, or generate a new one.
        
        Args:
            master_password (str, optional): Master password provided during initialization.
            
        Returns:
            str: The master password to use for key encryption.
        """
        # First, try using the provided password
        if master_password:
            return master_password
            
        # Second, try environment variable
        env_password = os.getenv('VAULT_MASTER_PASSWORD')
        if env_password:
            return env_password
            
        # Third, try reading from password file
        if self.password_file.exists():
            try:
                with open(self.password_file, 'r') as f:
                    return f.read().strip()
            except Exception as e:
                self.logger.warning("Failed to read master password file", error=str(e))
                
        # Finally, generate a new secure random password
        new_password = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
        try:
            # Save password with restricted permissions
            with open(self.password_file, 'w') as f:
                f.write(new_password)
                
            # Set secure permissions on the password file
            try:
                if os.name == 'posix':  # Unix-like systems
                    import stat
                    os.chmod(self.password_file, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write only
            except Exception as e:
                self.logger.warning("Failed to set permissions on password file", error=str(e))
                
            self.logger.info("Generated new master password and saved to file", path=str(self.password_file))
            return new_password
        except Exception as e:
            self.logger.warning("Failed to save master password", error=str(e))
            # Return the generated password even if we couldn't save it
            return new_password

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
        """Load existing key or create a new one, with encryption"""
        try:
            if self.key_file.exists():
                with open(self.key_file, 'r') as f:
                    key_data = json.load(f)
                    
                    # Extract encrypted data and metadata
                    encrypted_private_key = key_data['encrypted_private_key']
                    key_salt_b64 = key_data['key_salt']
                    key_salt = base64.b64decode(key_salt_b64)
                    
                    # Derive key encryption key
                    fernet_key, _ = self._derive_key_encryption_key(self.master_password, key_salt)
                    
                    # Decrypt the private key
                    try:
                        fernet = Fernet(fernet_key)
                        private_bytes = fernet.decrypt(encrypted_private_key.encode('utf-8'))
                        return Ed25519PrivateKey.from_private_bytes(private_bytes)
                    except Exception as e:
                        self.logger.error("Failed to decrypt private key - password may be incorrect", error=str(e))
                        raise ValueError("Failed to decrypt signing key - master password may be incorrect")
        except Exception as e:
            self.logger.warning("Failed to load key, creating new one", error=str(e))

        # Create new key
        key = Ed25519PrivateKey.generate()
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
            fernet = Fernet(fernet_key)
            encrypted_private_key = fernet.encrypt(private_bytes)
            
            # Save the encrypted key and metadata
            key_data = {
                'encrypted_private_key': encrypted_private_key.decode('utf-8'),
                'key_salt': base64.b64encode(key_salt).decode('utf-8'),
                # Store public key in cleartext for verification purposes
                'public_key': base64.b64encode(
                    key.public_key().public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                ).decode('utf-8')
            }
            
            with open(self.key_file, 'w') as f:
                json.dump(key_data, f)
                
            # Set secure permissions on key file
            try:
                if os.name == 'posix':  # Unix-like systems
                    import stat
                    os.chmod(self.key_file, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write only
            except Exception as e:
                self.logger.warning("Failed to set permissions on key file", error=str(e))
                
        except Exception as e:
            self.logger.warning("Failed to save key", error=str(e))

        return key

    def derive_key(self, password: str, salt: bytes = None) -> bytes:
        """Derive encryption key from password using Argon2id"""
        if salt:
            self.salt = salt
            
        kdf = Argon2id(
            length=32,
            salt=self.salt,
            iterations=10,          # Increased from 4 to 10 for better security
            lanes=4,                # equivalent to parallelism in some versions
            memory_cost=65536       # memory size in kB
        )
        return kdf.derive(password.encode())

    def encrypt(self, data: bytes, password: str) -> EncryptedData:
        """Encrypt data using AES-256-GCM with authenticated encryption"""
        try:
            nonce = os.urandom(12)
            key = self.derive_key(password)
            aesgcm = AESGCM(key)
            
            ciphertext = aesgcm.encrypt(nonce, data, None)
            signature = self._signing_key.sign(ciphertext)

            # Get public key for verification
            public_key_bytes = self._signing_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            encrypted_data = EncryptedData(
                nonce=base64.b64encode(nonce).decode('utf-8'),
                salt=base64.b64encode(self.salt).decode('utf-8'),
                ciphertext=base64.b64encode(ciphertext).decode('utf-8'),
                signature=base64.b64encode(signature).decode('utf-8'),
                public_key=base64.b64encode(public_key_bytes).decode('utf-8')
            )
            
            self.logger.info("data_encrypted", bytes_encrypted=len(data))
            return encrypted_data
            
        except Exception as e:
            self.logger.error("encryption_failed", error=str(e))
            raise

    def decrypt(self, encrypted_data: EncryptedData, password: str) -> bytes:
        """Decrypt data and verify its signature"""
        try:
            nonce = base64.b64decode(encrypted_data.nonce)
            salt = base64.b64decode(encrypted_data.salt)
            ciphertext = base64.b64decode(encrypted_data.ciphertext)
            signature = base64.b64decode(encrypted_data.signature)
            public_key_bytes = base64.b64decode(encrypted_data.public_key)
            
            # Verify using the public key from the encrypted data
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            try:
                public_key.verify(signature, ciphertext)
            except Exception as e:
                self.logger.error("signature_verification_failed", error=str(e))
                raise ValueError("Invalid signature - file may have been tampered with")
            
            # Derive key and decrypt
            key = self.derive_key(password, salt)
            aesgcm = AESGCM(key)
            
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            self.logger.info("data_decrypted", bytes_decrypted=len(plaintext))
            return plaintext
            
        except InvalidTag:
            self.logger.error("decryption_failed", error="Invalid password or corrupted data")
            raise ValueError("Invalid password or corrupted data")
        except Exception as e:
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
            
            with open(self.key_file, 'w') as f:
                json.dump(key_data, f)
                
            # Update password file if it exists
            if self.password_file.exists():
                with open(self.password_file, 'w') as f:
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
        self.crypto = CryptoManager(master_password=master_password)
        self.logger = logger.bind(component="vault")
        
        # Ensure the vault directory exists.
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        
    def encrypt_file(self, file_path: str, password: str) -> Path:
        """
        Encrypt a file and store it in the vault.

        The encrypted file will retain its original file name (with extension)
        and have '.vault' appended. For example, 'document.pdf' becomes
        'document.pdf.vault'.

        Args:
            file_path (str): Path to the file to encrypt.
            password (str): Password used for encryption.

        Returns:
            Path: Path to the encrypted file.

        Raises:
            FileNotFoundError: If the input file does not exist.
            Exception: For any encryption error.
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Read file content.
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Encrypt data using the CryptoManager.
            encrypted_data = self.crypto.encrypt(data, password)
            
            # Retain the original file name and append '.vault'.
            encrypted_filename = f"{file_path.name}.vault"
            encrypted_path = self.vault_dir / encrypted_filename
            
            # Write the encrypted data as JSON.
            with open(encrypted_path, 'w') as f:
                f.write(encrypted_data.model_dump_json())
            
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
        Decrypt a file from the vault.

        The decrypted file will be written to the specified output path.
        It is assumed that the encrypted file's name ends with '.vault';
        the caller is responsible for restoring the original name if desired.

        Args:
            encrypted_path (str): Path to the encrypted file.
            output_path (str): Path where the decrypted file should be saved.
            password (str): Password used for decryption.

        Returns:
            Path: Path to the decrypted file.

        Raises:
            Exception: If decryption fails.
        """
        try:
            encrypted_path = Path(encrypted_path)
            output_path = Path(output_path)
            
            # Read the encrypted JSON data.
            with open(encrypted_path, 'r') as f:
                encrypted_data = EncryptedData.model_validate_json(f.read())
            
            # Decrypt the data.
            decrypted_data = self.crypto.decrypt(encrypted_data, password)
            
            # Create parent directory if necessary
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write the decrypted data.
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.logger.info("file_decrypted",
                             source=str(encrypted_path),
                             destination=str(output_path),
                             size=len(decrypted_data))
            
            return output_path
            
        except Exception as e:
            self.logger.error("file_decryption_failed",
                              file=str(encrypted_path),
                              error=str(e))
            raise

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