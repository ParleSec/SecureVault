import os
import json
from pathlib import Path
from typing import Dict, List
import structlog
from .crypto import CryptoManager, EncryptedData

logger = structlog.get_logger()

class SecureVault:
    def __init__(self, vault_dir: str = None):
        self.vault_dir = Path(vault_dir or os.getenv('VAULT_DIR', './vault'))
        self.crypto = CryptoManager()
        self.logger = logger.bind(component="vault")
        
        # Create vault directory if it doesn't exist
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        
    def encrypt_file(self, file_path: str, password: str) -> Path:
        """Encrypt a file and store it in the vault"""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Read file content
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Encrypt data
            encrypted_data = self.crypto.encrypt(data, password)
            
            # Store encrypted file
            encrypted_path = self.vault_dir / f"{file_path.stem}.vault"
            with open(encrypted_path, 'w') as f:
                f.write(encrypted_data.model_dump_json())  # Updated from json()
            
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
        """Decrypt a file from the vault"""
        try:
            encrypted_path = Path(encrypted_path)
            output_path = Path(output_path)
            
            # Read encrypted data
            with open(encrypted_path, 'r') as f:
                # Updated from parse_raw()
                encrypted_data = EncryptedData.model_validate_json(f.read())
            
            # Decrypt data
            decrypted_data = self.crypto.decrypt(encrypted_data, password)
            
            # Write decrypted file
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
        """List all encrypted files in the vault"""
        return list(self.vault_dir.glob("*.vault"))