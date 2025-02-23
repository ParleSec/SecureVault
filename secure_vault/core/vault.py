import os
import json
from pathlib import Path
from typing import List
import structlog
from .crypto import CryptoManager, EncryptedData

logger = structlog.get_logger()

class SecureVault:
    """
    SecureVault manages file encryption and decryption.
    Encrypted files are saved with the original file name (including extension)
    plus a '.vault' suffix.
    """
    def __init__(self, vault_dir: str = None):
        self.vault_dir = Path(vault_dir or os.getenv('VAULT_DIR', './vault'))
        self.crypto = CryptoManager()
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
        It is assumed that the encrypted file’s name ends with '.vault';
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