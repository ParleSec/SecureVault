from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidTag
import os
import base64
from pydantic import BaseModel
import structlog
import json
from pathlib import Path

logger = structlog.get_logger()

class EncryptedData(BaseModel):
    nonce: str
    salt: str
    ciphertext: str
    signature: str
    public_key: str  # Added to store the public key

class CryptoManager:
    def __init__(self, key_file: str = None):
        """Initialize the crypto manager with an optional key file path"""
        self.salt = os.urandom(16)
        self.logger = logger.bind(component="crypto")
        
        # Set up key file path
        if key_file is None:
            # Use script directory for key file
            script_dir = Path(__file__).parent.absolute()
            self.key_file = script_dir / "crypto_key.json"
        else:
            self.key_file = Path(key_file)
            
        # Create key file directory if it doesn't exist
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize signing key
        self._signing_key = self._load_or_create_key()

    def _load_or_create_key(self) -> Ed25519PrivateKey:
        """Load existing key or create a new one"""
        try:
            if self.key_file.exists():
                with open(self.key_file, 'r') as f:
                    key_data = json.load(f)
                    private_bytes = base64.b64decode(key_data['private_key'])
                    return Ed25519PrivateKey.from_private_bytes(private_bytes)
        except Exception as e:
            self.logger.warning("Failed to load key, creating new one", error=str(e))

        # Create new key
        key = Ed25519PrivateKey.generate()
        try:
            # Save the key
            key_data = {
                'private_key': base64.b64encode(
                    key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                ).decode('utf-8')
            }
            with open(self.key_file, 'w') as f:
                json.dump(key_data, f)
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
            iterations=4,
            lanes=4,          # equivalent to parallelism in some versions
            memory_cost=65536  # memory size in kB
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

            # Include public key in encrypted data
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