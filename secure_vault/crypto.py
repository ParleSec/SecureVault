from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidTag
import os
import base64
from pydantic import BaseModel
import structlog

logger = structlog.get_logger()

class EncryptedData(BaseModel):
    nonce: str
    salt: str
    ciphertext: str
    signature: str

class CryptoManager:
    def __init__(self):
        self.salt = os.urandom(16)
        self._signing_key = Ed25519PrivateKey.generate()
        self.logger = logger.bind(component="crypto")

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
            
            encrypted_data = EncryptedData(
                nonce=base64.b64encode(nonce).decode('utf-8'),
                salt=base64.b64encode(self.salt).decode('utf-8'),
                ciphertext=base64.b64encode(ciphertext).decode('utf-8'),
                signature=base64.b64encode(signature).decode('utf-8')
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
            
            # Verify signature
            try:
                self._signing_key.public_key().verify(signature, ciphertext)
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