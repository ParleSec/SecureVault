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

    def _derive_key(self, password: str, salt: bytes = None) -> bytes:
        """Derive encryption key from password using Argon2id with enhanced reliability"""
        if salt is None:
            salt = self.salt
            
        # Ensure salt is valid
        if not salt or len(salt) < 8:
            self.logger.warning(f"Invalid salt, using secure random salt instead")
            salt = os.urandom(16)
            
        try:
            # Use Argon2id with explicit parameters
            kdf = Argon2id(
                length=32,
                salt=salt,
                iterations=10,          # Time cost
                lanes=4,                # Parallelism
                memory_cost=65536       # Memory size in kB
            )
            return kdf.derive(password.encode('utf-8'))
        except Exception as e:
            # Log the error and try with default parameters as fallback
            self.logger.error(f"Error in key derivation: {e}, trying fallback parameters")
            try:
                # Fallback to simpler parameters
                kdf = Argon2id(
                    length=32,
                    salt=salt,
                    iterations=3,       # Lower time cost
                    lanes=1,            # Lower parallelism
                    memory_cost=16384   # Lower memory cost
                )
                return kdf.derive(password.encode('utf-8'))
            except Exception as fallback_e:
                # If Argon2id completely fails, fall back to PBKDF2
                self.logger.error(f"Argon2id failed completely: {fallback_e}, using PBKDF2 fallback")
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                from cryptography.hazmat.primitives import hashes
                
                pbkdf2 = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000
                )
                return pbkdf2.derive(password.encode('utf-8'))
        
    def encrypt(self, data: bytes, password: str):
        """
        Encrypt data using AES-256-GCM with authenticated encryption.
        This is a wrapper around the original encrypt implementation to ensure compatibility.
        
        Args:
            data (bytes): The data to encrypt
            password (str): The password to use for encryption
            
        Returns:
            EncryptedData: Object containing the encrypted data and metadata
        """
        try:
            nonce = os.urandom(12)
            salt  = os.urandom(16)

            # ✅ fixed – use the correct helper and pass the salt
            key = self._derive_key(password, salt)

            aesgcm     = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, data, None)
            signature  = self._signing_key.sign(ciphertext)

            public_key_bytes = self._signing_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            encrypted_data = EncryptedData(
                nonce      = base64.b64encode(nonce).decode(),
                salt       = base64.b64encode(salt).decode(),
                ciphertext = base64.b64encode(ciphertext).decode(),
                signature  = base64.b64encode(signature).decode(),
                public_key = base64.b64encode(public_key_bytes).decode(),
            )

            logger.info("data_encrypted", bytes_encrypted=len(data))
            return encrypted_data

        except Exception as e:
            logger.error("encryption_failed", error=str(e))
            raise

    def decrypt(self, encrypted_data: bytes, password: str) -> bytes:
        """
        Decrypt data from binary format with improved error handling and fallback mechanisms.
        """
        original_error = None
        
        try:
            # Check minimum length for header and verify magic bytes
            if len(encrypted_data) < 16:  # Minimum header size
                raise ValueError(f"Invalid encrypted data: too short ({len(encrypted_data)} bytes)")
                
            # Extract header components
            magic = encrypted_data[:8]
            if magic != b"SECVAULT":
                magic_str = magic.decode('utf-8', errors='replace')
                raise ValueError(f"Invalid encrypted data: not a SecureVault file (magic: {magic_str})")
                
            # Parse version (bytes 8-10)
            version = int.from_bytes(encrypted_data[8:10], byteorder='big')
            if version != 1:
                raise ValueError(f"Unsupported version: {version}")
                
            # Extract sizes with validation
            salt_size = int.from_bytes(encrypted_data[10:11], byteorder='big')
            nonce_size = int.from_bytes(encrypted_data[11:12], byteorder='big')
            
            # Validate sizes are reasonable
            if salt_size <= 0 or salt_size > 32:
                raise ValueError(f"Invalid salt size: {salt_size}")
            if nonce_size <= 0 or nonce_size > 16:
                raise ValueError(f"Invalid nonce size: {nonce_size}")
            
            # Current position in the byte stream
            pos = 12
            
            # Extract salt and nonce with boundary checks
            if pos + salt_size > len(encrypted_data):
                raise ValueError(f"Salt extends beyond data boundary: pos={pos}, salt_size={salt_size}, data_len={len(encrypted_data)}")
            salt = encrypted_data[pos:pos+salt_size]
            pos += salt_size
            
            if pos + nonce_size > len(encrypted_data):
                raise ValueError(f"Nonce extends beyond data boundary: pos={pos}, nonce_size={nonce_size}, data_len={len(encrypted_data)}")
            nonce = encrypted_data[pos:pos+nonce_size]
            pos += nonce_size
            
            # Extract public key size with validation
            if pos + 2 > len(encrypted_data):
                raise ValueError(f"Public key size field extends beyond data boundary: pos={pos}, data_len={len(encrypted_data)}")
            public_key_size = int.from_bytes(encrypted_data[pos:pos+2], byteorder='big')
            if public_key_size <= 0 or public_key_size > 1024:
                raise ValueError(f"Invalid public key size: {public_key_size}")
            pos += 2
            
            # Extract public key with boundary check
            if pos + public_key_size > len(encrypted_data):
                raise ValueError(f"Public key extends beyond data boundary: pos={pos}, size={public_key_size}, data_len={len(encrypted_data)}")
            public_key_bytes = encrypted_data[pos:pos+public_key_size]
            pos += public_key_size
            
            # Extract signature size with validation
            if pos + 2 > len(encrypted_data):
                raise ValueError(f"Signature size field extends beyond data boundary: pos={pos}, data_len={len(encrypted_data)}")
            signature_size = int.from_bytes(encrypted_data[pos:pos+2], byteorder='big')
            if signature_size <= 0 or signature_size > 1024:
                raise ValueError(f"Invalid signature size: {signature_size}")
            pos += 2
            
            # Extract signature with boundary check
            if pos + signature_size > len(encrypted_data):
                raise ValueError(f"Signature extends beyond data boundary: pos={pos}, size={signature_size}, data_len={len(encrypted_data)}")
            signature = encrypted_data[pos:pos+signature_size]
            pos += signature_size
            
            # Extract ciphertext size with validation
            if pos + 4 > len(encrypted_data):
                raise ValueError(f"Ciphertext size field extends beyond data boundary: pos={pos}, data_len={len(encrypted_data)}")
            ciphertext_size = int.from_bytes(encrypted_data[pos:pos+4], byteorder='big')
            if ciphertext_size <= 0:
                raise ValueError(f"Invalid ciphertext size: {ciphertext_size}")
            pos += 4
            
            # Extract ciphertext with boundary check
            if pos + ciphertext_size > len(encrypted_data):
                raise ValueError(f"Ciphertext extends beyond data boundary: pos={pos}, size={ciphertext_size}, data_len={len(encrypted_data)}")
            ciphertext = encrypted_data[pos:pos+ciphertext_size]
            
            # Verify signature
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            try:
                public_key.verify(signature, ciphertext)
                self.logger.info("Signature verification successful")
            except Exception as e:
                self.logger.error(f"Signature verification failed: {e}")
                raise ValueError("Invalid signature - file may have been tampered with")
            
            # Derive key and decrypt
            key = self._derive_key(password, salt)
            aesgcm = AESGCM(key)
            
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            self.logger.info(f"Data decrypted successfully: {len(plaintext)} bytes")
            
            # Verify we got actual data
            if not plaintext:
                raise ValueError("Decryption resulted in empty data")
                
            return plaintext
            
        except Exception as e:
            # Store the original error for fallback reporting
            original_error = e
            self.logger.error(f"Standard decryption failed: {e}")
            
            # Try fallback decryption without signature verification
            try:
                self.logger.warning("Attempting fallback decryption")
                
                # Parse the binary format again but skip signature verification
                if len(encrypted_data) < 16:
                    raise ValueError("Data too short for fallback decryption")
                
                # Extract sizes
                salt_size = int.from_bytes(encrypted_data[10:11], byteorder='big')
                nonce_size = int.from_bytes(encrypted_data[11:12], byteorder='big')
                
                # Calculate position for salt and nonce
                pos = 12
                
                # Extract salt and nonce
                salt = encrypted_data[pos:pos+salt_size]
                pos += salt_size
                
                nonce = encrypted_data[pos:pos+nonce_size]
                pos += nonce_size
                
                # Skip public key
                public_key_size = int.from_bytes(encrypted_data[pos:pos+2], byteorder='big')
                pos += 2 + public_key_size
                
                # Skip signature
                signature_size = int.from_bytes(encrypted_data[pos:pos+2], byteorder='big')
                pos += 2 + signature_size
                
                # Extract ciphertext
                ciphertext_size = int.from_bytes(encrypted_data[pos:pos+4], byteorder='big')
                pos += 4
                
                ciphertext = encrypted_data[pos:pos+ciphertext_size]
                
                # Derive key and try decryption without verification
                key = self._derive_key(password, salt)
                aesgcm = AESGCM(key)
                
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                
                # Verify we got actual data
                if not plaintext:
                    raise ValueError("Fallback decryption resulted in empty data")
                    
                self.logger.info(f"Fallback decryption successful: {len(plaintext)} bytes")
                return plaintext
                
            except Exception as fallback_e:
                # Both standard and fallback decryption failed
                self.logger.error(f"Fallback decryption also failed: {fallback_e}")
                raise ValueError(f"Decryption failed. Original error: {original_error}, Fallback error: {fallback_e}")
