# Secure Vault API Documentation

## CryptoManager

The `CryptoManager` class provides low-level cryptographic operations using industry-standard algorithms and secure parameters.

### Class Definition
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

class CryptoManager:
    def __init__(self):
        self.salt = os.urandom(16)
        self._signing_key = Ed25519PrivateKey.generate()
```

### Methods

#### `derive_key(password: str, salt: bytes = None) -> bytes`
Derives an encryption key from a password using Argon2id with secure parameters.

**Parameters:**
- `password` (str): User-provided password
- `salt` (bytes, optional): Salt for key derivation. If None, generates new salt.

**Returns:**
- `bytes`: 32-byte encryption key

**Example:**
```python
crypto = CryptoManager()
key = crypto.derive_key("my_secure_password")
```

**Implementation Details:**
- Uses Argon2id for key derivation
- Memory cost: 65536 KB
- Iterations: 4
- Parallel lanes: 4
- Output length: 32 bytes

#### `encrypt(data: bytes, password: str) -> EncryptedData`
Encrypts data using AES-256-GCM with authenticated encryption and signs it.

**Parameters:**
- `data` (bytes): Data to encrypt
- `password` (str): Encryption password

**Returns:**
- `EncryptedData`: Object containing:
  - `nonce` (str): Base64-encoded nonce
  - `salt` (str): Base64-encoded salt
  - `ciphertext` (str): Base64-encoded encrypted data
  - `signature` (str): Base64-encoded Ed25519 signature

**Example:**
```python
crypto = CryptoManager()
data = b"secret data"
encrypted = crypto.encrypt(data, "my_password")
```

**Security Features:**
- AES-256-GCM for authenticated encryption
- Unique nonce for each encryption
- Digital signature for integrity
- Secure key derivation

#### `decrypt(encrypted_data: EncryptedData, password: str) -> bytes`
Decrypts data and verifies its signature.

**Parameters:**
- `encrypted_data` (EncryptedData): Encrypted data object
- `password` (str): Decryption password

**Returns:**
- `bytes`: Decrypted data

**Raises:**
- `ValueError`: If password is wrong or data is corrupted
- `InvalidTag`: If authentication fails

**Example:**
```python
try:
    decrypted = crypto.decrypt(encrypted_data, "my_password")
except ValueError as e:
    print("Decryption failed:", e)
```

## SecureVault

The `SecureVault` class provides high-level file encryption operations with proper file handling and logging.

### Class Definition
```python
class SecureVault:
    def __init__(self, vault_dir: str = None):
        self.vault_dir = Path(vault_dir or './vault')
        self.crypto = CryptoManager()
```

### Methods

#### `encrypt_file(file_path: str, password: str) -> Path`
Encrypts a file and stores it in the vault.

**Parameters:**
- `file_path` (str): Path to file to encrypt
- `password` (str): Encryption password

**Returns:**
- `Path`: Path to encrypted file

**Raises:**
- `FileNotFoundError`: If source file doesn't exist
- `IOError`: If file operations fail

**Example:**
```python
vault = SecureVault("./encrypted_files")
encrypted_path = vault.encrypt_file("secret.txt", "my_password")
```

**Implementation Details:**
- Generates unique filename
- Handles large files efficiently
- Includes audit logging
- Proper file cleanup

#### `decrypt_file(encrypted_path: str, output_path: str, password: str) -> Path`
Decrypts a file from the vault.

**Parameters:**
- `encrypted_path` (str): Path to encrypted file
- `output_path` (str): Where to save decrypted file
- `password` (str): Decryption password

**Returns:**
- `Path`: Path to decrypted file

**Raises:**
- `FileNotFoundError`: If encrypted file not found
- `ValueError`: If password wrong or file corrupted
- `IOError`: If file operations fail

**Example:**
```python
decrypted_path = vault.decrypt_file(
    "secret.txt.vault",
    "decrypted.txt",
    "my_password"
)
```

#### `list_files() -> List[Path]`
Lists all encrypted files in the vault.

**Returns:**
- `List[Path]`: List of paths to encrypted files

**Example:**
```python
files = vault.list_files()
for file in files:
    print(f"Encrypted file: {file.name}")
```

## Web API

RESTful API providing remote access to vault functionality with authentication and rate limiting.

### Authentication

#### POST /api/auth
Get JWT authentication token.

**Request:**
```bash
curl -X POST http://localhost:5000/api/auth \
     -u username:password
```

**Response:**
```json
{
    "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "expires_in": 86400
}
```

### File Operations

#### GET /api/files
List all encrypted files in the vault.

**Request:**
```bash
curl -H "Authorization: Bearer <token>" \
     http://localhost:5000/api/files
```

**Response:**
```json
[
    {
        "name": "secret.txt.vault",
        "size": 1234,
        "modified": "2025-02-16T12:00:00"
    }
]
```

#### POST /api/files
Encrypt and store a file.

**Request:**
```bash
curl -X POST http://localhost:5000/api/files \
     -H "Authorization: Bearer <token>" \
     -F "file=@secret.txt" \
     -F "password=my_password"
```

**Response:**
```json
{
    "message": "File encrypted successfully",
    "file": "secret.txt.vault",
    "size": 1234,
    "modified": "2025-02-16T12:00:00"
}
```

#### POST /api/files/<filename>
Decrypt and download a file.

**Request:**
```bash
curl -X POST http://localhost:5000/api/files/secret.txt.vault \
     -H "Authorization: Bearer <token>" \
     -F "password=my_password" \
     --output decrypted.txt
```

**Response:**
- File download or error JSON:
```json
{
    "error": "Invalid password or file corrupted"
}
```

#### DELETE /api/files/<filename>
Delete an encrypted file.

**Request:**
```bash
curl -X DELETE http://localhost:5000/api/files/secret.txt.vault \
     -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
    "message": "File deleted successfully"
}
```

### Error Responses

All endpoints may return these error responses:

```json
{
    "error": "Missing authentication token",
    "status": 401
}
```

```json
{
    "error": "Rate limit exceeded",
    "status": 429,
    "retry_after": 3600
}
```

```json
{
    "error": "File too large",
    "status": 413,
    "max_size": 16777216
}
```

### Security Features

1. Authentication
   - JWT tokens with expiration
   - Secure password handling
   - Rate limiting per user

2. Request Validation
   - File size limits
   - Content type verification
   - Input sanitization

3. Response Security
   - HTTPS only
   - Secure headers
   - Error sanitization

4. File Handling
   - Secure temp files
   - Proper cleanup
   - Access control