# Secure Vault Documentation

## Overview
Secure Vault is a professional-grade file encryption system that provides multiple ways to securely encrypt and manage sensitive files. It uses industry-standard encryption (AES-256-GCM) with modern security features like Argon2id key derivation and Ed25519 digital signatures.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secure-vault.git
cd secure-vault

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## Ways to Use Secure Vault

### 1. Python API

The Python API provides programmatic access to the vault's functionality:

```python
from secure_vault import SecureVault

# Initialize the vault
vault = SecureVault("./my_encrypted_files")

# Encrypt a file
vault.encrypt_file("secret_document.txt", "your_secure_password")

# Decrypt a file
vault.decrypt_file(
    "secret_document.txt.vault",
    "decrypted_document.txt",
    "your_secure_password"
)

# List encrypted files
files = vault.list_files()
for file in files:
    print(f"Encrypted file: {file}")
```

### 2. Command Line Interface (CLI)

The CLI provides quick access from the terminal:

```bash
# Encrypt a file
secure-vault encrypt secret.txt --password "your_password"

# Decrypt a file
secure-vault decrypt secret.txt.vault decrypted.txt --password "your_password"

# List all encrypted files
secure-vault list
```

### 3. Web API

The Web API allows remote access with authentication:

```bash
# Start the server
export FLASK_APP=secure_vault.web_api
export SECRET_KEY=your-secret-key
flask run

# In production, use HTTPS and a proper WSGI server
```

API Endpoints:
- `POST /api/auth` - Get authentication token
  ```bash
  curl -u username:password http://localhost:5000/api/auth
  ```

- `GET /api/files` - List encrypted files
  ```bash
  curl -H "Authorization: Bearer <token>" http://localhost:5000/api/files
  ```

- `POST /api/files` - Encrypt a file
  ```bash
  curl -H "Authorization: Bearer <token>" \
       -F "file=@secret.txt" \
       -F "password=mysecret" \
       http://localhost:5000/api/files
  ```

- `POST /api/files/<filename>` - Decrypt a file
  ```bash
  curl -H "Authorization: Bearer <token>" \
       -F "password=mysecret" \
       http://localhost:5000/api/files/secret.txt.vault \
       --output decrypted.txt
  ```

- `DELETE /api/files/<filename>` - Delete an encrypted file
  ```bash
  curl -X DELETE \
       -H "Authorization: Bearer <token>" \
       http://localhost:5000/api/files/secret.txt.vault
  ```

### 4. Graphical User Interface (GUI)

The GUI provides a user-friendly interface:

```bash
# Start the GUI
python secure_vault_gui.py
```

Features:
- File list showing encrypted files
- Encrypt button to add new files
- Decrypt button for selected files
- Password dialog for secure input
- Refresh button to update the view

## Security Features

### Encryption
- AES-256-GCM authenticated encryption
- Protects both confidentiality and integrity
- Unique encryption key for each file

### Key Derivation
- Argon2id for secure password-based key derivation
- Memory-hard algorithm resistant to brute-force attacks
- Unique salt for each encryption

### Digital Signatures
- Ed25519 signatures verify file authenticity
- Prevents tampering with encrypted files
- Cryptographic proof of integrity

### Additional Security
- No keys stored on disk
- Secure random number generation
- Proper cleanup of sensitive data
- Rate limiting on API
- JWT authentication for web access

## Troubleshooting

Common Issues:
1. "Invalid password" error
   - Verify password is correct
   - Check for typos
   - Ensure using correct file

2. "File not found" error
   - Check file path
   - Verify file exists
   - Check permissions

3. "Signature verification failed"
   - File may be corrupted
   - Possible tampering
   - Try from backup

## Support

For issues or questions:
1. Check documentation
2. Review error messages
3. Check logs for details
4. Report bugs to me via GitHub issues - I'll try to fix them

## Technical Details

### File Format
Encrypted files contain:
- Encrypted data (AES-256-GCM)
- Authentication tag
- Salt for key derivation
- Digital signature
- Metadata (JSON format)

### Performance
- Fast encryption/decryption
- Efficient key derivation
- Minimal memory usage
- Scalable to large files