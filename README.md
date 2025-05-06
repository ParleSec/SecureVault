# SecureVault

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/) [![Crypto](https://img.shields.io/badge/Encryption-AES--GCM%20%7C%20Argon2id%20%7C%20Ed25519-blue?style=for-the-badge&logo=lock)](https://cryptography.io/en/latest/) [![Security](https://img.shields.io/badge/Security-Memory%20Protection%20%7C%20Secure%20Delete-red?style=for-the-badge&logo=shield)](https://github.com/pyca/cryptography) [![Interface](https://img.shields.io/badge/Interface-GUI%20%7C%20API%20%7C%20CLI-purple?style=for-the-badge&logo=windowsterminal)](https://www.python.org/) [![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**SecureVault** is a comprehensive file encryption system implementing modern cryptographic principles and security best practices. With multiple interfaces (GUI, API, CLI) and a focus on security at every level, SecureVault protects your sensitive files with robust encryption and secure operational practices.

## Purpose & Motivation

Modern data protection requires strong encryption, secure handling practices, and usability. SecureVault aims to:

- Provide strong encryption with authenticated encryption modes
- Implement secure memory handling to protect sensitive data
- Offer multiple interfaces for different use cases
- Follow security best practices for key derivation and file operations
- Create a user-friendly experience for secure file management

## Quick Installation

### Executable Download (Recommended)

Download and run the standalone executable without any installation:

```bash
# Windows
curl.exe -L -o SecureVault.exe https://github.com/ParleSec/SecureVault/releases/latest/download/SecureVault-windows-amd64.exe
.\SecureVault.exe

```

### From Source

```bash
# Clone the repository
git clone https://github.com/ParleSec/SecureVault
cd SecureVault

# (optional) Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

## Key Features

### 🔐 Core Security
- **AES-256-GCM authenticated encryption** for confidentiality and integrity
- **Password-based key derivation** with Argon2id
- **Ed25519 digital signatures** for file authenticity verification
- **Secure memory handling** for sensitive data
- **Comprehensive audit logging** of all security operations

### 🖥️ Multiple Interfaces
- **User-friendly GUI** application with intuitive controls
- **Secure HTTPS API** server with JWT authentication
- **CLI** for command-line and scripting operations

### 🛡️ Security Features
- **Secure file deletion** with multiple-pass overwriting
- **Memory protection** techniques to prevent leakage of sensitive data
- **Input validation and sanitization** to prevent attacks
- **Rate limiting and CSRF protection** in API mode
- **Detailed security monitoring and logging**

## Security Architecture

### Encryption Implementation

SecureVault uses AES-256-GCM, which provides:
- **Confidentiality** through encryption
- **Integrity and authenticity** through authentication tags
- **Nonce management** with secure random generation

### Key Derivation

- **Argon2id** for password-based key derivation
  - Memory-hard algorithm resistant to GPU/ASIC attacks
  - Configurable memory and CPU cost parameters
  - Salt uniquely generated for each encryption operation

### Signature Verification

- **Ed25519** digital signatures to verify file authenticity
- Automatically generated public/private key pairs
- Signature verification before any decryption attempt

### Secure Memory Handling

- **Memory locking** to prevent sensitive data being swapped to disk
- **Multi-pass memory wiping** when sensitive data is no longer needed
- **SecureString and SecureBytes** classes for protecting passwords and keys
- **Context managers** for automatic cleanup of sensitive memory

### Secure File Operations

- **Secure permissions** set on all files and directories
- **Multi-pass overwrite** for secure file deletion:
  - Random data pass
  - Zeros pass
  - Ones (0xFF) pass
- **Secure move operations** to prevent data leakage
- **Path validation** to prevent directory traversal attacks

## Command Reference

### GUI Application
```bash
# Start the GUI
python main.py
```

### API Server
```bash
# Start the API server
python main.py --api-server
# Or set environment variable:
# set SECUREVAULT_API_MODE=true  # Windows
# export SECUREVAULT_API_MODE=true  # Linux/Mac
```

### CLI Usage

| Command | Description | Example |
|---------|-------------|---------|
| `encrypt` | Encrypt a file | `python -m secure_vault.cli encrypt path/to/file.txt --password "password"` |
| `decrypt` | Decrypt a vault file | `python -m secure_vault.cli decrypt path/to/file.txt.vault output.txt --password "password"` |
| `list` | List encrypted files | `python -m secure_vault.cli list` |
| `delete` | Securely delete a file | `python -m secure_vault.cli delete path/to/file.txt.vault` |
| `info` | Display vault metadata | `python -m secure_vault.cli info path/to/file.txt.vault` |

For complete options, run `python -m secure_vault.cli --help` or `python -m secure_vault.cli <command> --help`.

## API Examples

### Authentication
```python
import requests

# Authenticate and get token
response = requests.post(
    'https://localhost:5000/api/auth',
    auth=('username', 'password'),
    verify=False  # For development only
)
token = response.json()['token']
```

### File Operations
```python
# Encrypt file
with open('secret.txt', 'rb') as f:
    response = requests.post(
        'https://localhost:5000/api/files',
        headers={'Authorization': f'Bearer {token}'},
        files={'file': f},
        data={'password': 'your_password'},
        verify=False  # For development only
    )

# Decrypt file
response = requests.post(
    'https://localhost:5000/api/files/secret.txt.vault',
    headers={'Authorization': f'Bearer {token}'},
    data={'password': 'your_password'},
    verify=False  # For development only
)
```

## Comparison with Alternatives

| Feature | SecureVault | GPG | VeraCrypt | Cryptomator |
|---------|-------------|-----|-----------|-------------|
| **Authenticated Encryption** | ✅ (AES-GCM) | ✅ | ✅ | ✅ |
| **Memory-Hard KDF** | ✅ (Argon2id) | ❌ | ✅ (PBKDF2) | ✅ |
| **Digital Signatures** | ✅ | ✅ | ❌ | ❌ |
| **Secure Memory Handling** | ✅ | ❌ | ✅ | ❌ |
| **Multiple Interfaces** | ✅ (GUI/API/CLI) | ✅ (CLI) | ✅ (GUI) | ✅ (GUI) |
| **Secure Deletion** | ✅ | ❌ | ✅ | ❌ |
| **Cross-Platform** | ✅ | ✅ | ✅ | ✅ |
| **Volume Encryption** | ❌ | ❌ | ✅ | ✅ |

## Getting Started

### Basic GUI Usage

1. Launch the application: `python main.py`
2. Use the interface to:
   - Browse for files to encrypt/decrypt
   - Enter secure passwords
   - Manage your encrypted vault

### CLI Examples

```bash
# Encrypt a file
python -m secure_vault.cli encrypt my_document.pdf --password "secure_password"

# The file will be encrypted to my_document.pdf.vault

# Decrypt a file
python -m secure_vault.cli decrypt my_document.pdf.vault output.pdf --password "secure_password"

# List all encrypted files in the vault
python -m secure_vault.cli list

# Get information about an encrypted file
python -m secure_vault.cli info my_document.pdf.vault
```

### API Server Usage

Start the API server:
```bash
python main.py --api-server
```

Access the API documentation:
```
https://localhost:5000/api/docs
```


## Project Structure
```
SecureVault/
├── main.py                  # Main entry point
├── secure_vault_gui.py      # GUI implementation
├── securevault.py           # Core functionality
├── config_manager.py        # Configuration management
├── secure_vault/           # Core package
│   ├── core/               # Encryption & storage
│   │   ├── crypto.py       # Cryptographic operations
│   │   ├── vault.py        # Vault management
│   │   └── keys.py         # Key handling
│   ├── web/                # API components
│   ├── security/           # Security features
│   │   ├── files.py        # Secure file operations
│   │   ├── memory.py       # Memory protection
│   │   └── auth.py         # Authentication
│   ├── users/              # User management
│   ├── utils/              # Utilities
│   └── cli.py              # CLI interface
├── resources/              # Application resources
├── certs/                  # SSL certificates
├── encrypted_vault/        # Default vault location
├── tests/                  # Test suites
└── demos/                  # Usage examples
    ├── demo_api.py        # API usage examples
    ├── demo_cli.py        # CLI usage examples
    └── demo_encryption.py # Encryption examples
```

## Technical Security Details

### Cryptographic Implementation

- **AES-256-GCM** with 12-byte nonce for authenticated encryption
- **Argon2id** key derivation function with time, memory, and parallel cost factors
- **Ed25519** for digital signature generation and verification
- **Secure binary format** with magic bytes, version control, and size validation
- **Salt and nonce** uniquely generated for each operation

### Memory Protection

- `SecureString` and `SecureBytes` classes overwrite memory before freeing
- Memory locking prevents sensitive data from being swapped to disk
- Multi-pattern memory wiping (0x00, 0xFF, 0xAA, 0x55)
- Context managers ensure automatic memory cleanup

### File Security

- Owner-only permissions for all sensitive files
- Platform-specific security measures:
  - Windows: ACL and security descriptors
  - Unix: File permission modes (chmod)
- Multi-pass secure deletion with different patterns
- File renaming for secure deletion of locked files
- Filesystem sync operations to ensure data is committed

### Error Handling and Resilience

- Comprehensive error handling with appropriate fallbacks
- Detailed security audit logging
- Layered approach to error recovery
- Graceful degradation when security features are unavailable

## Executable Builds

SecureVault is available as pre-built executables for different platforms:

- Windows (x64): `SecureVault-windows-amd64.exe`
- Linux (x64): `securevault-linux-amd64`
- macOS (x64): `securevault-macos-amd64`

### Download Executables

Pre-built executables can be downloaded from the [releases page](https://github.com/ParleSec/SecureVault/releases).

### Building Your Own Executable

You can also build the executable yourself:

```bash
# Build executable
python build_securevault.py

# For installer package (Windows)
# Requires Inno Setup
python build_securevault.py --installer
```

## Testing

```bash
# Run tests
python -m pytest

# Run specific test file
pytest tests/test_crypto.py
```

## Troubleshooting

Common issues:

1. **SSL Certificate Errors**: Development server uses self-signed certificates. In a production environment, use proper SSL certificates.

2. **Permission Issues**: Ensure proper file permissions on the vault directory.

3. **Memory Errors**: Check available system memory when handling large files.

## Disclaimer

### Security Limitations
- SecureVault implements strong cryptographic algorithms and security practices, but no encryption system can be guaranteed as unbreakable.
- The security of your encrypted data depends significantly on the strength of your passwords.
- While we strive for security best practices, software vulnerabilities may exist in SecureVault or its dependencies.

### Legal Usage
- Users are responsible for complying with all applicable laws related to encryption, data protection, and privacy in their jurisdiction.
- SecureVault should not be used to store or transmit illegal content.
- Some countries restrict the use, import, or export of encryption software. Ensure you are legally permitted to use this software in your location.

### Research and Development
- This software may be used for security research, education, and legitimate data protection needs.
- ParleSec provides this tool for defensive security purposes only.

### No Warranty
- SecureVault is provided "as is" without warranty of any kind, express or implied.
- The authors and contributors are not liable for any damages or liability arising from the use of this software.
- Users are responsible for implementing their own data backup strategies.

### Privacy
- SecureVault does not collect or transmit user data or usage statistics.
- All encryption and decryption operations occur locally on your device.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
<i>SecureVault - ParleSec</i>
</div>