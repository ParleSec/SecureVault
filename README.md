# SecureVault

A secure file encryption system implementing modern cryptographic principles and security best practices. Features CLI, GUI and API interfaces for secure file management.

## Features

### Core Security
- AES-256-GCM authenticated encryption
- Argon2id password-based key derivation
- Ed25519 digital signatures for file authenticity
- Secure memory handling and file operations
- Comprehensive audit logging

### Multiple Interfaces
- User-friendly GUI application
- Secure HTTPS API server
- CLI for command-line operations

### Security Features
- Secure file deletion with multiple passes
- Memory protection for sensitive data
- Input validation and sanitization
- Rate limiting and CSRF protection
- Detailed security monitoring

## Installation

```bash
# Clone the repository
git clone https://github.com/ParleSec/SecureVault
cd SecureVault

# (optional) Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### GUI Application
```bash
# Start the GUI
python main.py
```

### API Server
```bash
# Start the API server
python -m secure_vault.web.run_api
```

### CLI Usage
```bash
# Encrypt a file
python cli.py encrypt path/to/file.txt --password "your_password"

# Decrypt a file
python cli.py decrypt path/to/file.txt.vault output.txt --password "your_password"

# List encrypted files
python cli.py list
```

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

## Project Structure
```
securevault/
├── main.py                  # Main entry point
├── secure_vault_gui.py      # GUI implementation
├── cli.py                   # CLI interface
├── secure_vault/           # Core package
│   ├── core/               # Encryption & storage
│   ├── web/                # API components
│   ├── security/           # Security features
│   └── utils/              # Utilities
├── tests/                  # Test suites
└── demos/                  # Usage examples
```

## Testing

```bash
# Run tests
python -m pytest

# Run specific test file
pytest tests/test_crypto.py
```

## Security Features

The project implements several security best practices:
- Zero trust architecture - all data encrypted before storage
- No stored keys or passwords
- Secure key derivation using Argon2id
- Digital signatures for file authenticity
- Comprehensive error handling and audit logging
- Secure memory handling for sensitive data
- HTTPS with TLS 1.2/1.3 support

## Demos
SecureVault includes several demonstration scripts in the demos/ directory to help you get started:

#### API Demo
Check out demos/demo_api.py for a complete HTTPS API demonstration:
```bash 
python demos/demo_api.py
```

#### CLI Demo
Check out demos/demo_cli.py for command-line interface examples:
```bash 
python demos/demo_cli.py
```

#### Encryption Demo
Check out demos/demo_encryption.py for encryption functionality:
```bash 
python demos/demo_encryption.py
```

## Troubleshooting

Common issues:
1. **SSL Certificate Errors**: Development server uses self-signed certificates. In a production environment, use proper SSL certificates.

2. **Permission Issues**: Ensure proper file permissions on the vault directory.

3. **Memory Errors**: Check available system memory when handling large files.
###
Known Issues:
1. **Renamed File Errors**: Renaming the file during decryption will cause the extension to be removed. Take note of the extension and append post-decryption.

## Contributing

Contributions are welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.