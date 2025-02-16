# Secure Vault

A homebrewed secure file encryption system implementing modern cryptographic principles and security best practices.

## Features

- AES-256-GCM authenticated encryption
- Argon2id password-based key derivation
- Ed25519 digital signatures for file authenticity
- Secure random number generation
- Feature-rich CLI and Web API interfaces
- Comprehensive logging and error handling
- Full test coverage

## Installation

```bash
# Clone the repository
git clone https://github.com/Bobfrog93/SecureVault
cd secure-vault

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## Quick Start

### Python API
```python
from secure_vault import SecureVault

# Initialize vault
vault = SecureVault("./encrypted_files")

# Encrypt a file
vault.encrypt_file("secret.txt", "your_password")

# Decrypt a file
vault.decrypt_file("secret.txt.vault", "decrypted.txt", "your_password")
```

### Web API
The Web API uses Flask for the environment server.
```bash
# Set environment variables
export FLASK_APP=secure_vault.web_api
export FLASK_ENV=development
export SECRET_KEY=your-secret-key

# Start the server
flask run
```

### GUI Interface
```bash
python secure_vault_gui.py
```

## Documentation

- [User Guide](docs/USER_GUIDE.md)
- [API Documentation](docs/API.md)
- [Security Guide](docs/SECURITY.md)
- [Developer Guide](docs/DEVELOPER.md)

## Testing

```bash
# Run tests
python -m pytest

# Run with coverage
pytest --cov=secure_vault
```

## Security

The project implements several security best practices:
- No stored keys or passwords
- Secure key derivation
- Digital signatures
- Comprehensive error handling
- Audit logging

See [SECURITY.md](docs/SECURITY.md) for details.

## Contributing

Contributions are welcome :)
