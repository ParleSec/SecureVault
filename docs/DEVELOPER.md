# Developer Guide

## Project Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/SecureVault.git
cd SecureVault
```

2. Create and activate a virtual environment:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
pip install -e .
```

## Project Structure

```
SecureVault/
├── secure_vault/           # Main package directory
│   ├── __init__.py        # Package initialization
│   ├── crypto.py          # Cryptographic operations
│   ├── vault.py           # Core vault functionality
│   ├── cli.py             # Command-line interface
│   └── web_api.py         # Web API implementation
├── tests/                 # Test directory
│   ├── __init__.py
│   ├── test_crypto.py     # Crypto tests
│   └── test_vault.py      # Vault tests
└── docs/                  # Documentation
```

## Core Components

### CryptoManager (crypto.py)
Handles cryptographic operations:
- AES-256-GCM encryption/decryption
- Argon2id key derivation
- Ed25519 digital signatures

### SecureVault (vault.py)
Manages file operations:
- File encryption/decryption
- Vault directory management
- File listing and tracking

### Web API (web_api.py)
Provides RESTful interface:
- JWT authentication
- File operations endpoints
- Rate limiting

## Development Workflow

1. Create a new branch for features:
```bash
git checkout -b feature/your-feature-name
```

2. Run tests during development:
```bash
python -m pytest
```

3. Check code style:
```bash
black secure_vault
pylint secure_vault
mypy secure_vault
```

4. Run test coverage:
```bash
pytest --cov=secure_vault

## Environment Setup

Create a `.env` file in the project root:
```
FLASK_APP=secure_vault.web_api
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
VAULT_DIR=./encrypted_vault
```

## Testing

1. Run all tests:
```bash
python -m pytest
```

2. Run specific test file:
```bash
python -m pytest tests/test_crypto.py
```

3. Run with coverage:
```bash
pytest --cov=secure_vault
```

## Web API Development

1. Start the development server:
```bash
flask run
```

2. Test endpoints:
```bash
# Get auth token
curl -X POST http://localhost:5000/api/auth \
     -u username:password

# List files
curl -H "Authorization: Bearer <token>" \
     http://localhost:5000/api/files
```

## Development Tasks

### Adding New Features

1. Add tests in `tests/` directory
2. Implement feature in appropriate module
3. Update documentation
4. Run test suite
5. Submit pull request

### Debugging

1. Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

2. Use debugger:
```python
import pdb
pdb.set_trace()
```

## API Development Guidelines

1. All endpoints should:
   - Have proper authentication
   - Include error handling
   - Return appropriate status codes
   - Include logging

2. Example endpoint structure:
```python
@app.route('/api/endpoint', methods=['POST'])
@require_auth
@rate_limit
def endpoint():
    try:
        # Implementation
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error("operation_failed", error=str(e))
        return jsonify({"error": str(e)}), 500
```

## Security Considerations

1. Password Handling:
   - Never store raw passwords
   - Use secure key derivation
   - Implement rate limiting

2. File Operations:
   - Secure file cleanup
   - Proper permission handling
   - Input validation

3. Encryption:
   - Secure random number generation
   - Proper IV/nonce handling
   - Key separation

## Performance Optimization

1. File Handling:
   - Use buffered operations
   - Implement chunking for large files
   - Clean up temporary files

2. Memory Management:
   - Monitor memory usage
   - Implement streaming where appropriate
   - Clean up resources properly

## Documentation Guidelines

1. Code Documentation:
   - Use docstrings for all functions
   - Include type hints
   - Document exceptions

2. Example documentation:
```python
def encrypt_file(file_path: str, password: str) -> Path:
    """
    Encrypt a file and store in vault.

    Args:
        file_path: Path to file to encrypt
        password: Encryption password

    Returns:
        Path: Path to encrypted file

    Raises:
        ValueError: If password is invalid
        FileNotFoundError: If source file doesn't exist
    """
```

## Deployment

1. Production setup:
```bash
# Install production requirements
pip install gunicorn

# Start with gunicorn
gunicorn secure_vault.web_api:app
```

2. Environment variables:
```bash
export FLASK_ENV=production
export SECRET_KEY=<secure-key>
export VAULT_DIR=/path/to/vault
```

## Contributing

1. Fork the repository
2. Create feature branch
3. Make changes
4. Run tests
5. Submit pull request

## Questions and Support

For questions or issues:
1. Check existing documentation
2. Review closed issues
3. Open new issue with:
   - Description of problem
   - Steps to reproduce
   - Expected vs actual behavior