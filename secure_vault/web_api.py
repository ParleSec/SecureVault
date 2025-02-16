from flask import Flask, request, jsonify, send_file, Response
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
import tempfile
from pathlib import Path
import os
import time
from typing import Dict, Optional
import secrets
import structlog
import jwt
from datetime import datetime, timedelta, UTC
from .vault import SecureVault

logger = structlog.get_logger()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configuration
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', secrets.token_hex(32)),
    JWT_EXPIRATION_HOURS=24,
    UPLOAD_FOLDER='./temp_uploads',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file size
    RATE_LIMIT_REQUESTS=100,  # requests per window
    RATE_LIMIT_WINDOW=3600,  # window size in seconds
)

# Initialize vault
vault = SecureVault(os.getenv('VAULT_DIR', './encrypted_vault'))

# Simple in-memory rate limiting
rate_limit_store: Dict[str, Dict[str, int]] = {}

def require_auth(f):
    """Decorator to require JWT authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': 'Missing authentication token'}), 401
            
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = payload['sub']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
            
        return f(*args, **kwargs)
    return decorated

def rate_limit(f):
    """Decorator to implement rate limiting"""
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = request.user_id
        now = int(time.time())
        
        # Initialize or clean up old entries
        if user_id not in rate_limit_store:
            rate_limit_store[user_id] = {'count': 0, 'window_start': now}
        elif now - rate_limit_store[user_id]['window_start'] >= app.config['RATE_LIMIT_WINDOW']:
            rate_limit_store[user_id] = {'count': 0, 'window_start': now}
            
        # Check rate limit
        if rate_limit_store[user_id]['count'] >= app.config['RATE_LIMIT_REQUESTS']:
            return jsonify({'error': 'Rate limit exceeded'}), 429
            
        # Increment counter
        rate_limit_store[user_id]['count'] += 1
        
        return f(*args, **kwargs)
    return decorated

@app.route('/api/auth', methods=['POST'])
def authenticate():
    """Generate JWT token for API access"""
    auth = request.authorization
    
    if not auth or not auth.username or not auth.password:
        return jsonify({'error': 'Missing credentials'}), 401
        
    # In production, validate against user database
    # For demo, accept any username/password
    user_id = auth.username
    
    # Generate token with timezone-aware datetime
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            'sub': user_id,
            'iat': now,
            'exp': now + timedelta(hours=app.config['JWT_EXPIRATION_HOURS'])
        },
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    
    return jsonify({'token': token})

@app.route('/api/files', methods=['GET'])
@require_auth
@rate_limit
def list_files():
    """List all encrypted files in the vault"""
    try:
        files = vault.list_files()
        return jsonify([
            {
                'name': f.name,
                'size': f.stat().st_size,
                'modified': datetime.fromtimestamp(f.stat().st_mtime).isoformat()
            }
            for f in files
        ])
    except Exception as e:
        logger.error("list_files_failed", error=str(e))
        return jsonify({'error': 'Failed to list files'}), 500

@app.route('/api/files', methods=['POST'])
@require_auth
@rate_limit
def encrypt_file():
    """Encrypt and store a file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
        
    file = request.files['file']
    password = request.form.get('password')
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
        
    # Create temp directory if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    temp_path = None
    try:
        # Save uploaded file temporarily
        temp_path = Path(app.config['UPLOAD_FOLDER']) / secrets.token_hex(16)
        file.save(temp_path)
        
        # Encrypt the file
        encrypted_path = vault.encrypt_file(str(temp_path), password)
        
        return jsonify({
            'message': 'File encrypted successfully',
            'file': encrypted_path.name
        })
        
    except Exception as e:
        logger.error("encryption_failed", error=str(e))
        return jsonify({'error': 'Encryption failed'}), 500
        
    finally:
        # Clean up temp file
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except Exception as e:
                logger.error("cleanup_failed", error=str(e))

@app.route('/api/files/<filename>', methods=['POST'])
@require_auth
@rate_limit
def decrypt_file(filename):
    """Decrypt and download a file"""
    password = request.form.get('password')
    if not password:
        return jsonify({'error': 'No password provided'}), 400
        
    encrypted_path = vault.vault_dir / filename
    if not encrypted_path.exists():
        return jsonify({'error': 'File not found'}), 404
        
    temp_file = None
    try:
        # Create temp file for decrypted content
        temp_fd, temp_path = tempfile.mkstemp()
        os.close(temp_fd)  # Close file descriptor immediately
        
        # Decrypt to temp file
        vault.decrypt_file(encrypted_path, temp_path, password)
        
        # Send file and ensure it's closed after sending
        return send_file(
            temp_path,
            as_attachment=True,
            download_name=filename.replace('.vault', ''),
            max_age=0
        )
            
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error("decryption_failed", error=str(e))
        return jsonify({'error': 'Decryption failed'}), 500
    finally:
        # Clean up temp file
        if temp_path:
            try:
                os.unlink(temp_path)
            except Exception as e:
                logger.error("cleanup_failed", error=str(e))

@app.route('/api/files/<filename>', methods=['DELETE'])
@require_auth
@rate_limit
def delete_file(filename):
    """Delete an encrypted file"""
    try:
        file_path = vault.vault_dir / filename
        if not file_path.exists():
            return jsonify({'error': 'File not found'}), 404
            
        file_path.unlink()
        return jsonify({'message': 'File deleted successfully'})
        
    except Exception as e:
        logger.error("delete_failed", error=str(e))
        return jsonify({'error': 'Delete failed'}), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file size exceeded error"""
    return jsonify({'error': 'File too large'}), 413

def create_app(testing=False):
    """Application factory for testing"""
    if testing:
        app.config['TESTING'] = True
    return app

if __name__ == '__main__':
    # In production, use proper WSGI server and HTTPS
    app.run(debug=False)